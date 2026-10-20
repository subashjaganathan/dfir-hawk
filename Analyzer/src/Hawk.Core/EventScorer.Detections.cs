using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace Hawk.Core;

/// <summary>
/// Detection pack 2: credential access, account manipulation, defense evasion
/// and execution rules over event data the parser already keeps (Security,
/// Sysmon) plus $MFT timestamps. Same FP philosophy as the rest of the scorer:
/// a benign-capable single signal scores medium or not at all; convergence or
/// an explicitly malicious pattern scores high/critical.
/// </summary>
public static partial class EventScorer
{
    private static int ScoreDetectionPack2(SqliteConnection conn)
    {
        var total = 0;
        total += Kerberoasting(conn);
        total += AccountManipulation(conn);
        total += AuditPolicyWeakened(conn);
        total += SuspiciousProcessCreation(conn);
        total += LsassAccess(conn);
        total += MftTimestomp(conn);
        return total;
    }

    // ---- shared helpers ------------------------------------------------------

    private static readonly string[] ShellImages =
        ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
         "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msbuild.exe", "installutil.exe"];
    private static readonly string[] OfficeImages =
        ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "mspub.exe", "msaccess.exe", "visio.exe"];
    private static readonly string[] ServerImages =
        ["w3wp.exe", "httpd.exe", "nginx.exe", "tomcat.exe", "tomcat9.exe", "sqlservr.exe", "java.exe", "php-cgi.exe", "umworkerprocess.exe"];

    private static string Leaf(string? path) =>
        string.IsNullOrEmpty(path) ? "" : Path.GetFileName(path.Replace('/', '\\').TrimEnd('\\')).ToLowerInvariant();

    private sealed record Ev(long Id, string? Ts, string Channel, long EventId, Dictionary<string, string> Data)
    {
        public string F(string k) => Data.TryGetValue(k, out var v) ? v : "";
        public DateTime? When => DateTime.TryParse(Ts, CultureInfo.InvariantCulture,
            DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var d) ? d : null;
    }

    private static List<Ev> LoadEvents(SqliteConnection conn, string where)
    {
        var list = new List<Ev>();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"SELECT id, ts_utc, channel, event_id, event_data FROM event_logs WHERE {where} ORDER BY ts_utc";
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (!r.IsDBNull(4))
            {
                try
                {
                    foreach (var p in JsonDocument.Parse(r.GetString(4)).RootElement.EnumerateObject())
                        data[p.Name] = p.Value.ValueKind == JsonValueKind.String ? p.Value.GetString() ?? "" : p.Value.ToString();
                }
                catch { /* malformed event_data: keep the row, no fields */ }
            }
            list.Add(new Ev(r.GetInt64(0), r.IsDBNull(1) ? null : r.GetString(1),
                r.IsDBNull(2) ? "" : r.GetString(2), r.GetInt64(3), data));
        }
        return list;
    }

    private static int InsertEventFindings(SqliteConnection conn,
        List<(string rule, string sev, string sum, string? det, string? ts, long? id)> rows)
    {
        if (rows.Count == 0) return 0;
        using var tx = conn.BeginTransaction();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO findings (rule, severity, summary, detail, ts_utc, artifact_table, artifact_id)
            VALUES ($rule, $sev, $sum, $det, $ts, 'event_logs', $id)
            """;
        var pRule = P(cmd, "$rule"); var pSev = P(cmd, "$sev"); var pSum = P(cmd, "$sum");
        var pDet = P(cmd, "$det"); var pTs = P(cmd, "$ts"); var pId = P(cmd, "$id");
        foreach (var (rule, sev, sum, det, ts, id) in rows)
        {
            pRule.Value = rule; pSev.Value = sev; pSum.Value = sum;
            pDet.Value = (object?)det ?? DBNull.Value; pTs.Value = (object?)ts ?? DBNull.Value;
            pId.Value = (object?)id ?? DBNull.Value;
            cmd.ExecuteNonQuery();
        }
        tx.Commit();
        return rows.Count;
    }

    private static string Clip(string s, int n = 400) => s.Length > n ? s[..n] + "..." : s;

    // ---- rules ---------------------------------------------------------------

    /// <summary>
    /// 4769 Kerberoasting: one account requesting RC4 (0x17) / DES service
    /// tickets for 3+ distinct user-service SPNs within 60 minutes. A single
    /// RC4 ticket is normal on legacy estates and scores nothing; machine
    /// accounts ($) and krbtgt are excluded.
    /// </summary>
    private static int Kerberoasting(SqliteConnection conn)
    {
        string[] weakEnc = ["0x17", "0x18", "0x1", "0x3"];
        var evs = LoadEvents(conn, "channel = 'Security' AND event_id = 4769 AND ts_utc IS NOT NULL")
            .Where(e => weakEnc.Contains(e.F("TicketEncryptionType").ToLowerInvariant())
                        && (e.F("Status") is "" or "0x0")
                        && !e.F("ServiceName").EndsWith('$')
                        && !e.F("ServiceName").Equals("krbtgt", StringComparison.OrdinalIgnoreCase)
                        && e.When != null)
            .ToList();
        var rows = new List<(string, string, string, string?, string?, long?)>();
        foreach (var byAcct in evs.GroupBy(e => e.F("TargetUserName").ToLowerInvariant()))
        {
            var list = byAcct.OrderBy(e => e.When).ToList();
            for (int i = 0, j = 0; j < list.Count; j++)
            {
                while (list[j].When!.Value - list[i].When!.Value > TimeSpan.FromMinutes(60)) i++;
                var window = list.Skip(i).Take(j - i + 1).ToList();
                var spns = window.Select(e => e.F("ServiceName")).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                if (spns.Count < 3) continue;
                rows.Add(("kerberoasting-rc4-spn-sweep", spns.Count >= 10 ? "critical" : "high",
                    $"Possible Kerberoasting: {byAcct.First().F("TargetUserName")} requested weak-encryption tickets for {spns.Count} services in 60 min",
                    $"services: {Clip(string.Join(", ", spns))}; source: {window[0].F("IpAddress")}",
                    window[0].Ts, window[0].Id));
                break;   // one finding per account
            }
        }
        return InsertEventFindings(conn, rows);
    }

    private static readonly string[] PrivilegedGroups =
        ["administrators", "domain admins", "enterprise admins", "schema admins", "account operators",
         "backup operators", "server operators", "print operators", "dnsadmins", "group policy creator owners",
         "remote desktop users", "remote management users", "hyper-v administrators", "key admins", "enterprise key admins"];

    /// <summary>
    /// 4720 account created (medium) and 4728/4732/4756 member added to a
    /// privileged group (high). An account that is created AND put into a
    /// privileged group within 24h converges to critical (T1136 + T1098).
    /// </summary>
    private static int AccountManipulation(SqliteConnection conn)
    {
        var created = LoadEvents(conn, "channel = 'Security' AND event_id = 4720");
        var added = LoadEvents(conn, "channel = 'Security' AND event_id IN (4728, 4732, 4756)")
            .Where(e => PrivilegedGroups.Contains(e.F("TargetUserName").ToLowerInvariant()))
            .ToList();
        var rows = new List<(string, string, string, string?, string?, long?)>();
        var convergedSids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var a in added)
        {
            var sid = a.F("MemberSid");
            var c = created.FirstOrDefault(x => sid.Length > 0 && x.F("TargetSid").Equals(sid, StringComparison.OrdinalIgnoreCase)
                                                && x.When != null && a.When != null
                                                && (a.When.Value - x.When.Value).Duration() <= TimeSpan.FromHours(24));
            var member = a.F("MemberName") is { Length: > 0 } mn && mn != "-" ? mn : sid;
            if (c != null)
            {
                convergedSids.Add(sid);
                rows.Add(("new-account-added-to-privileged-group", "critical",
                    $"Account '{c.F("TargetUserName")}' created and added to '{a.F("TargetUserName")}' within 24h",
                    $"created {c.Ts} by {c.F("SubjectUserName")}; added {a.Ts} by {a.F("SubjectUserName")}; member {member}",
                    a.Ts, a.Id));
            }
            else
            {
                rows.Add(("member-added-to-privileged-group", "high",
                    $"'{member}' added to privileged group '{a.F("TargetUserName")}'",
                    $"by {a.F("SubjectDomainName")}\\{a.F("SubjectUserName")} (EID {a.EventId})",
                    a.Ts, a.Id));
            }
        }
        foreach (var c in created.Where(x => !convergedSids.Contains(x.F("TargetSid"))))
            rows.Add(("local-account-created", "medium",
                $"User account created: {c.F("TargetDomainName")}\\{c.F("TargetUserName")}",
                $"by {c.F("SubjectDomainName")}\\{c.F("SubjectUserName")}",
                c.Ts, c.Id));
        return InsertEventFindings(conn, rows);
    }

    /// <summary>
    /// 4719 system audit policy changed with a Success/Failure audit REMOVED
    /// (%%8448 / %%8450) by an interactive principal. Group Policy refreshes
    /// run as SYSTEM (S-1-5-18) and are excluded.
    /// </summary>
    private static int AuditPolicyWeakened(SqliteConnection conn)
    {
        var rows = new List<(string, string, string, string?, string?, long?)>();
        foreach (var e in LoadEvents(conn, "channel = 'Security' AND event_id = 4719"))
        {
            var changes = e.F("AuditPolicyChanges");
            if (!(changes.Contains("%%8448") || changes.Contains("%%8450"))) continue;
            if (e.F("SubjectUserSid") is "S-1-5-18" or "S-1-5-19" or "S-1-5-20") continue;
            rows.Add(("audit-policy-weakened", "high",
                $"Audit policy weakened by {e.F("SubjectDomainName")}\\{e.F("SubjectUserName")}",
                $"subcategory {e.F("SubcategoryGuid")}; changes {changes.Replace("%%8448", "Success removed").Replace("%%8450", "Failure removed")}",
                e.Ts, e.Id));
        }
        return InsertEventFindings(conn, rows);
    }

    /// <summary>
    /// Process creation history (Security 4688 / Sysmon 1):
    ///  - web/database server process spawning a shell = web shell (critical)
    ///  - Office spawning a shell / script host = malicious document (high)
    ///  - LSASS dump command lines (comsvcs MiniDump, procdump lsass) (critical)
    ///  - LOLBin download/execute patterns (certutil -urlcache, mshta http,
    ///    regsvr32 /i:http, bitsadmin /transfer, rundll32 javascript:) (high)
    /// </summary>
    private static int SuspiciousProcessCreation(SqliteConnection conn)
    {
        var rows = new List<(string, string, string, string?, string?, long?)>();
        var evs = LoadEvents(conn,
            "(channel = 'Security' AND event_id = 4688) OR (channel = 'Microsoft-Windows-Sysmon/Operational' AND event_id = 1)");
        foreach (var e in evs)
        {
            var sysmon = e.EventId == 1;
            var image = sysmon ? e.F("Image") : e.F("NewProcessName");
            var parent = sysmon ? e.F("ParentImage") : e.F("ParentProcessName");
            var cmd = e.F("CommandLine");
            var child = Leaf(image); var par = Leaf(parent);
            var lc = cmd.ToLowerInvariant();
            var src = sysmon ? "Sysmon 1" : "4688";

            if (ShellImages.Contains(child) && ServerImages.Contains(par))
                rows.Add(("webserver-spawned-shell", "critical",
                    $"Server process {par} spawned {child} (possible web shell)",
                    $"{src}: {Clip(cmd.Length > 0 ? cmd : image)}", e.Ts, e.Id));
            else if (ShellImages.Contains(child) && OfficeImages.Contains(par))
                rows.Add(("office-spawned-shell-history", "high",
                    $"Office application {par} spawned {child}",
                    $"{src}: {Clip(cmd.Length > 0 ? cmd : image)}", e.Ts, e.Id));

            if ((lc.Contains("comsvcs") && lc.Contains("minidump")) ||
                (lc.Contains("procdump") && lc.Contains("lsass")) ||
                (lc.Contains("sqldumper") && lc.Contains("0x01100")) ||
                (child == "rundll32.exe" && lc.Contains("#24") && lc.Contains("comsvcs")))
                rows.Add(("lsass-dump-commandline", "critical",
                    $"Credential dumping command line ({child})",
                    $"{src}: {Clip(cmd)}", e.Ts, e.Id));
            else if ((child == "certutil.exe" && (lc.Contains("-urlcache") || lc.Contains("/urlcache") || lc.Contains("-decode"))) ||
                     (child == "mshta.exe" && (lc.Contains("http:") || lc.Contains("https:") || lc.Contains("javascript:") || lc.Contains("vbscript:"))) ||
                     (child == "regsvr32.exe" && (lc.Contains("/i:http") || lc.Contains("-i:http") || lc.Contains("scrobj"))) ||
                     (child == "bitsadmin.exe" && lc.Contains("/transfer")) ||
                     (child == "rundll32.exe" && lc.Contains("javascript:")))
                rows.Add(("lolbin-download-execute", "high",
                    $"LOLBin download/execute pattern: {child}",
                    $"{src}: {Clip(cmd)}", e.Ts, e.Id));
        }
        return InsertEventFindings(conn, rows);
    }

    /// <summary>
    /// Sysmon 10: a non-system process opened LSASS with memory-read access
    /// (0x10 VM_READ in the granted mask). Known OS / security components are
    /// excluded; anything else reading LSASS memory is a credential-theft lead.
    /// </summary>
    private static int LsassAccess(SqliteConnection conn)
    {
        string[] trustedSources =
        [
            @"\windows\system32\csrss.exe", @"\windows\system32\wininit.exe", @"\windows\system32\lsm.exe",
            @"\windows\system32\services.exe", @"\windows\system32\svchost.exe", @"\windows\system32\wbem\wmiprvse.exe",
            @"\windows\system32\taskmgr.exe", @"\windows\system32\lsass.exe", @"\windows\system32\werfault.exe",
            @"\programdata\microsoft\windows defender\platform\", @"\program files\windows defender\",
            @"\windows\system32\mrt.exe", @"\windows\system32\vmtoolsd.exe", @"\program files\vmware\vmware tools\",
        ];
        var rows = new List<(string, string, string, string?, string?, long?)>();
        foreach (var e in LoadEvents(conn, "channel = 'Microsoft-Windows-Sysmon/Operational' AND event_id = 10"))
        {
            if (Leaf(e.F("TargetImage")) != "lsass.exe") continue;
            var src = e.F("SourceImage"); var lsrc = src.ToLowerInvariant();
            if (trustedSources.Any(lsrc.Contains)) continue;
            var masked = e.F("GrantedAccess");
            if (!long.TryParse(masked.Replace("0x", ""), NumberStyles.HexNumber, null, out var access)) continue;
            if ((access & 0x10) == 0) continue;   // no PROCESS_VM_READ -> not a memory read
            rows.Add(("lsass-memory-access", "high",
                $"{Leaf(src)} opened LSASS with memory-read access ({masked})",
                $"source {src}; call trace {Clip(e.F("CallTrace"), 200)}", e.Ts, e.Id));
        }
        return InsertEventFindings(conn, rows);
    }

    /// <summary>
    /// $MFT timestomping lead: an executable/script in a user-writable path
    /// whose $STANDARD_INFORMATION creation time is more than an hour EARLIER
    /// than its $FILE_NAME creation time. Tools rewrite $SI (user-settable);
    /// $FN is maintained by the kernel. Archive extraction can produce the same
    /// shape, so this is medium - corroborate with prefetch/USN.
    /// </summary>
    private static int MftTimestomp(SqliteConnection conn)
    {
        if (!TableExists(conn, "mft_entries")) return 0;
        string[] exts = [".exe", ".dll", ".sys", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".scr"];
        string[] userWritable = [@"\temp\", @"\appdata\", @"\downloads\", @"\public\", @"\programdata\", @"\perflogs\", @"\windows\tasks\"];
        var rows = new List<(string rule, string sev, string sum, string det, string? ts)>();
        using (var read = conn.CreateCommand())
        {
            read.CommandText = """
                SELECT file_name, full_path, si_created_utc, fn_created_utc FROM mft_entries
                WHERE in_use = 1 AND is_directory = 0 AND si_created_utc IS NOT NULL AND fn_created_utc IS NOT NULL
                  AND si_created_utc < fn_created_utc
                """;
            using var r = read.ExecuteReader();
            while (r.Read())
            {
                var fn = r.GetString(0).ToLowerInvariant();
                if (!exts.Any(fn.EndsWith)) continue;
                var path = r.IsDBNull(1) ? fn : r.GetString(1);
                if (!userWritable.Any(path.ToLowerInvariant().Contains)) continue;
                if (!DateTime.TryParse(r.GetString(2), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out var si) ||
                    !DateTime.TryParse(r.GetString(3), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out var fnc)) continue;
                if (fnc - si < TimeSpan.FromHours(1)) continue;
                rows.Add(("mft-timestomp-suspected", "medium",
                    $"Possible timestomping: {r.GetString(0)}",
                    $"$SI created {r.GetString(2)} is {(fnc - si).TotalDays:N1} days before $FN created {r.GetString(3)}; path {path}",
                    r.GetString(3)));
            }
        }
        return InsertSimple(conn, rows, "mft_entries");
    }
}
