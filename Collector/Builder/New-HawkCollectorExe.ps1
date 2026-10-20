<#
.SYNOPSIS
    Wraps a built Hawk Collector package folder into a SINGLE self-extracting
    executable (HawkCollector.exe) for deployment to isolated / quarantined
    hosts. No internet and no third-party tools required: it compiles a tiny
    .NET launcher with the in-box C# compiler (csc.exe) and embeds the whole
    package (modules, runtime, config, and any staged Tools\ like go-winpmem)
    as a resource.

    The produced .exe:
      - requests Administrator at launch (UAC prompt; no "run as admin" needed),
      - extracts the package beside its output (the .exe's folder, normally the
        USB) rather than %TEMP% on the evidence drive,
      - runs the collector, writing the .hawk next to the .exe (e.g. the USB),
        falling back to %SystemDrive%\HawkOutput then %TEMP% if not writable,
      - cleans up the temp folder afterwards.

.EXAMPLE
    .\New-HawkCollectorExe.ps1 -PackageRoot C:\Users\me\HawkCollector -OutputExe C:\Users\me\HawkCollector.exe
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PackageRoot,
    [Parameter(Mandatory)][string]$OutputExe
)
$ErrorActionPreference = 'Stop'

if (-not (Test-Path (Join-Path $PackageRoot 'Runtime\Collector.ps1'))) {
    throw "PackageRoot does not look like a built collector (missing Runtime\Collector.ps1): $PackageRoot"
}

$csc = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path $csc)) { $csc = "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\csc.exe" }
if (-not (Test-Path $csc)) { throw "In-box C# compiler not found (csc.exe). .NET Framework 4.x is required to build the .exe." }
$fwDir   = Split-Path $csc
$zipAsm  = Join-Path $fwDir 'System.IO.Compression.FileSystem.dll'
$zipAsm2 = Join-Path $fwDir 'System.IO.Compression.dll'

Write-Host "[*] Building self-extracting HawkCollector.exe" -ForegroundColor Cyan

$build = Join-Path $env:TEMP ("hawkexe_" + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Force $build | Out-Null
try {
    # --- Stage a clean copy of the package (exclude stray outputs) -----------
    $stage = Join-Path $build 'pkg'
    Copy-Item -LiteralPath $PackageRoot -Destination $stage -Recurse -Force
    Get-ChildItem $stage -Recurse -Include '*.hawk','*.hawk.sha256' -ErrorAction SilentlyContinue |
        Remove-Item -Force -ErrorAction SilentlyContinue

    # --- Zip the staged package (structure preserved) ------------------------
    $payload = Join-Path $build 'payload.zip'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::CreateFromDirectory($stage, $payload,
        [IO.Compression.CompressionLevel]::Optimal, $false)
    Write-Host ("[+] Package payload: {0:N1} MB" -f ((Get-Item $payload).Length / 1MB))

    # --- Manifest: request Administrator at launch ---------------------------
    $manifest = Join-Path $build 'app.manifest'
@'
<?xml version="1.0" encoding="utf-8"?>
<assembly manifestVersion="1.0" xmlns="urn:schemas-microsoft-com:asm.v1">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
'@ | Out-File $manifest -Encoding utf8

    # --- C# launcher source --------------------------------------------------
    $src = Join-Path $build 'HawkLauncher.cs'
@'
using System;
using System.IO;
using System.Diagnostics;
using System.Reflection;
using System.IO.Compression;

class HawkLauncher {
    // Usage: HawkCollector.exe [-NoPause] [-CaseNumber X] [-Investigator Y] [-OutputDir Z]
    // Exit code = the collector's (0 ok, 1 not elevated, 2 partial, 3 seal failed,
    // 4 ConstrainedLanguage); 10+ are launcher errors.
    static string Quote(string a) {
        if (a.Length > 0 && a.IndexOfAny(new[] { ' ', '\t', '"' }) < 0) return a;
        return "\"" + a.Replace("\"", "\\\"") + "\"";
    }

    static int Main(string[] args) {
        bool noPause = false; string outOverride = null; string passThru = "";
        for (int i = 0; i < args.Length; i++) {
            string a = args[i];
            if (a.Equals("-NoPause", StringComparison.OrdinalIgnoreCase) || a.Equals("/nopause", StringComparison.OrdinalIgnoreCase)) { noPause = true; continue; }
            if (a.Equals("-OutputDir", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length) { outOverride = args[++i]; continue; }
            if ((a.Equals("-CaseNumber", StringComparison.OrdinalIgnoreCase) || a.Equals("-Investigator", StringComparison.OrdinalIgnoreCase)) && i + 1 < args.Length) {
                passThru += " " + a + " " + Quote(args[++i]); continue;
            }
            Console.WriteLine("[!] Unknown argument ignored: " + a);
        }
        // No console to answer a "press any key" prompt (EDR live response, PsExec, scheduler).
        try { if (Console.IsInputRedirected) noPause = true; } catch { noPause = true; }

        try { Console.Title = "Hawk Collector"; } catch {}
        Console.WriteLine("=== Hawk Collector (self-extracting, offline-capable) ===");
        // Unpack beside the output (normally the USB the .exe runs from), not in
        // %TEMP% on the evidence drive: writes there overwrite unallocated space.
        string outDir;
        if (outOverride != null) {
            try { Directory.CreateDirectory(outOverride); outDir = Path.GetFullPath(outOverride); }
            catch (Exception ex) { Console.WriteLine("[!] -OutputDir unusable: " + ex.Message); return 13; }
        } else outDir = ChooseOutputDir();
        string tmp = Path.Combine(outDir, "HawkCollector_pkg_" + Guid.NewGuid().ToString("N").Substring(0, 8));
        int rc = 12;
        try {
            Directory.CreateDirectory(tmp);
            string zipPath = Path.Combine(tmp, "payload.zip");
            using (Stream rs = Assembly.GetExecutingAssembly().GetManifestResourceStream("HawkCollector.payload")) {
                if (rs == null) { Console.WriteLine("[!] Embedded payload missing."); return rc = 10; }
                using (FileStream fs = File.Create(zipPath)) { rs.CopyTo(fs); }
            }
            Console.WriteLine("[*] Extracting collector...");
            string pkg = Path.Combine(tmp, "pkg");
            ZipFile.ExtractToDirectory(zipPath, pkg);
            try { File.Delete(zipPath); } catch {}

            string collector = Path.Combine(pkg, "Runtime", "Collector.ps1");
            if (!File.Exists(collector)) { Console.WriteLine("[!] Collector.ps1 not found after extract."); return rc = 11; }

            // A Tools\ folder beside the .exe (e.g. winpmem + SHA256SUMS.txt dropped on the USB
            // at IR time) overrides the tools bundled at build time.
            try {
                string exeTools = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "Tools");
                if (Directory.Exists(exeTools)) {
                    string pkgTools = Path.Combine(pkg, "Tools"); Directory.CreateDirectory(pkgTools);
                    foreach (string f in Directory.GetFiles(exeTools)) File.Copy(f, Path.Combine(pkgTools, Path.GetFileName(f)), true);
                    Console.WriteLine("[*] Using Tools\\ beside the exe: " + exeTools);
                }
            } catch (Exception ex) { Console.WriteLine("[!] Could not stage Tools\\ beside the exe: " + ex.Message); }

            Console.WriteLine("[*] Output (.hawk) will be written to: " + outDir);

            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = "powershell.exe";
            psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File \"" + collector + "\" -PackageRoot \"" + pkg + "\" -OutputDir \"" + outDir + "\"" + passThru;
            psi.UseShellExecute = false;
            Process p = Process.Start(psi);
            p.WaitForExit();
            rc = p.ExitCode;
            Console.WriteLine();
            Console.WriteLine("[+] Collector exit code " + rc + ". Look for the .hawk in: " + outDir);
            return rc;
        }
        catch (Exception ex) { Console.WriteLine("[!] Error: " + ex.Message); return rc; }
        finally {
            // pkg is a disposable copy of the collector; collected evidence lives in outDir.
            try { Directory.Delete(tmp, true); } catch {}
            if (!noPause) {
                Console.WriteLine("Press any key to close...");
                try { Console.ReadKey(); } catch {}
            }
        }
    }

    static string ChooseOutputDir() {
        try { string d = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location); if (IsWritable(d)) return d; } catch {}
        try {
            string sd = Environment.GetEnvironmentVariable("SystemDrive"); if (string.IsNullOrEmpty(sd)) sd = "C:";
            string ho = Path.Combine(sd + "\\", "HawkOutput"); Directory.CreateDirectory(ho); if (IsWritable(ho)) return ho;
        } catch {}
        return Path.GetTempPath();
    }
    static bool IsWritable(string dir) {
        try { string t = Path.Combine(dir, ".hwk_" + Guid.NewGuid().ToString("N").Substring(0, 6)); File.WriteAllText(t, "x"); File.Delete(t); return true; }
        catch { return false; }
    }
}
'@ | Out-File $src -Encoding utf8

    # --- Compile -------------------------------------------------------------
    New-Item -ItemType Directory -Force (Split-Path $OutputExe) | Out-Null
    $cscArgs = @(
        '/nologo', '/target:exe', '/platform:anycpu',
        "/win32manifest:$manifest",
        "/reference:$zipAsm2", "/reference:$zipAsm",
        "/resource:$payload,HawkCollector.payload",
        "/out:$OutputExe",
        $src
    )
    & $csc @cscArgs
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $OutputExe)) { throw "csc.exe compilation failed (exit $LASTEXITCODE)" }

    Write-Host ("[+] Built: {0} ({1:N1} MB)" -f $OutputExe, ((Get-Item $OutputExe).Length / 1MB)) -ForegroundColor Green
    Write-Host "    Copy this single file to the target. Double-click (it prompts for Admin)."
    Write-Host "    The .hawk lands beside the .exe, or in %SystemDrive%\HawkOutput if the exe's folder is read-only."
}
finally {
    Remove-Item $build -Recurse -Force -ErrorAction SilentlyContinue
}
