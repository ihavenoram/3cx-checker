<#
    3CX Desk-Phone Connectivity Checker (WinForms)
    ------------------------------------------------
    Interactive on-site tool for Windows PowerShell 5.1.

      * Resolves a 3CX FQDN / URL and runs a full connectivity diagnostic
        against the desk-phone port set (443, 5001, 5060, 5061, 5090) with
        TCP reachability, TLS certificate inspection and an HTTPS HEAD check.
      * Ping-sweeps the local /24, reads the ARP cache and lists Yealink
        phones by MAC (11 Yealink OUIs).
      * Shows local listening ports (5001/5060/5061/5090) as a diagnostic.

    Launch via Launch-3CX-Checker.cmd (forces -STA, required for WinForms).
    No admin required for the network tests; process-name resolution in the
    listeners grid may be limited when not elevated.
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
[System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false)

# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------
# $YealinkOui is assigned from Get-YealinkOui once the helpers are loaded, so
# the list lives in exactly one place. See just below the helper load.
$YealinkOui = @()

$PortDefs = @(
    [pscustomobject]@{ Port = 443;  Name = 'HTTPS provisioning/presence (v20 & hosted default)'; Tls = $true;  Http = $true  },
    [pscustomobject]@{ Port = 5001; Name = 'HTTPS provisioning (v18 / upgraded-v20 default)';    Tls = $true;  Http = $true  },
    [pscustomobject]@{ Port = 5060; Name = 'SIP signalling (UDP/TCP)';              Tls = $false; Http = $false },
    [pscustomobject]@{ Port = 5061; Name = 'SIP over TLS';                          Tls = $true;  Http = $false },
    [pscustomobject]@{ Port = 5090; Name = '3CX Tunnel / SBC';                      Tls = $false; Http = $false }
)

# ---------------------------------------------------------------------------
# Worker helpers - loaded as source TEXT from 3CX-Checker.Helpers.ps1 so the
# same single definition can be dot-sourced into the background runspace AND
# the UI thread. See that file's header for the rules new helpers must follow.
# ---------------------------------------------------------------------------
$HelpersPath = Join-Path $PSScriptRoot '3CX-Checker.Helpers.ps1'
if (-not (Test-Path -LiteralPath $HelpersPath)) {
    [void][System.Windows.Forms.MessageBox]::Show(
        ('Cannot find {0}.' + [Environment]::NewLine + [Environment]::NewLine +
         'It must sit in the same folder as 3CX-Checker.ps1.') -f $HelpersPath,
        '3CX Checker', 'OK', 'Error')
    return
}
$HelpersSource = Get-Content -LiteralPath $HelpersPath -Raw

# Make the helpers available on the UI thread too (used for subnet auto-fill).
. ([scriptblock]::Create($HelpersSource))

# One definition of the vendor OUI lists, now that the helpers are loaded. The
# background runspace gets them for free because it dot-sources the same text.
$YealinkOui = @(Get-YealinkOui)

# ---------------------------------------------------------------------------
# Background worker - runs all network tests off the UI thread and reports
# progress/results through a synchronized hashtable ($Shared).
# ---------------------------------------------------------------------------
$WorkerScript = {
    param($Shared,$HelpersSource,$Mode,$Target,$Cidr,$Ports,$Ouis,$ProbePhones,$SaveRaw,$FindSbc,$MediaOpts,$ProbeVq,$ProbeList,$CredObjects)

    . ([scriptblock]::Create($HelpersSource))
    function WriteLog($m) { [void]$Shared.Log.Add(('[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $m)) }

    try {
        try {
            [System.Net.ServicePointManager]::SecurityProtocol =
                [System.Net.SecurityProtocolType]::Tls12 -bor
                [System.Net.SecurityProtocolType]::Tls11 -bor
                [System.Net.SecurityProtocolType]::Tls
        } catch {}
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

        # One raw capture per run - phone web pages, SIP sweep replies, and this PC's
        # own SBC reply - created whenever Save raw is ticked, before anything writes.
        $rawPath = ''
        if ($SaveRaw) {
            $rawPath = Join-Path $env:TEMP ('3CX-Checker-probe_{0}.txt' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
            WriteLog ('Raw capture: {0}' -f $rawPath)
        }

        # ---- A 3CX SBC on THIS machine ------------------------------------------
        # The LAN sweep can never see one: a host is never in its own ARP table. So
        # it is checked directly - and only if the 3CXSBC service exists at all, so on
        # an ordinary PC this costs one Get-Service call and adds nothing.
        $localSbc = $null
        $localSbcRow = $null
        $testFqdn = ''
        if ($Target) { $testFqdn = ((($Target.Trim() -replace '^\s*https?://', '') -replace '/.*$', '') -replace ':\d+$', '') }
        # A phone-password probe is about the phones only: nothing else is re-run.
        if ($Mode -ne 'Probe') {
            try {
                $localSbc = Get-LocalSbcReport -TestFqdn $testFqdn -RawLogPath $rawPath
            } catch { WriteLog ('Local SBC check failed: ' + $_.Exception.Message) }
        }
        if ($localSbc -and $localSbc.Present) {
            $Shared.LocalSbc = $localSbc
            WriteLog ('This PC has the 3CX SBC: ' + ($localSbc.Verdict -replace '^THIS PC: 3CX SBC ', ''))
            if ($localSbc.TunnelAddr) { WriteLog ('  paired with {0}:{1}; config {2}' -f $localSbc.TunnelAddr, $localSbc.TunnelPort, $localSbc.ConfigPath) }
            if ($localSbc.Mismatch) {
                WriteLog ('  WARNING: you are testing {0}, but this PC''s SBC is paired with {1} - the 3CX results will be for a DIFFERENT PBX.' -f $testFqdn, $localSbc.TunnelAddr)
            }
            $localSbcRow = ConvertTo-LocalSbcRow -R $localSbc
            $Shared.Sbc        = @($localSbcRow)
            $Shared.SbcReady   = $true
            $Shared.SbcVersion = [int]$Shared.SbcVersion + 1
        }

        # ---- 3CX connectivity -------------------------------------------------
        if ($Mode -eq 'Cx' -or $Mode -eq 'All') {
            $Shared.Status = 'Resolving 3CX host...'
            $Shared.Progress = 3
            WriteLog ('Resolving {0}' -f $Target)
            $tgt  = Resolve-3cxTarget $Target
            $rows = [System.Collections.Generic.List[object]]::new()

            if ($tgt.ResolveOk) {
                WriteLog ('Resolved {0} -> {1}' -f $tgt.Fqdn, $tgt.Ip)
                $rows.Add([pscustomobject]@{ Check='DNS'; Target=$tgt.Fqdn; Port='-'; Result='Resolved'; Detail=$tgt.Ip; Status='ok' })
            } else {
                WriteLog ('DNS resolution FAILED for {0}' -f $tgt.Fqdn)
                $rows.Add([pscustomobject]@{ Check='DNS'; Target=$tgt.Fqdn; Port='-'; Result='FAILED'; Detail='Could not resolve host'; Status='fail' })
            }

            $Shared.Status = 'Detecting public egress IP...'
            $pub = Get-PublicIp
            if ($pub) {
                WriteLog ('Public egress IP: {0}' -f $pub)
                $Shared.PublicIp = $pub
                $rows.Add([pscustomobject]@{ Check='Public IP'; Target='(this site)'; Port='-'; Result=$pub; Detail='Site egress IP - check against 3CX Allowed/Blacklisted IPs'; Status='info' })
            }

            $openMap = @{}
            $tlsProblems = [System.Collections.Generic.List[string]]::new()
            $prog = 8
            foreach ($pd in $Ports) {
                $Shared.Status = ('Testing TCP {0}...' -f $pd.Port)
                $tcp = Test-TcpPort -ComputerName $tgt.Fqdn -Port ([int]$pd.Port)
                $openMap[[int]$pd.Port] = $tcp.Open
                if ($tcp.Open) {
                    WriteLog ('TCP {0} OPEN ({1} ms) - {2}' -f $pd.Port, $tcp.LatencyMs, $pd.Name)
                    $rows.Add([pscustomobject]@{ Check='TCP'; Target=$tgt.Fqdn; Port=[string]$pd.Port; Result=('OPEN ({0} ms)' -f $tcp.LatencyMs); Detail=$pd.Name; Status='ok' })
                } else {
                    WriteLog ('TCP {0} CLOSED/filtered - {1}' -f $pd.Port, $pd.Name)
                    $rows.Add([pscustomobject]@{ Check='TCP'; Target=$tgt.Fqdn; Port=[string]$pd.Port; Result='CLOSED'; Detail=$pd.Name; Status='fail' })
                }

                if ($pd.Tls -and $tcp.Open) {
                    $Shared.Status = ('TLS handshake {0}...' -f $pd.Port)
                    $cert = Get-TlsCertInfo -ComputerName $tgt.Fqdn -Port ([int]$pd.Port)
                    if ($cert) {
                        $cd = ('Subject {0}; Issuer {1}; expires {2:yyyy-MM-dd} ({3} days)' -f $cert.Subject, $cert.Issuer, $cert.NotAfter, $cert.DaysToExpiry)
                        if ($cert.Problem) {
                            # The phones validate this certificate, so anything Windows
                            # objects to - or had to paper over - is a failure here.
                            $st  = 'fail'
                            $res = 'cert REJECTED'
                            $cd  = ('PROBLEM: {0}.  {1}' -f $cert.Problem, $cd)
                            [void]$tlsProblems.Add(('port {0}: {1}' -f $pd.Port, $cert.Problem))
                            WriteLog ('TLS {0} certificate problem - {1}' -f $pd.Port, $cert.Problem)
                        } else {
                            $st  = if ($cert.DaysToExpiry -lt 30) { 'fail' } else { 'ok' }
                            $res = ('cert {0} days' -f $cert.DaysToExpiry)
                            WriteLog ('TLS {0} cert valid, expires {1:yyyy-MM-dd} ({2} days)' -f $pd.Port, $cert.NotAfter, $cert.DaysToExpiry)
                        }
                        $rows.Add([pscustomobject]@{ Check='TLS'; Target=$tgt.Fqdn; Port=[string]$pd.Port; Result=$res; Detail=$cd; Status=$st })
                        if (-not $Shared.CxCert) { $Shared.CxCert = $cert }
                    } else {
                        WriteLog ('TLS {0} handshake failed' -f $pd.Port)
                        $rows.Add([pscustomobject]@{ Check='TLS'; Target=$tgt.Fqdn; Port=[string]$pd.Port; Result='no TLS'; Detail='TLS handshake failed or no certificate presented'; Status='info' })
                    }
                }

                if ($pd.Http -and $tcp.Open) {
                    $Shared.Status = ('HTTPS {0}...' -f $pd.Port)
                    $url = if ([int]$pd.Port -eq 443) { 'https://' + $tgt.Fqdn } else { 'https://' + $tgt.Fqdn + ':' + $pd.Port }
                    $h = Invoke-HttpsHead $url
                    if ($h.Ok) {
                        WriteLog ('HTTPS {0} -> {1}' -f $pd.Port, $h.Status)
                        $rows.Add([pscustomobject]@{ Check='HTTPS'; Target=$url; Port=[string]$pd.Port; Result=$h.Status; Detail=('Server: {0}' -f $h.Server); Status='ok' })
                    } else {
                        WriteLog ('HTTPS {0} failed: {1}' -f $pd.Port, $h.Status)
                        $rows.Add([pscustomobject]@{ Check='HTTPS'; Target=$url; Port=[string]$pd.Port; Result='no HTTP'; Detail=$h.Status; Status='fail' })
                    }
                }

                $prog += 6
                $Shared.Progress = [int][math]::Min($prog, 27)
            }

            # 443 and 5001 are alternatives for 3CX's web/provisioning: new v20 and
            # hosted PBXs serve HTTPS on 443; v18 and v18->v20-upgraded PBXs keep 5001.
            # Whichever one is open, the other being closed is expected - reporting it
            # as a failure put a red row, and a "1 failed", on every healthy site.
            foreach ($pair in @(@('5001', 443), @('443', 5001))) {
                if (-not $openMap[[int]$pair[1]]) { continue }
                foreach ($row in $rows) {
                    if ($row.Check -eq 'TCP' -and $row.Port -eq $pair[0] -and $row.Result -eq 'CLOSED') {
                        $row.Result = 'CLOSED (expected)'
                        $row.Status = 'info'
                        $row.Detail = ($row.Detail + ' - not needed: this PBX serves HTTPS on ' + $pair[1])
                    }
                }
            }

            $Shared.Status = 'SIP OPTIONS over UDP 5060...'
            $sipu = Test-SipUdp -ComputerName $tgt.Fqdn -Port 5060
            $sipUdpOk = [bool]$sipu.Ok
            if ($sipUdpOk) {
                WriteLog ('UDP SIP OPTIONS -> {0}' -f $sipu.FirstLine)
                $rows.Add([pscustomobject]@{ Check='SIP/UDP'; Target=$tgt.Fqdn; Port='5060/UDP'; Result=$sipu.FirstLine; Detail='SIP OPTIONS answered - UDP registration path works end to end'; Status='ok' })
            } else {
                WriteLog ('UDP SIP OPTIONS failed: {0}' -f $sipu.FirstLine)
                $rows.Add([pscustomobject]@{ Check='SIP/UDP'; Target=$tgt.Fqdn; Port='5060/UDP'; Result='NO REPLY'; Detail=('UDP SIP not answered (' + $sipu.FirstLine + ') - firewall/SIP-ALG may block UDP, or phones use TLS/SBC'); Status='fail' })
            }

            $rows.Add([pscustomobject]@{ Check='RTP'; Target=$tgt.Fqdn; Port='9000-10999/UDP'; Result='n/a'; Detail='UDP media range - cannot be reliably TCP-tested; verify at the firewall'; Status='info' })

            # ---- verdict ----
            $prov = $false; $provPort = ''
            if     ($openMap[443])  { $prov = $true; $provPort = '443'  }
            elseif ($openMap[5001]) { $prov = $true; $provPort = '5001' }
            $sip    = ($openMap[5060] -or $openMap[5061])
            $tunnel = [bool]$openMap[5090]

            $p5060  = if ($openMap[5060]) { 'open' } else { 'closed' }
            $p5061  = if ($openMap[5061]) { 'open' } else { 'closed' }
            $p5090  = if ($tunnel)        { 'open' } else { 'closed' }
            $sipTxt = if ($sip)          { 'OK'   } else { 'FAIL'   }

            $sb = [System.Text.StringBuilder]::new()
            if ($prov) { [void]$sb.AppendLine(('Provisioning/HTTPS: OK on port {0}.' -f $provPort)) }
            else       { [void]$sb.AppendLine('Provisioning/HTTPS: FAIL - neither 443 nor 5001 reachable.') }
            if ($openMap[443] -and -not $openMap[5001]) { [void]$sb.AppendLine('  (443 is the HTTPS port on new v20 installs and hosted 3CX; 5001 closed is normal. On-prem or v18->v20-upgraded PBXs may use 5001 instead.)') }
            if ($openMap[5001] -and -not $openMap[443]) { [void]$sb.AppendLine('  (This PBX serves HTTPS on 5001 - typical of v18 or a v18->v20 upgrade; 443 closed is fine.)') }
            [void]$sb.AppendLine(('SIP signalling (TCP): {0}  (5060 {1}, 5061/TLS {2}).' -f $sipTxt, $p5060, $p5061))
            $sipUdpTxt = if ($sipUdpOk) { 'answered (200 OK) - UDP path OK' } else { 'NO REPLY - UDP 5060 likely blocked/mangled at the router (phones on UDP SIP will fail)' }
            [void]$sb.AppendLine(('SIP OPTIONS over UDP 5060: {0}.' -f $sipUdpTxt))
            [void]$sb.AppendLine(('3CX Tunnel / SBC (5090): {0}.' -f $p5090))
            if ($Shared.PublicIp) { [void]$sb.AppendLine(('Site public IP: {0}  (verify it is Allowed / not Blacklisted on 3CX).' -f $Shared.PublicIp)) }
            if ($tlsProblems.Count -gt 0) {
                foreach ($tp in $tlsProblems) { [void]$sb.AppendLine(('WARNING: TLS certificate problem on {0} - phones will refuse it.' -f $tp)) }
            } elseif ($Shared.CxCert) {
                # "valid" is only said once Get-TlsCertInfo has actually checked it.
                $c = $Shared.CxCert
                if ($c.DaysToExpiry -lt 30) { [void]$sb.AppendLine(('WARNING: TLS certificate expires in {0} days ({1:yyyy-MM-dd}).' -f $c.DaysToExpiry, $c.NotAfter)) }
                else                        { [void]$sb.AppendLine(('TLS certificate valid, expires {0:yyyy-MM-dd} ({1} days).' -f $c.NotAfter, $c.DaysToExpiry)) }
            }

            if ($localSbc -and $localSbc.Present) {
                [void]$sb.AppendLine(('This PC has the 3CX SBC: {0}.' -f ($localSbc.Verdict -replace '^THIS PC: 3CX SBC ', '')))
                if ($localSbc.Mismatch) {
                    $nl = [Environment]::NewLine
                    [void]$sb.Insert(0, ('WARNING: this PC''s 3CX SBC is paired with {0}, but you are testing {1}. Every result on this tab is for a DIFFERENT PBX - re-run against {0}.' -f $localSbc.TunnelAddr, $testFqdn) + $nl + $nl)
                }
            }
            $Shared.CxSummary = $sb.ToString()
            $Shared.Cx        = @($rows.ToArray())
            $Shared.CxReady   = $true
            WriteLog '3CX checks complete.'
            if ($Mode -eq 'Cx') { $Shared.Progress = 100 } else { $Shared.Progress = 30 }
        }

        # ---- LAN discovery ----------------------------------------------------
        if ($Mode -eq 'Lan' -or $Mode -eq 'All' -or $Mode -eq 'Probe') {
            if ($Mode -eq 'Probe') {
                # The phones already found, with the passwords typed into the grid.
                # Copies, so the grid the UI is showing is never changed underneath it.
                $phones = @(@($ProbeList) | ForEach-Object { $_.PSObject.Copy() })
                $Shared.Phones        = @($phones)
                $Shared.PhonesVersion = 1
                $Shared.PhonesReady   = $true
                $Shared.Progress = 10
                WriteLog ('Probing the {0} phone(s) already found - no rescan' -f @($phones).Count)
            } else {
            $Shared.Status = 'Ping-sweeping subnet...'
            $Shared.Progress = [int][math]::Max([int]$Shared.Progress, 32)
            $sweep = Get-SweepTargets -Cidr $Cidr
            if ($sweep.Error) {
                WriteLog ('Subnet not swept - {0}. Only phones already in the ARP table can be found.' -f $sweep.Error)
            } else {
                if ($sweep.Note) { WriteLog ('NOTE: ' + $sweep.Note) }
                WriteLog ('Ping sweep {0} ({1} addresses)' -f $sweep.Effective, @($sweep.Hosts).Count)
                Invoke-PingSweep -Hosts $sweep.Hosts
            }

            $Shared.Progress = 44
            $Shared.Status = 'Reading ARP table for Yealink OUIs...'
            WriteLog 'Reading ARP cache for Yealink OUIs'
            $phones = Get-YealinkArp -OuiList $Ouis
            $Shared.Phones        = @($phones)
            $Shared.PhonesVersion = 1
            $Shared.PhonesReady   = $true
            WriteLog ('Yealink phones found: {0}' -f @($phones).Count)
            if (@($phones).Count -eq 0) {
                WriteLog '  None on this network segment. Discovery reads this PC''s ARP table, so phones on a separate voice VLAN or another routed subnet are invisible from here - run the tool from a PC on the phones'' VLAN or switch port.'
            } else {
                # Each phone's model from its web page title - no login - so the rows
                # can be matched against the per-phone passwords in the 3CX console
                # before anyone types one. Short timeouts: this runs on every phone.
                WriteLog 'Reading each phone''s model from its web page title (no login)'
                $n = 0
                foreach ($ph in @($phones)) {
                    $n++
                    $Shared.Status = ('Identifying phone {0}/{1}: {2}...' -f $n, @($phones).Count, $ph.IP)
                    $id = Get-YealinkWebIdentity -Ip $ph.IP -ConnectMs 800 -TimeoutMs 2000 -RawLogPath $rawPath
                    if ($id.Model -and -not $ph.Model) { $ph.Model = [string]$id.Model }
                    # Which scheme answered, for "Open phone web page".
                    if ($id.Base) { Add-Member -InputObject $ph -NotePropertyName WebUi -NotePropertyValue ([string]$id.Base) -Force }
                    # Unreachable, refused or LOCKED: said in the row, so nobody types
                    # a password for it (or adds to a lock) without knowing.
                    if ($id.Note) {
                        $ph.Reg = [string]$id.Note
                        WriteLog ('  {0}: {1}' -f $ph.IP, $id.Note)
                    }
                    $Shared.Phones        = @($phones)
                    $Shared.PhonesVersion = $Shared.PhonesVersion + 1
                }
            }
            }

            if (($ProbePhones -or $Mode -eq 'Probe') -and @($phones).Count -gt 0) {
                # Never a guessed default: every failed login counts towards the
                # phone's lock-out, and 3CX gives each phone its own password. Only
                # the passwords typed into the grid, each tagged with its phone's MAC.
                $credAll = @(@($CredObjects) | Where-Object { $_ })
                WriteLog ('Logging in to the phones: {0} phone(s), {1} with a password typed into the grid' -f @($phones).Count, @($credAll).Count)
                if (@($credAll).Count -eq 0) { WriteLog '  No passwords entered - no phone was logged in to. Type each phone''s password into its row on the Yealink tab, then click Log in.' }
                $n = 0
                $vqResults = [System.Collections.Generic.List[object]]::new()
                # The PBX under test, for the provisioning comparison - host only.
                $pbxHost = Get-HostFromUrl $Target
                if ($ProbeVq) { WriteLog 'Also reading voice-quality (VQ-RTCPXR) readiness - read-only, nothing is changed on the phones' }
                foreach ($ph in @($phones)) {
                    $n++
                    $Shared.Status = ('Probing phone {0}/{1}: {2}...' -f $n, @($phones).Count, $ph.IP)
                    WriteLog ('Probing web UI {0}' -f $ph.IP)
                    $creds = @(Select-PhoneCreds -CredList $credAll -Ip $ph.IP -Mac $ph.MAC)
                    if (@($creds).Count -eq 0) {
                        # No password for this phone: no login attempt at all.
                        if (-not $ph.Reg) { $ph.Reg = 'not probed - no password entered' }
                        WriteLog ('  {0}: skipped - no password entered' -f $ph.IP)
                        continue
                    }
                    $pi = Get-YealinkPhoneInfo -Ip $ph.IP -CredList $creds -RawLogPath $rawPath -ProbeVq:([bool]$ProbeVq)
                    if ($pi.Cleartext) { WriteLog ('  {0}: its web UI only answered over plain HTTP, so the password crossed the LAN unencrypted' -f $ph.IP) }
                    $ph.Model     = [string]$pi.Model
                    if ([string]$pi.WebUI -like 'http*') { Add-Member -InputObject $ph -NotePropertyName WebUi -NotePropertyValue ([string]$pi.WebUI) -Force }
                    $ph.Firmware  = [string]$pi.Firmware
                    $ph.SipServer = [string]$pi.SipServer
                    $ph.Reg       = [string]$pi.Reg
                    # Add-Member, not assignment: a phone object carried over from an
                    # earlier run may predate these fields, and assigning a missing
                    # property throws (that exact crash happened here once already).
                    $pv = Get-ProvisioningVerdict -ProvHost $pi.ProvHost -PbxHost $pbxHost
                    Add-Member -InputObject $ph -NotePropertyName ProvHost     -NotePropertyValue ([string]$pi.ProvHost) -Force
                    Add-Member -InputObject $ph -NotePropertyName ProvNote     -NotePropertyValue $pv.Note -Force
                    Add-Member -InputObject $ph -NotePropertyName ProvMismatch -NotePropertyValue ([bool]$pv.Mismatch) -Force
                    if ($pv.Mismatch) { WriteLog ('  {0}: WARNING - {1}. Point its Auto Provision URL at this site''s PBX.' -f $ph.IP, $pv.Note) }
                    if ($ProbeVq) {
                        $vr = Get-VqReadiness -Vq $pi.Vq
                        if ($null -eq $pi.Vq) {
                            # The VQ pass only runs after a successful login, so a
                            # null here means the login itself failed.
                            $vr.Short  = 'not read - web login did not succeed'
                            if ($pi.LoginUnsupported) { $vr.Short = ('not read - the ' + $pi.Model + '''s web login is not supported yet') }
                            $vr.Detail = 'The VQ settings are read in the same session as the status pages, which never opened on this phone.'
                        } else {
                            [void]$vqResults.Add($vr)
                        }
                        $ph.Vq       = $vr.Short
                        $ph.VqDetail = $vr.Detail
                        WriteLog ('  {0}: VQ - {1}' -f $ph.IP, $vr.Short)
                    }
                    if ($pi.SipServer -or $pi.Model) {
                        WriteLog ('  {0}: model={1} fw={2} sip-server={3} (user {4})' -f $ph.IP, $ph.Model, $ph.Firmware, $ph.SipServer, $pi.UsedCred)
                    } else {
                        WriteLog ('  {0}: {1} [{2}]' -f $ph.IP, $ph.Reg, $pi.WebUI)
                    }
                    $Shared.Phones        = @($phones)
                    $Shared.PhonesVersion = $Shared.PhonesVersion + 1
                }
                # Provisioning, site-wide. With a PBX under test each phone was judged
                # against it above; without one, phones that disagree with each other
                # are the tell - one of those PBXs is stale.
                $provRead = @(@($phones) | Where-Object { $_.PSObject.Properties['ProvHost'] -and $_.ProvHost })
                $provBad  = @(@($provRead) | Where-Object { $_.ProvMismatch })
                if (@($provBad).Count -gt 0) {
                    WriteLog ('{0} of {1} phone(s) read provision from somewhere other than this site''s PBX - each will revert to that config at its next provisioning cycle (a reboot is enough).' -f @($provBad).Count, @($provRead).Count)
                } elseif (-not $pbxHost -and @($provRead).Count -gt 0) {
                    $groups = @($provRead | Group-Object ProvHost)
                    if (@($groups).Count -gt 1) {
                        WriteLog ('Phones provision from more than one PBX: {0}. Enter this site''s PBX in the FQDN box and re-probe to see which phones are stale.' -f ((@($groups | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Count })) -join ', '))
                    }
                }

                # Say it once, plainly: on a site full of T5x phones every row reads
                # "not read", and the question the probe was for still has an answer.
                $unsup = @(@($phones) | Where-Object { [string]$_.Reg -like 'not read - the * uses a newer web login*' })
                if (@($unsup).Count -gt 0) {
                    $models = ((@($unsup | ForEach-Object { $_.Model }) | Sort-Object -Unique) -join ', ')
                    WriteLog ('{0} of {1} phone(s) could not be read ({2}): their firmware uses a newer web login this tool cannot do yet. That is not a wrong password.' -f @($unsup).Count, @($phones).Count, $models)
                    WriteLog '  Which server each phone registers to (SBC, Router Phone, or the PBX directly) is also shown per phone in the 3CX admin console.'
                    if ($rawPath) { WriteLog ('  The raw capture of what these phones served is in {0} - send it so the tool can learn this login.' -f $rawPath) }
                    else          { WriteLog '  To help the tool learn this login: tick Save raw probe data, probe ONE of these phones with its password, and send the capture file.' }
                }
                if ($ProbeVq -and $vqResults.Count -gt 0) {
                    $vqN       = $vqResults.Count
                    $vqBlocked = @($vqResults | Where-Object { $_.CollectorRoute -eq 'blocked' }).Count
                    $vqViable  = @($vqResults | Where-Object { $_.CollectorRoute -eq 'viable' }).Count
                    $vqUnknown = $vqN - $vqBlocked - $vqViable
                    $vqOver    = @($vqResults | Where-Object { $_.Reprovision -eq 'overwrites' }).Count
                    if ($vqBlocked -gt 0) { WriteLog ('VQ: outbound proxy is ON on {0} of {1} phone(s) - a VQ collector would never receive their reports; Yealink sends them to the proxy (the PBX) instead.' -f $vqBlocked, $vqN) }
                    if ($vqViable  -gt 0) { WriteLog ('VQ: no outbound proxy on {0} of {1} phone(s) - a VQ collector could receive their reports.' -f $vqViable, $vqN) }
                    if ($vqUnknown -gt 0) { WriteLog ('VQ: outbound-proxy setting not readable on {0} of {1} phone(s) - the page paths are undocumented; tick Save raw probe data and send the capture.' -f $vqUnknown, $vqN) }
                    if ($vqOver    -gt 0) { WriteLog ('VQ: {0} phone(s) do not protect local changes, so enable VQ through the 3CX template (Copy 3CX template lines), not on the phone.' -f $vqOver) }
                }
            }

            if ($Mode -ne 'Probe') {
            $Shared.Progress = 52
            $Shared.Status = 'Checking local listeners...'
            WriteLog 'Checking local listening ports (5001/5060/5061/5090)'
            $listeners = Get-LocalListeners
            $Shared.Listeners      = @($listeners)
            $Shared.ListenersReady = $true
            WriteLog ('Local listeners found: {0}' -f @($listeners).Count)

            $Shared.Status = 'Checking gateway / DHCP roles...'
            WriteLog 'Checking who is the default gateway / DHCP server'
            $roles = @()
            try {
                $roles = @(Get-NetworkRoles -OuiList $Ouis -Phones $phones)
            } catch {
                WriteLog ('  gateway/DHCP role check could not run: {0}' -f $_.Exception.Message)
            }
            $Shared.Roles      = @($roles)
            $Shared.RolesReady = $true
            $roleWarn = @(@($roles) | Where-Object { $_.Warn })
            if (@($roleWarn).Count -gt 0) {
                foreach ($w in $roleWarn) { WriteLog ('  ' + $w.Note + ' [' + $w.IP + ' ' + $w.MAC + ']') }
            } else {
                foreach ($r in @($roles)) { WriteLog ('  {0}: {1} ({2}) - {3}' -f $r.Role, $r.IP, $r.MAC, $r.Note) }
            }

            if ($FindSbc) {
                $Shared.Progress = 54
                $Shared.Status = 'Scanning LAN for a 3CX SBC (SIP OPTIONS sweep)...'
                $hostList = @(Get-ArpHosts)
                WriteLog ('SIP OPTIONS sweep of {0} live LAN host(s)' -f @($hostList).Count)
                $sip = @(Invoke-SipSweep -Hosts $hostList -Port 5060 -WaitMs 4000)
                WriteLog ('SIP responders on LAN: {0}' -f @($sip).Count)
                if ($rawPath) {
                    foreach ($sr in @($sip)) {
                        $m3 = 'none'; if ($sr.Matched) { $m3 = $sr.Matched }
                        Write-PhoneRaw -Path $rawPath -Url ('SIP OPTIONS reply from {0}   [classified: {1}; 3CX signature matched on: {2}]' -f $sr.IP, $sr.Type, $m3) -Text ([string]$sr.Raw)
                    }
                }

                # Only the interesting hosts get port-profiled and banner-grabbed:
                # every SIP responder, plus any Raspberry Pi in the ARP table even
                # if it stayed silent on SIP. Profiling all 254 would take minutes
                # to say nothing.
                $arpAll  = @(Get-ArpTable)
                $arpByIp = @{}
                foreach ($a in $arpAll) { if (-not $arpByIp.ContainsKey($a.IP)) { $arpByIp[$a.IP] = $a } }

                $candIps = [System.Collections.Generic.List[string]]::new()
                foreach ($r in $sip) { if (-not $candIps.Contains($r.IP)) { [void]$candIps.Add($r.IP) } }
                foreach ($a in $arpAll) {
                    if ($a.Unicast -and $a.Vendor -eq 'Raspberry Pi' -and -not $candIps.Contains($a.IP)) {
                        [void]$candIps.Add($a.IP)
                        WriteLog ('  Raspberry Pi at {0} did not answer SIP, but is worth profiling anyway' -f $a.IP)
                    }
                }
                $phoneIps = @(@($phones) | ForEach-Object { $_.IP })

                # A phone filling the gateway or DHCP role belongs on this tab even
                # though it is emphatically not an SBC: it is the kind of fault that
                # explains the SIP symptoms someone opened this tab to chase.
                foreach ($rr in @($roles)) {
                    if ($rr.Warn -and $rr.IP -and -not $candIps.Contains([string]$rr.IP)) {
                        [void]$candIps.Add([string]$rr.IP)
                        WriteLog ('  {0} is the {1} AND looks like a phone - profiling it here too' -f $rr.IP, $rr.Role)
                    }
                }

                $sbcRows = [System.Collections.Generic.List[object]]::new()
                if ($localSbcRow) { [void]$sbcRows.Add($localSbcRow) }
                $sbcPbx = Get-HostFromUrl $Target
                $ci = 0
                foreach ($cip in @($candIps.ToArray())) {
                    if ($Shared.Cancel) { break }
                    $ci++
                    $Shared.Status = ('Identifying LAN host {0}/{1}: {2}...' -f $ci, @($candIps).Count, $cip)
                    $srArr = @($sip | Where-Object { $_.IP -eq $cip })
                    $sr = $null; if (@($srArr).Count -gt 0) { $sr = $srArr[0] }
                    $ar = $null; if ($arpByIp.ContainsKey($cip)) { $ar = $arpByIp[$cip] }
                    $cand = Test-SbcCandidate -Ip $cip -SipRow $sr -ArpRow $ar -Roles $roles -PhoneIps $phoneIps
                    # An SBC or Router Phone tunnelling to a different PBX sends every
                    # phone behind it there - the provisioning problem's twin.
                    if ($cand.ForwardsTo -and $sbcPbx -and $cand.ForwardsTo -ne $sbcPbx) {
                        $cand.ForwardsMismatch = $true
                        $cand.Detail += (' WARNING: it forwards to ' + $cand.ForwardsTo + ', not ' + $sbcPbx + ' - every phone registering through it reaches that PBX instead.')
                        WriteLog ('  WARNING: {0} forwards to {1}, not {2} - phones registering through it reach that PBX' -f $cip, $cand.ForwardsTo, $sbcPbx)
                    }
                    [void]$sbcRows.Add($cand)
                    $Shared.Sbc        = @($sbcRows.ToArray())
                    $Shared.SbcReady   = $true
                    $Shared.SbcVersion = [int]$Shared.SbcVersion + 1
                    WriteLog ('  {0}: {1}' -f $cip, $cand.Confidence)
                }
                $Shared.Sbc        = @($sbcRows.ToArray())
                $Shared.SbcReady   = $true
                $Shared.SbcVersion = [int]$Shared.SbcVersion + 1

                # Prefix match, not '*likely*': that also matches 'unlikely', which
                # would report every dismissed host as a candidate.
                $best = @(@($sbcRows.ToArray()) | Where-Object {
                    $_.Confidence -like 'very likely*' -or $_.Confidence -like 'likely*' -or
                    ($_.PSObject.Properties['SbcMarker'] -and $_.SbcMarker) -or
                    ($_.PSObject.Properties['Is3cxRouterPhone'] -and $_.Is3cxRouterPhone) })
                if (@($best).Count -gt 0) {
                    foreach ($b in $best) { WriteLog ('  SBC candidate {0}: {1}' -f $b.IP, $b.Detail) }
                } elseif ($localSbcRow) {
                    WriteLog '  No other SBC on the LAN - the SBC is this PC (see its row on the SIP / SBC tab).'
                } else {
                    WriteLog '  No local 3CX SBC identified - phones would need RPS / direct provisioning to the cloud PBX.'
                }
            }
            }   # end: not a phone-password probe
            if ($Mode -eq 'Lan' -or $Mode -eq 'Probe') { $Shared.Progress = 100 } else { $Shared.Progress = [int][math]::Max([int]$Shared.Progress, 60) }
        }

        # ---- Media / path quality --------------------------------------------
        if (($Mode -eq 'Media' -or $Mode -eq 'All') -and $MediaOpts -and
            ($MediaOpts.Train -or $MediaOpts.Nat -or $MediaOpts.Path -or $MediaOpts.Binding -or $MediaOpts.SoakMinutes -gt 0)) {

            $tgtM = Resolve-3cxTarget $Target
            $mrows = [System.Collections.Generic.List[object]]::new()
            $subs  = [System.Collections.Generic.List[object]]::new()
            $Shared.MediaReady = $true

            # Push what we have so far to the grid after every sub-test, so a
            # stage that can run for minutes does not look like a hang.
            function PushMedia {
                $Shared.Media = @($mrows.ToArray())
                $Shared.MediaVersion = [int]$Shared.MediaVersion + 1
            }
            function AddRow($g,$c,$r,$d,$s) {
                $mrows.Add([pscustomobject]@{ Group=$g; Check=$c; Result=$r; Detail=$d; Status=$s })
                PushMedia
            }

            AddRow 'Scope' 'What is measured' 'SIP path + STUN' 'Nothing answers on the RTP range (UDP 9000-10999) - 3CX only opens media ports for an established call. Everything below is measured over UDP 5060 to the same PBX, or over STUN. Good proxies for the media path; not the media itself.' 'info'
            AddRow 'Scope' 'Real-call quality' '3CX already records it' 'For quality measured on REAL calls, switch on Monitor Connection Quality in 3CX v20 for the site''s users (it runs up to 7 days), then read per-leg loss, jitter, RTT and a score in call history or the call log report. It cannot measure calls whose audio bypasses the PBX, and a leg reads Unknown if the phone sent no RTCP. For the phone''s own view, see VQ readiness on the Yealink tab.' 'info'

            $trainIdle = $null
            $mosIdle   = $null
            $mapping   = $null
            $alg       = $null
            $binding   = $null

            # ---- UDP path quality ---------------------------------------
            if ($MediaOpts.Train -and -not $Shared.Cancel) {
                $iv = 50; $dur = 20000
                if ($MediaOpts.Gentle) { $iv = 100; $dur = 30000 }
                $n = [int][math]::Floor($dur / $iv)
                WriteLog ('UDP path test: {0} probes at {1} pps to {2}' -f $n, [int](1000 / $iv), $tgtM.Fqdn)
                $Shared.Status = 'UDP path quality test...'
                $trainIdle = Invoke-SipOptionsTrain -ComputerName $tgtM.Fqdn -Port 5060 -IntervalMs $iv -DurationMs $dur -Label 'idle' -Shared $Shared
                $Shared.Progress = [int][math]::Max([int]$Shared.Progress, 72)

                if (-not $trainIdle.Ok -and -not $trainIdle.Cancelled) {
                    AddRow 'UDP path' 'SIP OPTIONS train' 'NO REPLIES' ('Sent {0} probes to UDP 5060 and got nothing back. {1}' -f $trainIdle.Sent, $trainIdle.Error) 'fail'
                } elseif ($trainIdle.Throttle -and $trainIdle.Throttle.Throttled) {
                    # A block is a change-point that never recovers; real loss is
                    # scattered. Reporting the first as the second would send a
                    # technician hunting a WAN fault that does not exist.
                    WriteLog ('Replies stopped at packet {0} of {1} and never resumed - treating as rate-limiting, not loss.' -f $trainIdle.Throttle.StoppedAtPacket, $trainIdle.Throttle.Total)
                    $probe = Test-TcpPort -ComputerName $tgtM.Fqdn -Port 443
                    $scope = if ($probe.Open) { 'TCP 443 still works, so this is a SIP-layer throttle rather than a full IP block.' } else { 'TCP 443 is also failing now, which suggests the whole source IP is blocked.' }
                    AddRow 'UDP path' 'SIP OPTIONS train' 'RATE-LIMITED' ('Replies stopped at packet {0} of {1} and never resumed. {2} Loss, jitter and MOS are NOT reported for this run because they would be meaningless. Check 3CX Console > Security > Blacklisted IPs for this site''s public IP, then retry with the gentle rate.{3}' -f $trainIdle.Throttle.StoppedAtPacket, $trainIdle.Throttle.Total, $scope, $(if ($trainIdle.RetryAfter) { ' The PBX sent Retry-After: ' + $trainIdle.RetryAfter + '.' } else { '' })) 'fail'
                } elseif ($trainIdle.Ok) {
                    $lossStatus = 'ok'
                    if ($trainIdle.LossPct -ge 2)      { $lossStatus = 'fail' }
                    elseif ($trainIdle.LossPct -ge 0.5) { $lossStatus = 'warn' }
                    AddRow 'UDP path' 'Packet loss' ('{0}%' -f $trainIdle.LossPct) ('{0} of {1} probes answered. Smallest loss this run could resolve is {2}%. Round-trip figure.' -f $trainIdle.Received, $trainIdle.Sent, $trainIdle.LossResolutionPct) $lossStatus

                    $rttStatus = 'ok'
                    if ($trainIdle.RttP95Ms -ge 200)     { $rttStatus = 'fail' }
                    elseif ($trainIdle.RttP95Ms -ge 100) { $rttStatus = 'warn' }
                    $rttDetail = ('min {0} / p50 {1} / p95 {2} / max {3} ms. Includes the PBX''s own time to answer OPTIONS, which a media relay would not add.' -f $trainIdle.RttMinMs, $trainIdle.RttP50Ms, $trainIdle.RttP95Ms, $trainIdle.RttMaxMs)
                    # A latency floor far below the typical response points at the
                    # PBX's responder scheduling, not the network. Worth saying
                    # plainly: otherwise this reads as "fix your WAN" when the
                    # network is actually delivering in min-RTT and the PBX is
                    # simply slow to answer OPTIONS.
                    $spread = $trainIdle.RttP50Ms - $trainIdle.RttMinMs
                    if ($spread -gt 20 -and $spread -gt (2.0 * $trainIdle.JitterMs)) {
                        $rttDetail += (' NOTE: the fastest reply came back in {0} ms while the typical one took {1} ms. A network path does not usually behave that way - a floor this far below the median points at the PBX''s own time to answer, so treat the latency and jitter above as an upper bound on the network and confirm against a real call before changing anything on site.' -f $trainIdle.RttMinMs, $trainIdle.RttP50Ms)
                    }
                    AddRow 'UDP path' 'Round-trip time' ('p50 {0} ms' -f $trainIdle.RttP50Ms) $rttDetail $rttStatus

                    # Below 3x the instrument's own noise, a jitter number is the
                    # tool measuring itself - say so rather than quoting it.
                    $floor = 3.0 * $trainIdle.InstrumentPacingSdMs
                    $jitText = ('{0} ms' -f $trainIdle.JitterMs)
                    $jitStatus = 'ok'
                    if ($trainIdle.JitterMs -ge 30)     { $jitStatus = 'fail' }
                    elseif ($trainIdle.JitterMs -ge 10) { $jitStatus = 'warn' }
                    if ($trainIdle.JitterMs -lt $floor) {
                        $jitText = ('<{0} ms' -f [math]::Round($floor, 2))
                        $jitStatus = 'ok'
                    }
                    AddRow 'UDP path' 'Jitter (RFC 3550)' $jitText ('Mean of the running RFC 3550 estimate; worst {0} ms, end-of-run {1} ms, mean |delta| {2} ms over {3} pairs. Round-trip - one-way is roughly 1/sqrt(2) of this.' -f $trainIdle.JitterMaxMs, $trainIdle.JitterFinalMs, $trainIdle.MeanAbsDeltaMs, $trainIdle.JitterPairs) $jitStatus

                    AddRow 'UDP path' 'Reordering / duplicates' ('{0} / {1}' -f $trainIdle.Reordered, $trainIdle.Duplicates) 'Informational only, never scored: a single request/response train on one 5-tuple almost never observes reordering, so a zero here is not evidence of anything.' 'info'

                    AddRow 'UDP path' 'Instrument noise floor' ('sd {0} ms' -f $trainIdle.InstrumentPacingSdMs) ('The tool''s own send-pacing spread (worst schedule error {0} ms; high-resolution timer {1}). Network jitter below about 3x this is not distinguishable from the measurement itself.' -f $trainIdle.InstrumentPacingMaxErrMs, $(if ($trainIdle.HighResTimer) { 'active' } else { 'UNAVAILABLE - figures are noisier' })) 'info'

                    $mosIdle = Get-EmodelMos -RttP50Ms $trainIdle.RttP50Ms -JitterMs $trainIdle.JitterMs -LossPctRoundTrip $trainIdle.LossPct -SampleCount $trainIdle.Received
                    if ($mosIdle.Ok) {
                        $mosStatus = 'ok'
                        if ($mosIdle.Mos -lt 3.6)     { $mosStatus = 'fail' }
                        elseif ($mosIdle.Mos -lt 4.0) { $mosStatus = 'warn' }
                        AddRow 'UDP path' 'Estimated MOS (G.711)' ('{0}' -f $mosIdle.Mos) ('R={0}, from one-way delay {1} ms and one-way loss {2}%. ESTIMATE from SIP signalling timing, NOT from RTP media: assumes a symmetric path, symmetric loss, random (non-bursty) loss and a 2x jitter buffer. Treat as an indicator.' -f $mosIdle.R, $mosIdle.OneWayDelayMs, $mosIdle.OneWayLossPct) $mosStatus
                    } else {
                        AddRow 'UDP path' 'Estimated MOS (G.711)' 'not computed' $mosIdle.Reason 'info'
                    }
                }
                [void]$subs.Add((Get-PathQualitySubscore -Train $trainIdle -Mos $mosIdle))
            }

            # ---- NAT mapping + SIP ALG -----------------------------------
            if ($MediaOpts.Nat -and -not $Shared.Cancel) {
                $Shared.Status = 'NAT mapping behaviour (STUN)...'
                WriteLog 'Classifying NAT mapping behaviour via STUN'
                $mapping = Get-NatMappingBehaviour
                $mStatus = 'info'
                if ($mapping.Behaviour -eq 'endpoint-independent') { $mStatus = 'ok' }
                elseif ($mapping.Behaviour -eq 'address-dependent' -or $mapping.MultiWan) { $mStatus = 'fail' }
                AddRow 'NAT' 'Mapping behaviour' $mapping.Behaviour ($mapping.Detail + ' Mapping behaviour only - filtering behaviour needs RFC 5780, which most servers no longer support, so no cone/symmetric label is claimed.') $mStatus
                if ($mapping.Ok) {
                    AddRow 'NAT' 'Port preservation' $(if ($mapping.PortPreserving) { 'preserved' } else { 'remapped' }) ('Local port {0} -> public {1}. Informational: preservation is common and harmless, but it does make the binding-lifetime test below unable to see anything.' -f $mapping.LocalPort, $mapping.MappedPortA) 'info'
                }
                $Shared.Progress = [int][math]::Max([int]$Shared.Progress, 80)

                $Shared.Status = 'SIP ALG detection...'
                WriteLog 'Testing for SIP ALG'
                $alg = Test-SipAlg -ComputerName $tgtM.Fqdn -Port 5060 -PublicIp ([string]$Shared.PublicIp)
                $aStatus = if ($alg.AlgDetected) { 'fail' } elseif ($alg.Ok) { 'ok' } else { 'info' }
                AddRow 'NAT' 'SIP ALG' $alg.Verdict $alg.Detail $aStatus
                if ($alg.MultiWan) {
                    AddRow 'NAT' 'Egress IP' 'MISMATCH' ('The PBX saw us arrive from {0} but HTTPS egresses as {1}. UDP and TCP leave by different WANs, which breaks 3CX IP allow-lists.' -f $alg.Received, $Shared.PublicIp) 'fail'
                }
                if ($null -ne $alg.SipPathMappingMatches) {
                    $sStatus = if ($alg.SipPathMappingMatches) { 'ok' } else { 'fail' }
                    AddRow 'NAT' 'Mapping on the SIP path' $(if ($alg.SipPathMappingMatches) { 'endpoint-independent' } else { 'destination-dependent' }) ('The PBX reported rport={0} and STUN reported {1} from the same local socket. This is the mapping test done on the real SIP path rather than only against a STUN server.' -f $alg.Rport, $alg.StunMappedPort) $sStatus
                }
                $Shared.Progress = [int][math]::Max([int]$Shared.Progress, 86)
            }

            # ---- path sanity ---------------------------------------------
            if ($MediaOpts.Path -and -not $Shared.Cancel) {
                $Shared.Status = 'Path MTU...'
                $mtu = Get-PathMtu -ComputerName $tgtM.Fqdn
                if ($mtu.Ok) {
                    AddRow 'Path' 'Path MTU' ('{0} bytes' -f $mtu.PathMtu) $mtu.Detail $(if ($mtu.Constrained) { 'warn' } else { 'ok' })
                } else {
                    AddRow 'Path' 'Path MTU' 'not measurable' $mtu.Detail 'info'
                }
                $Shared.Progress = [int][math]::Max([int]$Shared.Progress, 90)

                if (-not $Shared.Cancel) {
                    $Shared.Status = 'RTP range reachability...'
                    WriteLog 'Probing the RTP media range (positive-only test)'
                    $rtp = Test-UdpPortUnreachable -ComputerName $tgtM.Fqdn -Shared $Shared
                    $rStatus = if ($rtp.Conclusive -and $rtp.Verdict -eq 'path open') { 'ok' } else { 'info' }
                    AddRow 'Path' 'RTP range (9000-10999/UDP)' $rtp.Verdict ($rtp.Detail + ' Positive-only test: silence proves nothing, because it is also what a filtered path looks like.') $rStatus
                }
                $Shared.Progress = [int][math]::Max([int]$Shared.Progress, 93)
            }

            # ---- NAT binding lifetime (slow, opt-in, runs last) ------------
            if ($MediaOpts.Binding -and -not $Shared.Cancel) {
                WriteLog 'Measuring NAT UDP binding lifetime (30/60/120s idle ladder)'
                $binding = Test-NatBindingTimeout -LadderSeconds @(30,60,120) -Shared $Shared
                $bv = Get-NatBindingVerdict -Binding $binding -PhoneKeepAliveSeconds 30
                AddRow 'NAT' 'UDP binding lifetime' $bv.Text $bv.Detail $bv.Status
            }

            if ($MediaOpts.Nat) {
                $sbcFound = $false
                if ($Shared.Sbc) { $sbcFound = (@($Shared.Sbc | Where-Object { $_.Type -like '3CX*' }).Count -gt 0) }
                [void]$subs.Add((Get-NatSubscore -Mapping $mapping -Alg $alg -Binding $binding -LocalSbcFound $sbcFound))
            }

            # ---- soak ------------------------------------------------------
            # A one-shot scan cannot see the thing that actually generates
            # tickets: the link is fine for 58 minutes and awful for 2. Short
            # bursts on a slow cycle keep the average rate at ~3 pps so this
            # stays well clear of anti-hacking thresholds.
            if ($MediaOpts.SoakMinutes -gt 0 -and -not $Shared.Cancel) {
                $cycleSec = 60
                $endAt  = (Get-Date).AddMinutes($MediaOpts.SoakMinutes)
                $lossL = [System.Collections.Generic.List[double]]::new()
                $jitL  = [System.Collections.Generic.List[double]]::new()
                $p95L  = [System.Collections.Generic.List[double]]::new()
                $cycles = 0; $outages = 0; $throttles = 0
                $soakStart = Get-Date

                AddRow 'Soak' 'Window' ('{0} minutes' -f $MediaOpts.SoakMinutes) ('Repeating a 10s / 200-probe burst every {0}s. The verdict below uses the WORST window, not the average - a site that is fine for 58 minutes and broken for 2 is a site with dropped calls.' -f $cycleSec) 'info'
                $soakRow = $mrows.Count      # rows we rewrite in place each cycle
                AddRow 'Soak' 'Progress' 'starting...' '' 'info'
                AddRow 'Soak' 'Loss (cur / avg / worst)' '-' '' 'info'
                AddRow 'Soak' 'Jitter (cur / avg / worst)' '-' '' 'info'
                AddRow 'Soak' 'RTT p95 (cur / avg / worst)' '-' '' 'info'
                AddRow 'Soak' 'Outages' '0' 'A cycle where no probe at all was answered.' 'info'

                WriteLog ('Soak started: {0} minutes' -f $MediaOpts.SoakMinutes)
                while ((Get-Date) -lt $endAt -and -not $Shared.Cancel) {
                    $cycleStart = Get-Date
                    $cycles++
                    $Shared.Status = ('Soak cycle {0}...' -f $cycles)
                    # PrerollCount 0: the process is warm by now, and every extra
                    # packet here is multiplied by the cycle count.
                    $t = Invoke-SipOptionsTrain -ComputerName $tgtM.Fqdn -Port 5060 -IntervalMs 50 -DurationMs 10000 -Label ('soak' + $cycles) -PrerollCount 0 -NoWarmup -Shared $Shared

                    if ($t.Throttle -and $t.Throttle.Throttled) {
                        $throttles++
                        WriteLog ('Soak cycle {0}: replies stopped at packet {1} - rate-limited, figures discarded.' -f $cycles, $t.Throttle.StoppedAtPacket)
                    } elseif ($t.Ok) {
                        [void]$lossL.Add([double]$t.LossPct)
                        [void]$jitL.Add([double]$t.JitterMs)
                        [void]$p95L.Add([double]$t.RttP95Ms)
                    } else {
                        $outages++
                        WriteLog ('Soak cycle {0}: NO replies at all - outage.' -f $cycles)
                    }

                    $lossArr = @($lossL.ToArray()); $jitArr = @($jitL.ToArray()); $p95Arr = @($p95L.ToArray())
                    $fmt = {
                        param($cur,$arr)
                        if (@($arr).Count -eq 0) { return 'no data' }
                        $avg = ($arr | Measure-Object -Average).Average
                        $max = ($arr | Measure-Object -Maximum).Maximum
                        ('{0} / {1} / {2}' -f [math]::Round($cur,2), [math]::Round($avg,2), [math]::Round($max,2))
                    }
                    $mrows[$soakRow].Result     = ('cycle {0}' -f $cycles)
                    $mrows[$soakRow].Detail     = ('{0:N1} of {1} minutes elapsed.' -f (New-TimeSpan -Start $soakStart -End (Get-Date)).TotalMinutes, $MediaOpts.SoakMinutes)
                    $mrows[$soakRow + 1].Result = (& $fmt $t.LossPct $lossArr)
                    $mrows[$soakRow + 1].Detail = 'Percent, round-trip. Worst is the worst single cycle, which is what callers actually experienced.'
                    $mrows[$soakRow + 2].Result = (& $fmt $t.JitterMs $jitArr)
                    $mrows[$soakRow + 2].Detail = 'Milliseconds, RFC 3550, round-trip.'
                    $mrows[$soakRow + 3].Result = (& $fmt $t.RttP95Ms $p95Arr)
                    $mrows[$soakRow + 3].Detail = 'Milliseconds. Includes the PBX''s own time to answer OPTIONS.'
                    $mrows[$soakRow + 4].Result = [string]$outages
                    if ($throttles -gt 0) {
                        $mrows[$soakRow + 4].Detail = ('A cycle where no probe at all was answered. {0} further cycle(s) were discarded as rate-limiting rather than counted as loss.' -f $throttles)
                    }
                    foreach ($k in 0..4) {
                        $st = 'info'
                        if ($k -eq 1 -and @($lossArr).Count -gt 0) { $mx = ($lossArr | Measure-Object -Maximum).Maximum; if ($mx -ge 2) { $st = 'fail' } elseif ($mx -ge 0.5) { $st = 'warn' } else { $st = 'ok' } }
                        if ($k -eq 2 -and @($jitArr).Count  -gt 0) { $mx = ($jitArr  | Measure-Object -Maximum).Maximum; if ($mx -ge 30) { $st = 'fail' } elseif ($mx -ge 10) { $st = 'warn' } else { $st = 'ok' } }
                        if ($k -eq 3 -and @($p95Arr).Count  -gt 0) { $mx = ($p95Arr  | Measure-Object -Maximum).Maximum; if ($mx -ge 200) { $st = 'fail' } elseif ($mx -ge 100) { $st = 'warn' } else { $st = 'ok' } }
                        if ($k -eq 4 -and $outages -gt 0) { $st = 'fail' }
                        $mrows[$soakRow + $k].Status = $st
                    }
                    PushMedia

                    # Pace the cycle, staying responsive to Stop.
                    $sleepFor = $cycleSec - [int]((New-TimeSpan -Start $cycleStart -End (Get-Date)).TotalSeconds)
                    if ($sleepFor -gt 0 -and (Get-Date).AddSeconds($sleepFor) -lt $endAt) {
                        [void](Wait-Cancellable -Seconds $sleepFor -Shared $Shared -Message 'Soak: next cycle')
                    } elseif ($sleepFor -gt 0) { break }
                }
                WriteLog ('Soak finished after {0} cycle(s), {1} outage(s).' -f $cycles, $outages)

                # Verdict on the WORST window, not the average.
                if (@($lossL).Count -gt 0) {
                    $wLoss = ($lossL | Measure-Object -Maximum).Maximum
                    $wJit  = ($jitL  | Measure-Object -Maximum).Maximum
                    $wP95  = ($p95L  | Measure-Object -Maximum).Maximum
                    $worstTrain = [pscustomobject]@{ Ok = $true; LossPct = $wLoss; JitterMs = $wJit; RttP95Ms = $wP95; Throttle = $null }
                    $ws = Get-PathQualitySubscore -Train $worstTrain -Mos $null
                    $ws.Name = 'UDP path quality (worst soak window)'
                    [void]$subs.Add($ws)
                }
                if ($outages -gt 0) {
                    [void]$subs.Add((New-HealthSubscore -Name 'Continuity' -Level 'red' `
                        -Summary ('{0} of {1} soak cycles got no reply at all.' -f $outages, $cycles) `
                        -Remedy 'The link drops entirely for seconds at a time. Calls will disconnect. Chase this with the ISP before tuning anything on the PBX.'))
                } elseif ($cycles -gt 1) {
                    [void]$subs.Add((New-HealthSubscore -Name 'Continuity' -Level 'green' `
                        -Summary ('No full outages across {0} soak cycles.' -f $cycles)))
                }
            }

            # ---- verdict --------------------------------------------------
            $health = Get-SiteHealth -Subscores @($subs.ToArray())
            $sb2 = [System.Text.StringBuilder]::new()
            [void]$sb2.AppendLine($health.Headline)
            foreach ($s in $health.Subscores) {
                [void]$sb2.AppendLine(('  [{0}] {1}: {2}' -f $s.Level.ToUpper(), $s.Name, $s.Summary))
            }
            foreach ($a in $health.Actions) { [void]$sb2.AppendLine(('  -> {0}' -f $a)) }
            if ($MediaOpts.PhoneCount -gt 0) {
                [void]$sb2.AppendLine(('  Site has {0} phone(s) configured in this tool. Every figure above is the path from THIS PC; a phone on a different switch port or VLAN may differ.' -f $MediaOpts.PhoneCount))
            }
            # The same verdict as data, for the JSON report - the summary above is
            # only text. Numbers only from a clean train: a rate-limited or failed
            # one has none that mean anything.
            $Shared.Health = $health
            $mm = $null
            if ($trainIdle -and $trainIdle.Ok -and -not ($trainIdle.Throttle -and $trainIdle.Throttle.Throttled)) {
                $mm = [ordered]@{
                    sent = $trainIdle.Sent; received = $trainIdle.Received; lossPct = $trainIdle.LossPct; lossResolutionPct = $trainIdle.LossResolutionPct
                    rttMinMs = $trainIdle.RttMinMs; rttP50Ms = $trainIdle.RttP50Ms; rttP95Ms = $trainIdle.RttP95Ms; rttMaxMs = $trainIdle.RttMaxMs
                    jitterMs = $trainIdle.JitterMs; jitterMaxMs = $trainIdle.JitterMaxMs; mos = $null; rValue = $null
                    soak = $null
                }
                if ($mosIdle -and $mosIdle.Ok) { $mm.mos = $mosIdle.Mos; $mm.rValue = $mosIdle.R }
            }
            if ($MediaOpts.SoakMinutes -gt 0 -and (Test-Path variable:cycles)) {
                if (-not $mm) { $mm = [ordered]@{ soak = $null } }
                $mm.soak = [ordered]@{ minutes = $MediaOpts.SoakMinutes; cycles = $cycles; outages = $outages; rateLimited = $throttles
                                       worstLossPct = $(if (@($lossL).Count) { ($lossL | Measure-Object -Maximum).Maximum } else { $null })
                                       worstJitterMs = $(if (@($jitL).Count) { ($jitL | Measure-Object -Maximum).Maximum } else { $null })
                                       worstRttP95Ms = $(if (@($p95L).Count) { ($p95L | Measure-Object -Maximum).Maximum } else { $null }) }
            }
            $Shared.MediaMetrics = $mm
            $Shared.MediaSummary = $sb2.ToString()
            PushMedia
            WriteLog ('Media/path checks complete - ' + $health.Headline)
            $Shared.Progress = 100
        }
        if ($rawPath -and (Test-Path -LiteralPath $rawPath)) {
            WriteLog ('Raw capture saved - send this file back to confirm page paths and SIP replies: {0}' -f $rawPath)
        }
    } catch {
        $Shared.Error = $_.Exception.Message
        WriteLog ('ERROR: {0}' -f $_.Exception.Message)
    } finally {
        $Shared.Progress = 100
        $Shared.Status   = 'Done.'
        $Shared.Done     = $true
    }
}

# ---------------------------------------------------------------------------
# UI construction
# ---------------------------------------------------------------------------
$script:lastCx        = @()
$script:lastPhones    = @()
$script:lastListeners = @()
$script:lastRoles     = @()
$script:lastSbc       = @()
$script:lastMedia     = @()
# For the JSON report: when each section was last measured, and the objects the
# grids only show as text. Nothing secret is ever kept here.
$script:ToolVersion      = '1.0.0'
$script:DefaultFqdn      = ''                   # no built-in PBX; the tech enters the FQDN
# What the FQDN box opens with: the shape of a 3CX name, with the part to type
# selected on first click. Never tested as a name - Get-FqdnBoxText reads it as
# empty, because "<" and ">" cannot be in a host name.
$script:FqdnTemplate     = '<test>.3cx.us'
$script:sectionTimes     = @{}
$script:lastCxSummary    = ''
$script:lastMediaSummary = ''
$script:lastHealth       = $null
$script:lastMediaMetrics = $null
$script:lastLocalSbc     = $null
$script:lastRunLog       = @()
$script:lastRunOptions   = @{}
$script:siteAutoValue    = ''
$script:ReportDirOverride = ''
$script:scanActive    = $false
# The media train sends a burst of SIP OPTIONS at the PBX. Re-running it back to
# back is the surest way to trip 3CX anti-hacking, so the UI enforces a cooldown.
$script:lastTrainAt   = [DateTime]::MinValue

$script:form = New-Object System.Windows.Forms.Form
$script:form.Text = '3CX Desk-Phone Connectivity Checker'
$script:form.Size = New-Object System.Drawing.Size(840, 740)
$script:form.MinimumSize = New-Object System.Drawing.Size(720, 560)
$script:form.StartPosition = 'CenterScreen'
$script:form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

$tlp = New-Object System.Windows.Forms.TableLayoutPanel
$tlp.Dock = 'Fill'
$tlp.ColumnCount = 1
$tlp.RowCount = 3
[void]$tlp.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
[void]$tlp.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 120)))
[void]$tlp.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
[void]$tlp.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 175)))
$script:form.Controls.Add($tlp)

# ---- Top input panel ----
$panelTop = New-Object System.Windows.Forms.Panel
$panelTop.Dock = 'Fill'

$lblFqdn = New-Object System.Windows.Forms.Label
$lblFqdn.Text = '3CX FQDN:'
$lblFqdn.Location = New-Object System.Drawing.Point(8, 12)
$lblFqdn.Size = New-Object System.Drawing.Size(96, 20)

$script:txtFqdn = New-Object System.Windows.Forms.TextBox
$script:txtFqdn.Location = New-Object System.Drawing.Point(108, 9)
$script:txtFqdn.Size = New-Object System.Drawing.Size(290, 24)
$script:txtFqdn.Text = $script:FqdnTemplate

# Site name for the report. Filled from the 3CX instance name when there is one
# (examplepbx.3cx.us -> EXAMPLEPBX); whatever the technician types wins.
$lblSite = New-Object System.Windows.Forms.Label
$lblSite.Text = 'Site name:'
$lblSite.Location = New-Object System.Drawing.Point(406, 12)
$lblSite.Size = New-Object System.Drawing.Size(64, 20)

$script:txtSite = New-Object System.Windows.Forms.TextBox
$script:txtSite.Location = New-Object System.Drawing.Point(472, 9)
$script:txtSite.Size = New-Object System.Drawing.Size(146, 24)

$script:btnReport = New-Object System.Windows.Forms.Button
$script:btnReport.Text = 'Export report'
$script:btnReport.Location = New-Object System.Drawing.Point(450, 84)
$script:btnReport.Size = New-Object System.Drawing.Size(170, 28)
$script:btnReport.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)

$script:btnCheckCx = New-Object System.Windows.Forms.Button
$script:btnCheckCx.Text = 'Check 3CX'
$script:btnCheckCx.Location = New-Object System.Drawing.Point(628, 8)
$script:btnCheckCx.Size = New-Object System.Drawing.Size(120, 26)

$lblSubnet = New-Object System.Windows.Forms.Label
$lblSubnet.Text = 'Subnet (CIDR):'
$lblSubnet.Location = New-Object System.Drawing.Point(8, 48)
$lblSubnet.Size = New-Object System.Drawing.Size(96, 20)

$script:txtSubnet = New-Object System.Windows.Forms.TextBox
$script:txtSubnet.Location = New-Object System.Drawing.Point(108, 45)
$script:txtSubnet.Size = New-Object System.Drawing.Size(200, 24)

# Shown only when this PC runs a 3CX SBC paired with a different PBX from the one
# in the box. On a real site the box still held the default and every 3CX result
# was for the wrong PBX; a status-bar line was too easy to miss. One click fills
# the box - it is never changed without that click.
$script:lnkUseSbcPbx = New-Object System.Windows.Forms.LinkLabel
$script:lnkUseSbcPbx.Location = New-Object System.Drawing.Point(316, 48)
$script:lnkUseSbcPbx.Size = New-Object System.Drawing.Size(306, 18)
$script:lnkUseSbcPbx.AutoEllipsis = $true
$script:lnkUseSbcPbx.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$script:lnkUseSbcPbx.LinkColor = [System.Drawing.Color]::FromArgb(170, 90, 0)
$script:lnkUseSbcPbx.ActiveLinkColor = [System.Drawing.Color]::FromArgb(120, 60, 0)
$script:lnkUseSbcPbx.Visible = $false

$script:tipTop = New-Object System.Windows.Forms.ToolTip
$script:tipTop.AutoPopDelay = 15000

$script:btnScanLan = New-Object System.Windows.Forms.Button
$script:btnScanLan.Text = 'Scan LAN'
$script:btnScanLan.Location = New-Object System.Drawing.Point(628, 44)
$script:btnScanLan.Size = New-Object System.Drawing.Size(120, 26)

$script:btnRunAll = New-Object System.Windows.Forms.Button
$script:btnRunAll.Text = 'Run All'
$script:btnRunAll.Location = New-Object System.Drawing.Point(8, 84)
$script:btnRunAll.Size = New-Object System.Drawing.Size(120, 28)

$script:btnExport = New-Object System.Windows.Forms.Button
$script:btnExport.Text = 'Export CSV'
$script:btnExport.Location = New-Object System.Drawing.Point(136, 84)
$script:btnExport.Size = New-Object System.Drawing.Size(110, 28)

$script:btnCopy = New-Object System.Windows.Forms.Button
$script:btnCopy.Text = 'Copy'
$script:btnCopy.Location = New-Object System.Drawing.Point(254, 84)
$script:btnCopy.Size = New-Object System.Drawing.Size(90, 28)

$script:btnClear = New-Object System.Windows.Forms.Button
$script:btnClear.Text = 'Clear'
$script:btnClear.Location = New-Object System.Drawing.Point(352, 84)
$script:btnClear.Size = New-Object System.Drawing.Size(90, 28)

$script:btnMedia = New-Object System.Windows.Forms.Button
$script:btnMedia.Text = 'Media Test'
$script:btnMedia.Location = New-Object System.Drawing.Point(628, 80)
$script:btnMedia.Size = New-Object System.Drawing.Size(120, 28)

$panelTop.Controls.AddRange(@($lblFqdn, $script:txtFqdn, $lblSite, $script:txtSite, $script:btnCheckCx, $lblSubnet, $script:txtSubnet, $script:lnkUseSbcPbx, $script:btnScanLan, $script:btnRunAll, $script:btnExport, $script:btnCopy, $script:btnClear, $script:btnReport, $script:btnMedia))
$tlp.Controls.Add($panelTop, 0, 0)

# ---- Grid factory ----
function New-Grid {
    $g = New-Object System.Windows.Forms.DataGridView
    $g.Dock = 'Fill'
    $g.ReadOnly = $true
    $g.AllowUserToAddRows = $false
    $g.AllowUserToDeleteRows = $false
    $g.AllowUserToResizeRows = $false
    $g.RowHeadersVisible = $false
    $g.SelectionMode = 'FullRowSelect'
    $g.MultiSelect = $false
    $g.AutoSizeColumnsMode = 'Fill'
    $g.BackgroundColor = [System.Drawing.Color]::White
    $g.BorderStyle = 'None'
    $g.ColumnHeadersHeightSizeMode = 'DisableResizing'
    $g.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    return $g
}

# ---- Tabs ----
$tab = New-Object System.Windows.Forms.TabControl
$tab.Dock = 'Fill'

$tabCx = New-Object System.Windows.Forms.TabPage
$tabCx.Text = '3CX Connectivity'
$tabCx.Padding = New-Object System.Windows.Forms.Padding(4)

$script:gridCx = New-Grid
[void]$script:gridCx.Columns.Add('cxCheck',  'Check')
[void]$script:gridCx.Columns.Add('cxTarget', 'Target')
[void]$script:gridCx.Columns.Add('cxPort',   'Port')
[void]$script:gridCx.Columns.Add('cxResult', 'Result')
[void]$script:gridCx.Columns.Add('cxDetail', 'Detail')
$script:gridCx.Columns['cxCheck'].FillWeight  = 10
$script:gridCx.Columns['cxTarget'].FillWeight = 22
$script:gridCx.Columns['cxPort'].FillWeight   = 12
$script:gridCx.Columns['cxResult'].FillWeight = 18
$script:gridCx.Columns['cxDetail'].FillWeight = 40

$script:txtCxSummary = New-Object System.Windows.Forms.TextBox
$script:txtCxSummary.Multiline = $true
$script:txtCxSummary.ReadOnly = $true
$script:txtCxSummary.Dock = 'Top'
$script:txtCxSummary.Height = 96
$script:txtCxSummary.ScrollBars = 'Vertical'
$script:txtCxSummary.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)
$script:txtCxSummary.Font = New-Object System.Drawing.Font('Segoe UI', 9)

$tabCx.Controls.Add($script:gridCx)
$tabCx.Controls.Add($script:txtCxSummary)

$tabPhones = New-Object System.Windows.Forms.TabPage
$tabPhones.Text = 'Yealink Phones'
$tabPhones.Padding = New-Object System.Windows.Forms.Padding(4)
$script:gridPhones = New-Grid
# Each phone's own web login is typed straight into its row: User and Password
# are editable, every other column stays read-only. A click opens the cell.
$script:gridPhones.ReadOnly = $false
$script:gridPhones.SelectionMode = 'CellSelect'
$script:gridPhones.EditMode = 'EditOnEnter'
[void]$script:gridPhones.Columns.Add('phIp',     'IP Address')
[void]$script:gridPhones.Columns.Add('phMac',    'MAC Address')
[void]$script:gridPhones.Columns.Add('phModel',  'Model')
[void]$script:gridPhones.Columns.Add('phUser',   'User')
[void]$script:gridPhones.Columns.Add('phPass',   'Password')
# What the technician acts on first (registration / lock notes, where the phone
# registers and provisions), then the reference columns.
[void]$script:gridPhones.Columns.Add('phReg',    'Reg / Notes')
[void]$script:gridPhones.Columns.Add('phSip',    'SIP Server')
[void]$script:gridPhones.Columns.Add('phProv',   'Provisions from')
[void]$script:gridPhones.Columns.Add('phVq',     'VQ readiness')
[void]$script:gridPhones.Columns.Add('phFw',     'Firmware')
[void]$script:gridPhones.Columns.Add('phHost',   'Hostname')
# Column widths. Eleven columns used to share ~800 px by weight, so IP and MAC
# were cut off while notes columns sat half empty. Now: the short columns are
# sized to what they hold (Update-PhoneColumnWidths, capped), the long text
# columns share the rest with a floor, and below that the grid scrolls sideways
# with the IP column frozen so each row stays identifiable.
$script:phColFixed = [ordered]@{ phIp = @(100, 125); phMac = @(120, 145); phModel = @(60, 110); phUser = @(72, 0); phPass = @(88, 0); phFw = @(82, 130); phHost = @(76, 170) }   # start width, cap (0 = fixed)
$script:phColFill  = [ordered]@{ phSip = @(18, 130); phReg = @(32, 200); phVq = @(22, 150); phProv = @(26, 180) }                                                                       # weight, minimum
foreach ($n in $script:phColFixed.Keys) {
    $c = $script:gridPhones.Columns[$n]
    $c.AutoSizeMode = 'None'
    $c.Width = $script:phColFixed[$n][0]
}
foreach ($n in $script:phColFill.Keys) {
    $c = $script:gridPhones.Columns[$n]
    $c.AutoSizeMode = 'Fill'
    $c.FillWeight = $script:phColFill[$n][0]
    $c.MinimumWidth = $script:phColFill[$n][1]
}
$script:gridPhones.Columns['phIp'].Frozen = $true
$script:gridPhones.ScrollBars = 'Both'
foreach ($c in @($script:gridPhones.Columns)) {
    $c.ReadOnly = -not ($c.Name -eq 'phUser' -or $c.Name -eq 'phPass')
    if (-not $c.ReadOnly) { $c.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(255, 252, 230) }
}

# Probe controls (top strip of the Yealink tab)
$panelProbe = New-Object System.Windows.Forms.Panel
$panelProbe.Dock = 'Top'
$panelProbe.Height = 106
# Its real width BEFORE any child is added. A new Panel is 200 px wide, and a
# Right-anchored child records its right margin against that - a 780 px box once
# got a margin of -584 and was stretched off-screen when the panel docked at full
# width. (Found by the GUI self-test in Tests\Run-Tests.ps1.)
$panelProbe.Width = 802

$script:chkProbe = New-Object System.Windows.Forms.CheckBox
$script:chkProbe.Text = 'Log in to phones on Scan LAN / Run All (grid passwords)'
$script:chkProbe.Location = New-Object System.Drawing.Point(4, 4)
$script:chkProbe.Size = New-Object System.Drawing.Size(392, 20)

$script:chkRaw = New-Object System.Windows.Forms.CheckBox
$script:chkRaw.Text = 'Save raw probe data (phone pages + SIP replies)'
$script:chkRaw.Location = New-Object System.Drawing.Point(400, 4)
$script:chkRaw.Size = New-Object System.Drawing.Size(330, 20)

$script:chkSbc = New-Object System.Windows.Forms.CheckBox
$script:chkSbc.Text = 'Scan LAN for a 3CX SBC (SIP OPTIONS sweep of all live hosts) - see SIP / SBC tab'
$script:chkSbc.Location = New-Object System.Drawing.Point(4, 28)
$script:chkSbc.Size = New-Object System.Drawing.Size(560, 20)
# On by default: unticked, Scan LAN and Run All never looked for an SBC or Router
# Phone at all, which read as "none here". Costs about 15-20 s on a /24.
$script:chkSbc.Checked = $true

# One button: "Find phones" until the grid has some, then "Log in to N phone(s)"
# for the rows with a password typed in.
$script:btnPhonePwds = New-Object System.Windows.Forms.Button
$script:btnPhonePwds.Text = 'Find phones'
$script:btnPhonePwds.Location = New-Object System.Drawing.Point(4, 76)
$script:btnPhonePwds.Size = New-Object System.Drawing.Size(180, 26)
$script:btnPhonePwds.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)

$script:chkShowPw = New-Object System.Windows.Forms.CheckBox
$script:chkShowPw.Text = 'Show passwords'
$script:chkShowPw.Location = New-Object System.Drawing.Point(192, 80)
$script:chkShowPw.Size = New-Object System.Drawing.Size(124, 20)

$lblProbeHint = New-Object System.Windows.Forms.Label
$lblProbeHint.Text = 'Type each phone''s own web password into its row below (the 3CX admin console lists them per phone). Rows left blank get no login attempt. Ctrl+V pastes a column.'
$lblProbeHint.Location = New-Object System.Drawing.Point(322, 74)
$lblProbeHint.Size = New-Object System.Drawing.Size(474, 30)
$lblProbeHint.ForeColor = [System.Drawing.Color]::DimGray

# Voice-quality readiness. Read-only by design: the tool never changes a phone
# setting, because a web-UI change is wiped at the next 3CX provisioning cycle
# anyway. VQ is switched on through the 3CX template - hence the button.
$script:chkVq = New-Object System.Windows.Forms.CheckBox
$script:chkVq.Text = 'Also read voice-quality (VQ-RTCPXR) readiness - read-only, needs a phone login'
$script:chkVq.Location = New-Object System.Drawing.Point(4, 52)
$script:chkVq.Size = New-Object System.Drawing.Size(470, 20)
$script:chkVq.Checked = $true

$script:btnVqTemplate = New-Object System.Windows.Forms.Button
$script:btnVqTemplate.Text = 'Copy 3CX template lines for VQ'
$script:btnVqTemplate.Location = New-Object System.Drawing.Point(480, 49)
$script:btnVqTemplate.Size = New-Object System.Drawing.Size(210, 25)

# The selected phone's web page - also a double-click on its row, or right-click.
$script:btnPhoneWeb = New-Object System.Windows.Forms.Button
$script:btnPhoneWeb.Text = 'Open phone web page'
$script:btnPhoneWeb.Location = New-Object System.Drawing.Point(596, 23)
$script:btnPhoneWeb.Size = New-Object System.Drawing.Size(196, 25)

$panelProbe.Controls.AddRange(@($script:chkProbe, $script:chkRaw, $script:chkSbc, $script:chkVq, $script:btnVqTemplate, $script:btnPhoneWeb, $script:btnPhonePwds, $script:chkShowPw, $lblProbeHint))

$tabPhones.Controls.Add($script:gridPhones)
$tabPhones.Controls.Add($panelProbe)

$tabList = New-Object System.Windows.Forms.TabPage
$tabList.Text = 'Local Listeners'
$tabList.Padding = New-Object System.Windows.Forms.Padding(4)
$script:gridListeners = New-Grid
[void]$script:gridListeners.Columns.Add('lsAddr',  'Local Address')
[void]$script:gridListeners.Columns.Add('lsPort',  'Port')
[void]$script:gridListeners.Columns.Add('lsState', 'State')
[void]$script:gridListeners.Columns.Add('lsPid',   'PID')
[void]$script:gridListeners.Columns.Add('lsProc',  'Process')
$tabList.Controls.Add($script:gridListeners)

$tabNet = New-Object System.Windows.Forms.TabPage
$tabNet.Text = 'Network'
$tabNet.Padding = New-Object System.Windows.Forms.Padding(4)
$script:gridRoles = New-Grid
[void]$script:gridRoles.Columns.Add('nrRole',   'Role')
[void]$script:gridRoles.Columns.Add('nrIp',     'IP Address')
[void]$script:gridRoles.Columns.Add('nrMac',    'MAC')
[void]$script:gridRoles.Columns.Add('nrVendor', 'Vendor')
[void]$script:gridRoles.Columns.Add('nrNote',   'Note')
$script:gridRoles.Columns['nrRole'].FillWeight   = 14
$script:gridRoles.Columns['nrNote'].FillWeight   = 44
$tabNet.Controls.Add($script:gridRoles)

$tabSbc = New-Object System.Windows.Forms.TabPage
$tabSbc.Text = 'SIP / SBC'
$tabSbc.Padding = New-Object System.Windows.Forms.Padding(4)
$script:gridSbc = New-Grid
[void]$script:gridSbc.Columns.Add('sbIp',     'IP Address')
[void]$script:gridSbc.Columns.Add('sbVerdict','Verdict')
[void]$script:gridSbc.Columns.Add('sbPlat',   'Platform')
[void]$script:gridSbc.Columns.Add('sbVendor', 'Vendor')
[void]$script:gridSbc.Columns.Add('sbHost',   'Hostname')
[void]$script:gridSbc.Columns.Add('sbOs',     'SSH / OS')
[void]$script:gridSbc.Columns.Add('sbPorts',  'Open ports')
[void]$script:gridSbc.Columns.Add('sbSip',    'SIP')
[void]$script:gridSbc.Columns.Add('sbDetail', 'Why')
$script:gridSbc.Columns['sbIp'].FillWeight      = 11
$script:gridSbc.Columns['sbVerdict'].FillWeight = 15
$script:gridSbc.Columns['sbPlat'].FillWeight    = 15
$script:gridSbc.Columns['sbVendor'].FillWeight  = 10
$script:gridSbc.Columns['sbHost'].FillWeight    = 12
$script:gridSbc.Columns['sbOs'].FillWeight      = 14
$script:gridSbc.Columns['sbPorts'].FillWeight   = 16
$script:gridSbc.Columns['sbSip'].FillWeight     = 12
$script:gridSbc.Columns['sbDetail'].FillWeight  = 40
$tabSbc.Controls.Add($script:gridSbc)

# ---- SSH strip on the SIP / SBC tab ----
# The discovered-host grid and the thing you want a shell on are the same object,
# so this lives on that tab rather than a new one.
$panelSsh = New-Object System.Windows.Forms.Panel
$panelSsh.Dock = 'Top'
$panelSsh.Height = 128

$script:lblSbcTarget = New-Object System.Windows.Forms.Label
$script:lblSbcTarget.Text = 'Target:'
$script:lblSbcTarget.Location = New-Object System.Drawing.Point(4, 6)
$script:lblSbcTarget.Size = New-Object System.Drawing.Size(46, 18)
$script:lblSbcTarget.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)

# Editable, because a grid row is not always there to click: an SBC whose service
# has crashed stops answering SIP and drops off the grid - exactly when SSH is
# needed to restart it - and one on another VLAN is never in the ARP table.
$script:txtSbcTarget = New-Object System.Windows.Forms.TextBox
$script:txtSbcTarget.Location = New-Object System.Drawing.Point(52, 3)
$script:txtSbcTarget.Size = New-Object System.Drawing.Size(198, 22)

$lblSshUser = New-Object System.Windows.Forms.Label
$lblSshUser.Text = 'SSH user:'
$lblSshUser.Location = New-Object System.Drawing.Point(258, 6)
$lblSshUser.Size = New-Object System.Drawing.Size(58, 18)

$script:txtSshUser = New-Object System.Windows.Forms.TextBox
$script:txtSshUser.Location = New-Object System.Drawing.Point(318, 3)
$script:txtSshUser.Size = New-Object System.Drawing.Size(96, 22)

$lblSshPass = New-Object System.Windows.Forms.Label
$lblSshPass.Text = 'Password:'
$lblSshPass.Location = New-Object System.Drawing.Point(420, 6)
$lblSshPass.Size = New-Object System.Drawing.Size(60, 18)

$script:txtSshPass = New-Object System.Windows.Forms.TextBox
$script:txtSshPass.Location = New-Object System.Drawing.Point(482, 3)
$script:txtSshPass.Size = New-Object System.Drawing.Size(120, 22)
$script:txtSshPass.UseSystemPasswordChar = $true

$script:btnSshTerm = New-Object System.Windows.Forms.Button
$script:btnSshTerm.Text = 'Open SSH terminal'
$script:btnSshTerm.Location = New-Object System.Drawing.Point(610, 2)
$script:btnSshTerm.Size = New-Object System.Drawing.Size(138, 25)

$lblUserHint = New-Object System.Windows.Forms.Label
$lblUserHint.Text = 'Enter the SBC''s SSH username and password (whatever was set when it was deployed).'
$lblUserHint.Location = New-Object System.Drawing.Point(4, 28)
$lblUserHint.Size = New-Object System.Drawing.Size(760, 16)
$lblUserHint.ForeColor = [System.Drawing.Color]::DimGray

$lblCmd = New-Object System.Windows.Forms.Label
$lblCmd.Text = 'Command:'
$lblCmd.Location = New-Object System.Drawing.Point(4, 51)
$lblCmd.Size = New-Object System.Drawing.Size(62, 18)

$script:cboSbcCmd = New-Object System.Windows.Forms.ComboBox
$script:cboSbcCmd.DropDownStyle = 'DropDownList'
$script:cboSbcCmd.Location = New-Object System.Drawing.Point(68, 48)
$script:cboSbcCmd.Size = New-Object System.Drawing.Size(410, 22)

$script:btnSbcCopy = New-Object System.Windows.Forms.Button
$script:btnSbcCopy.Text = 'Copy'
$script:btnSbcCopy.Location = New-Object System.Drawing.Point(484, 47)
$script:btnSbcCopy.Size = New-Object System.Drawing.Size(60, 25)

$script:btnSbcRun = New-Object System.Windows.Forms.Button
$script:btnSbcRun.Text = 'Run (plink)'
$script:btnSbcRun.Location = New-Object System.Drawing.Point(548, 47)
$script:btnSbcRun.Size = New-Object System.Drawing.Size(90, 25)

$script:lblSbcNote = New-Object System.Windows.Forms.Label
$script:lblSbcNote.Text = ''
$script:lblSbcNote.Location = New-Object System.Drawing.Point(4, 74)
$script:lblSbcNote.Size = New-Object System.Drawing.Size(760, 30)
$script:lblSbcNote.ForeColor = [System.Drawing.Color]::FromArgb(70, 70, 70)

$script:lblSshState = New-Object System.Windows.Forms.Label
$script:lblSshState.Text = ''
$script:lblSshState.Location = New-Object System.Drawing.Point(4, 106)
$script:lblSshState.Size = New-Object System.Drawing.Size(760, 16)
$script:lblSshState.ForeColor = [System.Drawing.Color]::DimGray

$panelSsh.Controls.AddRange(@($script:lblSbcTarget, $script:txtSbcTarget, $lblSshUser, $script:txtSshUser, $lblSshPass, $script:txtSshPass,
                              $script:btnSshTerm, $lblUserHint, $lblCmd, $script:cboSbcCmd, $script:btnSbcCopy,
                              $script:btnSbcRun, $script:lblSbcNote, $script:lblSshState))

$script:txtSbcOut = New-Object System.Windows.Forms.TextBox
$script:txtSbcOut.Multiline = $true
$script:txtSbcOut.ReadOnly = $true
$script:txtSbcOut.Dock = 'Bottom'
$script:txtSbcOut.Height = 150
$script:txtSbcOut.ScrollBars = 'Both'
$script:txtSbcOut.WordWrap = $false
$script:txtSbcOut.BackColor = [System.Drawing.Color]::FromArgb(250, 250, 250)
$script:txtSbcOut.Font = New-Object System.Drawing.Font('Consolas', 9)

$tabSbc.Controls.Add($script:txtSbcOut)
$tabSbc.Controls.Add($panelSsh)

$tabMedia = New-Object System.Windows.Forms.TabPage
$tabMedia.Text = 'Media / Path Quality'
$tabMedia.Padding = New-Object System.Windows.Forms.Padding(4)

$script:gridMedia = New-Grid
[void]$script:gridMedia.Columns.Add('mqGroup',  'Group')
[void]$script:gridMedia.Columns.Add('mqCheck',  'Check')
[void]$script:gridMedia.Columns.Add('mqResult', 'Result')
[void]$script:gridMedia.Columns.Add('mqDetail', 'Detail')
$script:gridMedia.Columns['mqGroup'].FillWeight  = 13
$script:gridMedia.Columns['mqCheck'].FillWeight  = 20
$script:gridMedia.Columns['mqResult'].FillWeight = 19
$script:gridMedia.Columns['mqDetail'].FillWeight = 48

$script:txtMediaSummary = New-Object System.Windows.Forms.TextBox
$script:txtMediaSummary.Multiline = $true
$script:txtMediaSummary.ReadOnly = $true
$script:txtMediaSummary.Dock = 'Top'
$script:txtMediaSummary.Height = 88
$script:txtMediaSummary.ScrollBars = 'Vertical'
$script:txtMediaSummary.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)
$script:txtMediaSummary.Font = New-Object System.Drawing.Font('Segoe UI', 9)

$panelMedia = New-Object System.Windows.Forms.Panel
$panelMedia.Dock = 'Top'
$panelMedia.Height = 96

$script:chkMediaTrain = New-Object System.Windows.Forms.CheckBox
$script:chkMediaTrain.Text = 'UDP path quality - sends 400 SIP OPTIONS to the PBX over 20s'
$script:chkMediaTrain.Location = New-Object System.Drawing.Point(4, 4)
$script:chkMediaTrain.Size = New-Object System.Drawing.Size(420, 20)
$script:chkMediaTrain.Checked = $true

$script:chkMediaGentle = New-Object System.Windows.Forms.CheckBox
$script:chkMediaGentle.Text = 'Gentle rate (300 over 30s)'
$script:chkMediaGentle.Location = New-Object System.Drawing.Point(430, 4)
$script:chkMediaGentle.Size = New-Object System.Drawing.Size(190, 20)

$script:chkMediaNat = New-Object System.Windows.Forms.CheckBox
$script:chkMediaNat.Text = 'NAT mapping (STUN) + SIP ALG detection'
$script:chkMediaNat.Location = New-Object System.Drawing.Point(4, 26)
$script:chkMediaNat.Size = New-Object System.Drawing.Size(300, 20)
$script:chkMediaNat.Checked = $true

$script:chkMediaPath = New-Object System.Windows.Forms.CheckBox
$script:chkMediaPath.Text = 'Path MTU + RTP range reachability'
$script:chkMediaPath.Location = New-Object System.Drawing.Point(310, 26)
$script:chkMediaPath.Size = New-Object System.Drawing.Size(300, 20)
$script:chkMediaPath.Checked = $true

$script:chkMediaBinding = New-Object System.Windows.Forms.CheckBox
$script:chkMediaBinding.Text = 'NAT binding lifetime (adds 3.5 min of idle waiting)'
$script:chkMediaBinding.Location = New-Object System.Drawing.Point(4, 48)
$script:chkMediaBinding.Size = New-Object System.Drawing.Size(340, 20)

$lblSoak = New-Object System.Windows.Forms.Label
$lblSoak.Text = 'Soak:'
$lblSoak.Location = New-Object System.Drawing.Point(350, 50)
$lblSoak.Size = New-Object System.Drawing.Size(36, 18)

$script:cboSoak = New-Object System.Windows.Forms.ComboBox
$script:cboSoak.DropDownStyle = 'DropDownList'
$script:cboSoak.Location = New-Object System.Drawing.Point(388, 47)
$script:cboSoak.Size = New-Object System.Drawing.Size(150, 22)
[void]$script:cboSoak.Items.AddRange(@('Off (one-shot)','5 minutes','15 minutes','60 minutes'))
$script:cboSoak.SelectedIndex = 0

$lblPhones = New-Object System.Windows.Forms.Label
$lblPhones.Text = 'Phones on site:'
$lblPhones.Location = New-Object System.Drawing.Point(552, 50)
$lblPhones.Size = New-Object System.Drawing.Size(84, 18)

$script:numPhones = New-Object System.Windows.Forms.NumericUpDown
$script:numPhones.Location = New-Object System.Drawing.Point(638, 47)
$script:numPhones.Size = New-Object System.Drawing.Size(56, 22)
$script:numPhones.Minimum = 0
$script:numPhones.Maximum = 500
$script:numPhones.Value = 9

$lblMediaHint = New-Object System.Windows.Forms.Label
$lblMediaHint.Text = 'Measured over the SIP signalling path (UDP 5060) and STUN - nothing answers on the RTP range, so these are proxies for media, not media itself.'
$lblMediaHint.Location = New-Object System.Drawing.Point(4, 72)
$lblMediaHint.Size = New-Object System.Drawing.Size(800, 18)
$lblMediaHint.ForeColor = [System.Drawing.Color]::DimGray

$panelMedia.Controls.AddRange(@($script:chkMediaTrain, $script:chkMediaGentle, $script:chkMediaNat, $script:chkMediaPath, $script:chkMediaBinding, $lblSoak, $script:cboSoak, $lblPhones, $script:numPhones, $lblMediaHint))

$tabMedia.Controls.Add($script:gridMedia)
$tabMedia.Controls.Add($script:txtMediaSummary)
$tabMedia.Controls.Add($panelMedia)

# ---- Security tab ----
# Read-only, like everything else here. Three sources, each saying only what it can
# see - and the hint names the one thing none of them can: the router's port forwards.
$tabSec = New-Object System.Windows.Forms.TabPage
$tabSec.Text = 'Security'
$tabSec.Padding = New-Object System.Windows.Forms.Padding(4)

$panelSec = New-Object System.Windows.Forms.Panel
$panelSec.Dock = 'Top'
$panelSec.Height = 56

$script:btnSecPc = New-Object System.Windows.Forms.Button
$script:btnSecPc.Text = 'Check this PC''s SBC'
$script:btnSecPc.Location = New-Object System.Drawing.Point(4, 4)
$script:btnSecPc.Size = New-Object System.Drawing.Size(130, 26)

$script:btnSecEvents = New-Object System.Windows.Forms.Button
$script:btnSecEvents.Text = 'Import 3CX event log...'
$script:btnSecEvents.Location = New-Object System.Drawing.Point(140, 4)
$script:btnSecEvents.Size = New-Object System.Drawing.Size(170, 26)

$script:btnSecBlacklist = New-Object System.Windows.Forms.Button
$script:btnSecBlacklist.Text = 'Paste 3CX IP blacklist...'
$script:btnSecBlacklist.Location = New-Object System.Drawing.Point(316, 4)
$script:btnSecBlacklist.Size = New-Object System.Drawing.Size(176, 26)

$script:btnSecClear = New-Object System.Windows.Forms.Button
$script:btnSecClear.Text = 'Clear'
$script:btnSecClear.Location = New-Object System.Drawing.Point(498, 4)
$script:btnSecClear.Size = New-Object System.Drawing.Size(70, 26)

$lblSecHint = New-Object System.Windows.Forms.Label
$lblSecHint.Text = 'Read-only: changes nothing here, on the PBX or on the router. Blind spot: the router''s port forwards - not testable from inside the LAN.'
$lblSecHint.Location = New-Object System.Drawing.Point(4, 34)
$lblSecHint.Size = New-Object System.Drawing.Size(790, 18)
$lblSecHint.ForeColor = [System.Drawing.Color]::DimGray

$panelSec.Controls.AddRange(@($script:btnSecPc, $script:btnSecEvents, $script:btnSecBlacklist, $script:btnSecClear, $lblSecHint))

$script:gridSec = New-Grid
[void]$script:gridSec.Columns.Add('secSev',     'Severity')
[void]$script:gridSec.Columns.Add('secArea',    'Area')
[void]$script:gridSec.Columns.Add('secFinding', 'Finding')
[void]$script:gridSec.Columns.Add('secAction',  'What to do')
$script:gridSec.Columns['secSev'].FillWeight     = 8
$script:gridSec.Columns['secArea'].FillWeight    = 10
$script:gridSec.Columns['secFinding'].FillWeight = 46
$script:gridSec.Columns['secAction'].FillWeight  = 36
# Findings are sentences, so they wrap rather than hide behind an ellipsis.
$script:gridSec.DefaultCellStyle.WrapMode = [System.Windows.Forms.DataGridViewTriState]::True
$script:gridSec.AutoSizeRowsMode = 'AllCells'

$script:txtSecReport = New-Object System.Windows.Forms.TextBox
$script:txtSecReport.Multiline = $true
$script:txtSecReport.ReadOnly = $true
$script:txtSecReport.Dock = 'Bottom'
$script:txtSecReport.Height = 120
$script:txtSecReport.ScrollBars = 'Both'
$script:txtSecReport.WordWrap = $false
$script:txtSecReport.BackColor = [System.Drawing.Color]::FromArgb(250, 250, 250)
$script:txtSecReport.Font = New-Object System.Drawing.Font('Consolas', 9)

# Draggable, so the detailed report can be given room when it is the thing being read.
$splitSec = New-Object System.Windows.Forms.Splitter
$splitSec.Dock = 'Bottom'
$splitSec.Height = 5
$splitSec.MinExtra = 90
$splitSec.MinSize = 60

$tabSec.Controls.Add($script:gridSec)
$tabSec.Controls.Add($splitSec)
$tabSec.Controls.Add($script:txtSecReport)
$tabSec.Controls.Add($panelSec)

$tab.TabPages.AddRange(@($tabCx, $tabMedia, $tabPhones, $tabList, $tabNet, $tabSbc, $tabSec))
$tlp.Controls.Add($tab, 0, 1)

# ---- Bottom panel (progress + status + log) ----
$panelBottom = New-Object System.Windows.Forms.Panel
$panelBottom.Dock = 'Fill'

$lblLogTitle = New-Object System.Windows.Forms.Label
$lblLogTitle.Text = 'Activity Log:'
$lblLogTitle.Location = New-Object System.Drawing.Point(0, 2)
$lblLogTitle.Size = New-Object System.Drawing.Size(200, 16)
$lblLogTitle.Anchor = 'Top,Left'

$script:progress = New-Object System.Windows.Forms.ProgressBar
$script:progress.Location = New-Object System.Drawing.Point(0, 20)
$script:progress.Size = New-Object System.Drawing.Size(790, 16)
$script:progress.Minimum = 0
$script:progress.Maximum = 100
$script:progress.Style = 'Continuous'
$script:progress.Anchor = 'Top,Left,Right'

$script:lblStatus = New-Object System.Windows.Forms.Label
$script:lblStatus.Text = 'Ready.'
$script:lblStatus.Location = New-Object System.Drawing.Point(0, 40)
$script:lblStatus.Size = New-Object System.Drawing.Size(790, 16)
$script:lblStatus.Anchor = 'Top,Left,Right'

$script:txtLog = New-Object System.Windows.Forms.TextBox
$script:txtLog.Multiline = $true
$script:txtLog.ReadOnly = $true
$script:txtLog.ScrollBars = 'Both'
$script:txtLog.WordWrap = $false
$script:txtLog.Location = New-Object System.Drawing.Point(0, 60)
$script:txtLog.Size = New-Object System.Drawing.Size(790, 108)
$script:txtLog.Anchor = 'Top,Bottom,Left,Right'
$script:txtLog.BackColor = [System.Drawing.Color]::FromArgb(250, 250, 250)
$script:txtLog.ForeColor = [System.Drawing.Color]::FromArgb(20, 20, 20)
$script:txtLog.Font = New-Object System.Drawing.Font('Consolas', 9)

$panelBottom.Controls.AddRange(@($lblLogTitle, $script:progress, $script:lblStatus, $script:txtLog))
$tlp.Controls.Add($panelBottom, 0, 2)

# ---------------------------------------------------------------------------
# Rendering + actions
# ---------------------------------------------------------------------------
function Set-Busy {
    param([bool]$busy)
    $en = -not $busy
    $script:btnCheckCx.Enabled = $en
    $script:btnScanLan.Enabled = $en
    $script:btnRunAll.Enabled  = $en
    $script:btnExport.Enabled  = $en
    $script:btnCopy.Enabled    = $en
    $script:btnClear.Enabled   = $en
    if ($busy) { $script:btnPhonePwds.Enabled = $false } else { Update-PhoneLoginButton }
    $script:btnReport.Enabled    = $en
    # The media stage can run for an hour in soak mode, so its button stays live
    # and becomes the way out.
    $script:btnMedia.Text    = if ($busy) { 'Stop' } else { 'Media Test' }
    $script:btnMedia.Enabled = $true
}

function Render-Cx {
    param($sh)
    $script:sectionTimes['connectivity'] = Get-Date
    $script:lastCxSummary = [string]$sh.CxSummary
    $script:gridCx.Rows.Clear()
    $script:lastCx = @($sh.Cx)
    $bold = New-Object System.Drawing.Font($script:gridCx.Font, [System.Drawing.FontStyle]::Bold)
    foreach ($r in @($sh.Cx)) {
        $i = $script:gridCx.Rows.Add($r.Check, $r.Target, $r.Port, $r.Result, $r.Detail)
        $color = switch ($r.Status) {
            'ok'   { [System.Drawing.Color]::FromArgb(0, 128, 0) }
            'fail' { [System.Drawing.Color]::FromArgb(192, 0, 0) }
            default { [System.Drawing.Color]::DimGray }
        }
        $script:gridCx.Rows[$i].Cells['cxResult'].Style.ForeColor = $color
        $script:gridCx.Rows[$i].Cells['cxResult'].Style.Font = $bold
    }
    $script:txtCxSummary.Text = [string]$sh.CxSummary
    # The blacklist check compares allow entries with the site's real public IP.
    if ([string]$sh.PublicIp) {
        $script:lastPublicIp = [string]$sh.PublicIp
        if ($null -ne $script:secBlacklist) { Update-SecurityView }
    }
}

$script:phBoldFont = New-Object System.Drawing.Font($script:gridPhones.Font, [System.Drawing.FontStyle]::Bold)

function Update-PhoneColumnWidths {
    # The short columns fit what they hold - never narrower than their start
    # width (the header), never wider than their cap - so an IP or MAC is never
    # cut off and one long hostname cannot push everything else off-screen.
    $g = $script:gridPhones
    if (@($script:lastPhones | Where-Object { $_ -and $_.MAC }).Count -eq 0) { return }
    foreach ($n in $script:phColFixed.Keys) {
        $start = $script:phColFixed[$n][0]; $cap = $script:phColFixed[$n][1]
        if ($cap -le 0) { continue }
        $c = $g.Columns[$n]
        $g.AutoResizeColumn($c.Index, [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::AllCells)
        if ($c.Width -lt $start) { $c.Width = $start }
        if ($c.Width -gt $cap) { $c.Width = $cap }
    }
}

function Set-PhoneRowValues {
    # The read-only cells of one phone's row. User and Password are never touched
    # here - they are the technician's, not the scan's.
    param($Row, $Phone)
    $r = $Phone
    # Host only: the provisioning path is a secret and is never held.
    $prov = ''; $provBad = $false
    if ($r.PSObject.Properties['ProvHost'] -and $r.ProvHost) {
        $prov = [string]$r.ProvHost
        if ($r.PSObject.Properties['ProvMismatch'] -and $r.ProvMismatch) { $provBad = $true; $prov += ('  - ' + [string]$r.ProvNote) }
    }
    $Row.Cells['phIp'].Value    = [string]$r.IP
    $Row.Cells['phMac'].Value   = [string]$r.MAC
    $Row.Cells['phModel'].Value = [string]$r.Model
    $Row.Cells['phFw'].Value    = [string]$r.Firmware
    $Row.Cells['phSip'].Value   = [string]$r.SipServer
    $Row.Cells['phReg'].Value   = [string]$r.Reg
    $Row.Cells['phHost'].Value  = [string]$r.Hostname
    $Row.Cells['phVq'].Value    = [string]$r.Vq
    $Row.Cells['phProv'].Value  = $prov
    # A blocked collector route is the finding that matters most here.
    if ([string]$r.Vq -like 'outbound proxy ON*') { $Row.Cells['phVq'].Style.ForeColor = [System.Drawing.Color]::FromArgb(190, 110, 0) }
    else { $Row.Cells['phVq'].Style.ForeColor = [System.Drawing.Color]::Empty }
    if ($provBad) {
        $Row.Cells['phProv'].Style.ForeColor = [System.Drawing.Color]::FromArgb(192, 0, 0)
        $Row.Cells['phProv'].Style.Font = $script:phBoldFont
    } else {
        $Row.Cells['phProv'].Style.ForeColor = [System.Drawing.Color]::Empty
        $Row.Cells['phProv'].Style.Font = $null
    }
}

function Render-Phones {
    param($sh)
    $script:sectionTimes['phones'] = Get-Date
    $g = $script:gridPhones
    $phones = @($sh.Phones)
    $script:lastPhones = $phones

    # The same phones as the rows already showing - the worker re-publishes the
    # list once per phone as it reads them: update those rows in place, so a
    # password being typed is not interrupted. Matched by MAC, so a sorted grid
    # works too.
    $byKey = @{}
    foreach ($row in @($g.Rows)) { $k = Get-PhoneRowKey $row; if ($k) { $byKey[$k] = $row } }
    $same = ($phones.Count -gt 0 -and $phones.Count -eq $g.Rows.Count)
    if ($same) { foreach ($r in $phones) { if (-not $byKey.ContainsKey((ConvertTo-MacKey $r.MAC))) { $same = $false; break } } }
    if ($same) {
        foreach ($r in $phones) { Set-PhoneRowValues -Row $byKey[(ConvertTo-MacKey $r.MAC)] -Phone $r }
        Update-PhoneColumnWidths
        Update-PhoneLoginButton
        return
    }

    # A different set of phones: rebuild. Typing in progress is committed first
    # (CellEndEdit puts it in the store), and the cursor goes back to the same
    # phone and column afterwards.
    $keep = $null
    if ($g.CurrentCell) { $keep = @{ Key = (Get-PhoneRowKey $g.Rows[$g.CurrentCell.RowIndex]); Col = $g.Columns[$g.CurrentCell.ColumnIndex].Name } }
    if ($g.IsCurrentCellInEditMode) { [void]$g.EndEdit() }
    $g.Rows.Clear()
    if ($phones.Count -eq 0) {
        # The message goes in the wide notes column: in the IP column it was cut
        # off after a few words.
        $i = $g.Rows.Add()
        $g.Rows[$i].Cells['phIp'].Value = '(none)'
        $g.Rows[$i].Cells['phReg'].Value = 'No Yealink phones found here - phones on a separate voice VLAN cannot be seen from this PC; see the Activity Log.'
        $g.Rows[$i].ReadOnly = $true
        Update-PhoneLoginButton
        return
    }
    foreach ($r in $phones) {
        $row = $g.Rows[$g.Rows.Add()]
        Set-PhoneRowValues -Row $row -Phone $r
        $e = $script:phoneCredStore[(ConvertTo-MacKey $r.MAC)]
        $row.Cells['phUser'].Value = $(if ($e -and $e.User) { [string]$e.User } else { 'admin' })
    }
    Update-PhoneColumnWidths
    Update-PhonePassCells
    if ($keep -and $keep.Key) {
        foreach ($row in @($g.Rows)) {
            if ((Get-PhoneRowKey $row) -ne $keep.Key) { continue }
            # If the cell re-opens for editing, the caret goes to the end rather
            # than selecting everything - the next keystroke must not wipe it.
            $script:phGrid.Caret = $true
            try { $g.CurrentCell = $row.Cells[$keep.Col] } catch {}
            $script:phGrid.Caret = $false
            break
        }
    }
}

function Render-Listeners {
    param($sh)
    $script:sectionTimes['network'] = Get-Date
    $script:gridListeners.Rows.Clear()
    $script:lastListeners = @($sh.Listeners)
    if (@($sh.Listeners).Count -eq 0) {
        [void]$script:gridListeners.Rows.Add('(nothing listening locally on TCP 5001/5060/5061/5090 or UDP 5060/5090)', '', '', '', '')
        return
    }
    foreach ($r in @($sh.Listeners)) {
        [void]$script:gridListeners.Rows.Add($r.LocalAddress, $r.LocalPort, $r.State, $r.OwningProcess, $r.ProcessName)
    }
}

function Render-Roles {
    param($sh)
    $script:sectionTimes['network'] = Get-Date
    $script:gridRoles.Rows.Clear()
    $script:lastRoles = @($sh.Roles)
    if (@($sh.Roles).Count -eq 0) {
        [void]$script:gridRoles.Rows.Add('(gateway / DHCP roles not determined)', '', '', '', '')
        return
    }
    $bold = New-Object System.Drawing.Font($script:gridRoles.Font, [System.Drawing.FontStyle]::Bold)
    foreach ($r in @($sh.Roles)) {
        $i = $script:gridRoles.Rows.Add($r.Role, $r.IP, $r.MAC, $r.Vendor, $r.Note)
        if ($r.Warn) {
            $script:gridRoles.Rows[$i].Cells['nrNote'].Style.ForeColor = [System.Drawing.Color]::FromArgb(192, 0, 0)
            $script:gridRoles.Rows[$i].Cells['nrNote'].Style.Font = $bold
            $script:gridRoles.Rows[$i].Cells['nrVendor'].Style.ForeColor = [System.Drawing.Color]::FromArgb(192, 0, 0)
        }
    }
}

function Render-Sbc {
    param($sh)
    $script:sectionTimes['sbc'] = Get-Date
    $script:gridSbc.Rows.Clear()
    $script:lastSbc = @($sh.Sbc)
    if (@($sh.Sbc).Count -eq 0) {
        [void]$script:gridSbc.Rows.Add('(no SIP responders and no Raspberry Pi on the LAN - no local SBC detected)', '', '', '', '', '', '', '', '')
        return
    }
    $bold = New-Object System.Drawing.Font($script:gridSbc.Font, [System.Drawing.FontStyle]::Bold)
    foreach ($r in @($sh.Sbc)) {
        $sshTxt = 'no SSH'
        if ($r.SshOpen) { $sshTxt = $r.Os; if (-not $sshTxt) { $sshTxt = 'SSH open' } }
        $platTxt = $r.Platform
        if ($r.Ttl -gt 0 -and -not $r.SshOpen) { $platTxt = ($platTxt + '  (TTL ' + $r.Ttl + ')') }
        $i = $script:gridSbc.Rows.Add($r.IP, $r.Confidence, $platTxt, $r.Vendor, $r.Hostname, $sshTxt, $r.OpenPorts, $r.SipType, $r.Detail)
        $col = [System.Drawing.Color]::DimGray
        if     ($r.Confidence -like 'very likely*') { $col = [System.Drawing.Color]::FromArgb(0, 128, 0) }
        elseif ($r.Confidence -like 'likely*')      { $col = [System.Drawing.Color]::FromArgb(0, 110, 0) }
        elseif ($r.Confidence -like 'possible*')    { $col = [System.Drawing.Color]::FromArgb(190, 110, 0) }
        if ($r.IsRouterPhone) { $col = [System.Drawing.Color]::FromArgb(192, 0, 0) }
        # A Router Phone is a role, not a fault - but it is the site's SBC, so it
        # stands out in blue rather than reading as an ordinary candidate.
        if ($r.PSObject.Properties['Is3cxRouterPhone'] -and $r.Is3cxRouterPhone) { $col = [System.Drawing.Color]::FromArgb(0, 70, 160) }
        if ($r.PSObject.Properties['SbcMarker'] -and $r.SbcMarker -and -not $r.Is3cxRouterPhone) { $col = [System.Drawing.Color]::FromArgb(0, 128, 0) }
        # Tunnelling to a different PBX than the one under test overrides everything.
        if ($r.PSObject.Properties['ForwardsMismatch'] -and $r.ForwardsMismatch) { $col = [System.Drawing.Color]::FromArgb(192, 0, 0) }
        $isLocal = [bool]($r.PSObject.Properties['IsLocalSbc'] -and $r.IsLocalSbc)
        if ($isLocal) {
            if ($r.LocalHealth -eq 'ok')       { $col = [System.Drawing.Color]::FromArgb(0, 128, 0) }
            elseif ($r.LocalHealth -eq 'warn') { $col = [System.Drawing.Color]::FromArgb(190, 110, 0) }
            else                               { $col = [System.Drawing.Color]::FromArgb(192, 0, 0) }
        }
        $script:gridSbc.Rows[$i].Cells['sbVerdict'].Style.ForeColor = $col
        if ($isLocal -or $r.IsRouterPhone -or $r.Confidence -like 'very likely*' -or $r.Confidence -like 'likely*') {
            $script:gridSbc.Rows[$i].Cells['sbVerdict'].Style.Font = $bold
        }
        if ($r.Platform -eq 'Windows') { $script:gridSbc.Rows[$i].Cells['sbPlat'].Style.ForeColor = [System.Drawing.Color]::FromArgb(190, 110, 0) }
    }
}

function Render-Media {
    param($sh)
    $script:sectionTimes['media'] = Get-Date
    $script:lastMediaSummary = [string]$sh.MediaSummary
    $script:gridMedia.Rows.Clear()
    $script:lastMedia = @($sh.Media)
    if (@($sh.Media).Count -eq 0) {
        [void]$script:gridMedia.Rows.Add('(no media tests run yet)', '', '', '')
        $script:txtMediaSummary.Text = [string]$sh.MediaSummary
        return
    }
    $bold = New-Object System.Drawing.Font($script:gridMedia.Font, [System.Drawing.FontStyle]::Bold)
    foreach ($r in @($sh.Media)) {
        $i = $script:gridMedia.Rows.Add($r.Group, $r.Check, $r.Result, $r.Detail)
        $color = switch ($r.Status) {
            'ok'   { [System.Drawing.Color]::FromArgb(0, 128, 0) }
            'fail' { [System.Drawing.Color]::FromArgb(192, 0, 0) }
            'warn' { [System.Drawing.Color]::FromArgb(190, 110, 0) }
            default { [System.Drawing.Color]::DimGray }
        }
        $script:gridMedia.Rows[$i].Cells['mqResult'].Style.ForeColor = $color
        $script:gridMedia.Rows[$i].Cells['mqResult'].Style.Font = $bold
    }
    $script:txtMediaSummary.Text = [string]$sh.MediaSummary
}

# ---------------------------------------------------------------------------
# SIP / SBC tab - SSH actions
# ---------------------------------------------------------------------------
$script:sbcTargetIp = ''
$script:sbcTargetFromGrid = ''
$script:sbcCmds     = @()
$script:sshClients  = $null

function Sync-SshState {
    # Says plainly what is available. The terminal always works because ssh.exe
    # ships with Windows; only the Run button depends on plink being present.
    $script:sshClients = Find-SshClient
    $c = $script:sshClients
    $bits = [System.Collections.Generic.List[string]]::new()
    if ($c.Ssh)   { [void]$bits.Add('ssh.exe (built in)') }
    if ($c.Putty) { [void]$bits.Add('putty.exe') }
    if ($c.Plink) {
        $v = 'plink.exe'
        if ($c.PlinkVersion) { $v += (' - ' + $c.PlinkVersion) }
        if (-not $c.PwFileOk) { $v += ' [too old for -pwfile, needs PuTTY 0.77+]' }
        [void]$bits.Add($v)
    }
    if (@($bits).Count -eq 0) {
        $script:lblSshState.Text = 'No SSH client found at all - Windows OpenSSH is missing and PuTTY is not installed.'
    } else {
        $suffix = ''
        if (-not $c.Plink) { $suffix = '   |   plink not present, so Run is unavailable - use Copy and paste into the terminal.' }
        $script:lblSshState.Text = ('Found: ' + ((@($bits.ToArray()) -join ',  ')) + $suffix)
    }
    if (@($c.Rejected).Count -gt 0) {
        # A refused binary is not silently skipped: an unexpected plink.exe in the
        # shared tool dir is exactly what someone should look at.
        $script:lblSshState.Text += ('   |   IGNORED, not validly signed: ' + (@($c.Rejected) -join '; '))
    }
    Update-SbcButtons
}

function Update-SbcButtons {
    # Cheap, and safe to call on every grid click - unlike Sync-SshState, which
    # probes the filesystem and runs 'plink -V'.
    $c = $script:sshClients
    if (-not $c) {
        $script:btnSbcRun.Enabled = $false
        $script:btnSshTerm.Enabled = $false
        return
    }
    $script:btnSbcRun.Enabled  = [bool]($c.Plink -and $script:sbcTargetIp)
    $script:btnSshTerm.Enabled = [bool](($c.Ssh -or $c.Putty) -and $script:sbcTargetIp)
}

function Sync-SbcCommands {
    # Rebuilt from the live PBX FQDN so the "reach the PBX" command is never stale.
    $pbx = ''
    try { $pbx = Get-FqdnBoxText } catch {}
    $script:sbcCmds = @(Get-SbcCommandSet -PbxHost $pbx)
    $sel = $script:cboSbcCmd.SelectedIndex
    $script:cboSbcCmd.Items.Clear()
    foreach ($c in $script:sbcCmds) {
        $label = $c.Title
        if ($c.Destructive) { $label = ('!! ' + $label + '  (drops calls)') }
        [void]$script:cboSbcCmd.Items.Add($label)
    }
    if ($script:cboSbcCmd.Items.Count -gt 0) {
        if ($sel -ge 0 -and $sel -lt $script:cboSbcCmd.Items.Count) { $script:cboSbcCmd.SelectedIndex = $sel }
        else { $script:cboSbcCmd.SelectedIndex = 0 }
    }
}

function Get-SelectedSbcCommand {
    $i = $script:cboSbcCmd.SelectedIndex
    if ($i -lt 0 -or $i -ge @($script:sbcCmds).Count) { return $null }
    return $script:sbcCmds[$i]
}

function Show-SbcCommandNote {
    $c = Get-SelectedSbcCommand
    if (-not $c) { $script:lblSbcNote.Text = ''; return }
    $script:lblSbcNote.Text = $c.Note
    if ($c.Destructive) { $script:lblSbcNote.ForeColor = [System.Drawing.Color]::FromArgb(192, 0, 0) }
    else                { $script:lblSbcNote.ForeColor = [System.Drawing.Color]::FromArgb(70, 70, 70) }
}

function Set-SbcTargetFromGrid {
    # -Force is an explicit click, which always wins. Without it (the grid's own
    # SelectionChanged, which also fires when a scan re-renders and auto-selects
    # the first row) a value the technician TYPED is never overwritten.
    param([switch]$Force)
    $ip = ''
    try {
        if ($script:gridSbc.SelectedRows.Count -gt 0) {
            $ip = [string]$script:gridSbc.SelectedRows[0].Cells['sbIp'].Value
        }
    } catch {}
    if ($ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { return }      # placeholder row, nothing to take
    $cur = $script:txtSbcTarget.Text.Trim()
    if (-not $Force -and $cur -and $cur -ne $script:sbcTargetFromGrid) { return }
    $script:sbcTargetFromGrid = $ip
    $script:txtSbcTarget.Text = $ip          # TextChanged -> Sync-SbcTarget
}

function Sync-SbcTarget {
    # The target box is the single source of truth. An invalid entry turns pink
    # and disables the buttons rather than being passed anywhere.
    $t = $script:txtSbcTarget.Text.Trim()
    if ($t -and (Test-SshHostName $t)) {
        $script:sbcTargetIp = $t
        $script:txtSbcTarget.BackColor = [System.Drawing.SystemColors]::Window
    } else {
        $script:sbcTargetIp = ''
        if ($t) { $script:txtSbcTarget.BackColor = [System.Drawing.Color]::FromArgb(255, 225, 225) }
        else    { $script:txtSbcTarget.BackColor = [System.Drawing.SystemColors]::Window }
    }
    Update-SbcButtons
}

function Invoke-SbcCommandUi {
    # Runs one command through plink off the UI thread.
    #
    # DoEvents-pumped rather than fire-and-forget: the call is short and the
    # result is wanted immediately, but a hung SSH would otherwise freeze the
    # window for the full timeout.
    param($Cmd)
    if (-not $script:sbcTargetIp) { return }
    $c = $script:sshClients
    if (-not $c -or -not $c.Plink) {
        [void][System.Windows.Forms.MessageBox]::Show(
            'plink.exe is not available, so commands cannot be run from here. Use Copy and paste into the SSH terminal instead.',
            '3CX Checker', 'OK', 'Information'); return
    }
    $user = $script:txtSshUser.Text.Trim()
    if ($user -and -not (Test-SshUserName $user)) {
        [void][System.Windows.Forms.MessageBox]::Show('The SSH user may only contain letters, digits, dot, underscore and hyphen, and must not start with a hyphen.', '3CX Checker', 'OK', 'Warning'); return
    }
    if (-not $user) {
        [void][System.Windows.Forms.MessageBox]::Show('Enter the SSH user first.', '3CX Checker', 'OK', 'Warning'); return
    }
    if (-not $script:txtSshPass.Text) {
        [void][System.Windows.Forms.MessageBox]::Show(
            ('Enter the SSH password for ' + $user + '.' + [Environment]::NewLine + [Environment]::NewLine +
             'It is held for this session only, written to a temporary file with owner-only permissions that is deleted straight after the command, and never saved to a report.'),
            '3CX Checker', 'OK', 'Information'); return
    }
    if ($Cmd.Destructive) {
        $msg = ($Cmd.Title + [Environment]::NewLine + [Environment]::NewLine + $Cmd.Note + [Environment]::NewLine + [Environment]::NewLine +
                'Run this against ' + $script:sbcTargetIp + '?')
        if ([System.Windows.Forms.MessageBox]::Show($msg, 'Confirm - this changes the SBC', 'YesNo', 'Warning') -ne 'Yes') { return }
    }

    $script:btnSbcRun.Enabled = $false
    $script:btnSshTerm.Enabled = $false
    $old = $script:form.Cursor
    $script:form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    $script:txtSbcOut.Text = ('$ ' + $Cmd.Text + [Environment]::NewLine + [Environment]::NewLine + 'running...')
    $script:lblStatus.Text = ('Running on ' + $script:sbcTargetIp + '...')

    $rs = $null; $ps = $null
    try {
        $rs = [runspacefactory]::CreateRunspace([System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault())
        $rs.Open()
        $ps = [powershell]::Create(); $ps.Runspace = $rs
        [void]$ps.AddScript('
param($Src,$Plink,$Ip,$User,$Pass,$Cmd,$UseSudo)
. ([scriptblock]::Create($Src))
if ($UseSudo) { Invoke-PlinkCommand -PlinkPath $Plink -ComputerName $Ip -User $User -Password $Pass -Command $Cmd -TimeoutMs 30000 -Sudo }
else          { Invoke-PlinkCommand -PlinkPath $Plink -ComputerName $Ip -User $User -Password $Pass -Command $Cmd -TimeoutMs 30000 }
')
        [void]$ps.AddParameter('Src',   $HelpersSource)
        [void]$ps.AddParameter('Plink', $c.Plink)
        [void]$ps.AddParameter('Ip',    $script:sbcTargetIp)
        [void]$ps.AddParameter('User',  $user)
        [void]$ps.AddParameter('Pass',  $script:txtSshPass.Text)
        [void]$ps.AddParameter('Cmd',   $Cmd.Text)
        [void]$ps.AddParameter('UseSudo', [bool]$Cmd.NeedsSudo)
        $async = $ps.BeginInvoke()
        while (-not $async.IsCompleted) {
            [System.Windows.Forms.Application]::DoEvents()
            Start-Sleep -Milliseconds 60
        }
        $res = @($ps.EndInvoke($async))
        $r = $null; if (@($res).Count -gt 0) { $r = $res[0] }

        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine('$ ' + $Cmd.Text)
        [void]$sb.AppendLine('')
        if ($r) {
            if ($r.Output) { [void]$sb.AppendLine([string]$r.Output) }
            if ($r.Error) {
                [void]$sb.AppendLine('--- stderr ---')
                [void]$sb.AppendLine([string]$r.Error)
            }
            if (-not $r.Output -and -not $r.Error) { [void]$sb.AppendLine('(no output)') }
            [void]$sb.AppendLine(('--- exit code ' + $r.ExitCode + ' ---'))
            # A sudo password prompt cannot be answered by a captured session, so
            # name the cause rather than leaving a bare failure.
            if (([string]$r.Output + [string]$r.Error) -match '(?i)a (terminal|password) is required|PASSWORD-REQUIRED|sudo:') {
                [void]$sb.AppendLine('')
                [void]$sb.AppendLine('NOTE: sudo wanted a password. Raspberry Pi OS 6.2 (Trixie) turns off passwordless sudo on new installs. The password box above is fed to sudo over stdin, so check it is the right one for this account.')
            }
            $script:lblStatus.Text = ('Done (exit ' + $r.ExitCode + ').')
        } else {
            [void]$sb.AppendLine('(no result returned)')
            $script:lblStatus.Text = 'Command returned nothing.'
        }
        if ($ps.Streams.Error.Count) {
            [void]$sb.AppendLine('')
            foreach ($e in $ps.Streams.Error) { [void]$sb.AppendLine('runspace error: ' + $e) }
        }
        $script:txtSbcOut.Text = $sb.ToString()
    } catch {
        $script:txtSbcOut.Text = ('Failed: ' + $_.Exception.Message)
        $script:lblStatus.Text = 'Command failed.'
    } finally {
        if ($ps) { try { $ps.Dispose() } catch {} }
        if ($rs) { try { $rs.Close(); $rs.Dispose() } catch {} }
        $script:form.Cursor = $old
        Update-SbcButtons
    }
}

# ---------------------------------------------------------------------------
# Security tab
# ---------------------------------------------------------------------------
$script:secPc        = $null     # { Posture; Findings; Report } from Check this PC
$script:secEvents    = $null     # Get-3cxEventAnalysis result
$script:secEventPath = ''
$script:secBlacklist = $null     # parsed blacklist entries
$script:secBlText    = ''
$script:lastPublicIp = ''        # from the last Check 3CX run
$script:lastSec      = @()

function Set-SecBusy {
    param([bool]$busy)
    foreach ($b in @($script:btnSecPc, $script:btnSecEvents, $script:btnSecBlacklist, $script:btnSecClear)) { $b.Enabled = -not $busy }
    if ($busy) { $script:form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor } else { $script:form.Cursor = [System.Windows.Forms.Cursors]::Default }
}

function Invoke-SecurityJob {
    # Runs a helper off the UI thread and pumps messages meanwhile, the same way as
    # Invoke-SbcCommandUi: the firewall read and the config search take seconds.
    # Returns the job's last output; a terminating error in the job is rethrown.
    param([string]$Script,[hashtable]$Params = @{},[string]$Status = 'Working...')
    $rs = $null; $ps = $null
    Set-SecBusy $true
    $script:lblStatus.Text = $Status
    try {
        $rs = [runspacefactory]::CreateRunspace([System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault())
        $rs.Open()
        $ps = [powershell]::Create(); $ps.Runspace = $rs
        [void]$ps.AddScript($Script)
        [void]$ps.AddParameter('Src', $HelpersSource)
        foreach ($k in $Params.Keys) { [void]$ps.AddParameter($k, $Params[$k]) }
        $async = $ps.BeginInvoke()
        while (-not $async.IsCompleted) {
            [System.Windows.Forms.Application]::DoEvents()
            Start-Sleep -Milliseconds 60
        }
        $res = @($ps.EndInvoke($async))
        if (@($res).Count -eq 0) {
            if ($ps.Streams.Error.Count -gt 0) { throw ([string]$ps.Streams.Error[0]) }
            return $null
        }
        return $res[-1]
    } finally {
        if ($ps) { try { $ps.Dispose() } catch {} }
        if ($rs) { try { $rs.Close(); $rs.Dispose() } catch {} }
        Set-SecBusy $false
    }
}

function Get-SecSiteIps {
    # The site's public IP, only ever from something that measured or recorded it.
    $l = [System.Collections.Generic.List[object]]::new()
    if ($script:lastPublicIp) { $l.Add([pscustomobject]@{ Ip = $script:lastPublicIp; Source = 'measured by this tool' }) }
    if ($script:secEvents) {
        foreach ($h in @($script:secEvents.History)) {
            if ($h.PublicIp) { $l.Add([pscustomobject]@{ Ip = [string]$h.PublicIp; Source = ('SBC ''' + $h.Name + ''' in the PBX event log') }) }
        }
    }
    return @($l.ToArray())
}

function Update-SecurityView {
    $all = [System.Collections.Generic.List[object]]::new()
    $rep = New-Object System.Text.StringBuilder
    if ($script:secPc) {
        foreach ($f in @($script:secPc.Findings)) { $all.Add($f) }
        [void]$rep.AppendLine([string]$script:secPc.Report)
    }
    if ($script:secEvents) {
        foreach ($f in @($script:secEvents.Findings)) { $all.Add($f) }
        [void]$rep.AppendLine('File: ' + $script:secEventPath)
        [void]$rep.AppendLine([string]$script:secEvents.Report)
    }
    if ($null -ne $script:secBlacklist) {
        $atk = $null; if ($script:secEvents) { $atk = $script:secEvents.Attacks }
        foreach ($f in @(Get-3cxBlacklistFindings -Entries $script:secBlacklist -SiteIps (Get-SecSiteIps) -Attacks $atk)) { $all.Add($f) }
        [void]$rep.AppendLine('=== 3CX IP blacklist (pasted) ===')
        foreach ($e in @($script:secBlacklist)) {
            $m = ''; if ($e.Mask) { $m = ('/' + $e.Mask) }
            [void]$rep.AppendLine(('{0,-6} {1,-32} expires {2,-20} {3}' -f $e.Action, ($e.Ip + $m), $e.Expires, $e.Description))
        }
    }
    # Most severe first; within a severity, the order each source produced them in.
    $i = 0
    $sorted = @($all | ForEach-Object { [pscustomobject]@{ F = $_; R = (Get-SecSeverityRank $_.Severity); I = $i++ } } | Sort-Object R, I | ForEach-Object { $_.F })
    $script:lastSec = $sorted

    $script:gridSec.Rows.Clear()
    if (@($sorted).Count -eq 0) {
        [void]$script:gridSec.Rows.Add('', '', '(nothing checked yet - use the buttons above)', '')
    }
    $bold = New-Object System.Drawing.Font($script:gridSec.Font, [System.Drawing.FontStyle]::Bold)
    foreach ($f in $sorted) {
        $label = switch ($f.Severity) { 'high' { 'HIGH' } 'review' { 'REVIEW' } 'ok' { 'OK' } default { 'info' } }
        $i = $script:gridSec.Rows.Add($label, $f.Area, $f.Finding, $f.Action)
        $c = switch ($f.Severity) {
            'high'   { [System.Drawing.Color]::FromArgb(192, 0, 0) }
            'review' { [System.Drawing.Color]::FromArgb(190, 110, 0) }
            'ok'     { [System.Drawing.Color]::FromArgb(0, 128, 0) }
            default  { [System.Drawing.Color]::DimGray }
        }
        $script:gridSec.Rows[$i].Cells['secSev'].Style.ForeColor = $c
        if ($f.Severity -eq 'high' -or $f.Severity -eq 'review') { $script:gridSec.Rows[$i].Cells['secSev'].Style.Font = $bold }
    }
    $script:txtSecReport.Text = $rep.ToString()
}

function Start-SecPcCheck {
    try {
        $r = Invoke-SecurityJob -Status 'Checking this PC for the 3CX SBC (its files, SIP and 3CX ports)...' -Script '
param($Src)
. ([scriptblock]::Create($Src))
$P = Get-LocalSecurityPosture
[pscustomobject]@{ Posture = $P; Findings = @(Get-PostureFindings $P); Report = (Format-PostureReport $P) }
'
        if (-not $r) { throw 'The check returned nothing.' }
        $script:secPc = $r
        Update-SecurityView
        $script:sectionTimes['security.thisPc'] = Get-Date
        $script:lblStatus.Text = 'This PC checked.'
    } catch {
        $script:lblStatus.Text = 'This-PC check failed.'
        [void][System.Windows.Forms.MessageBox]::Show(('The check of this PC failed: ' + $_.Exception.Message), '3CX Checker', 'OK', 'Warning')
    }
}

function Start-SecEventImport {
    $ofd = New-Object System.Windows.Forms.OpenFileDialog
    $ofd.Title = 'Open a 3CX event log export (CSV)'
    $ofd.Filter = 'CSV files (*.csv)|*.csv|All files (*.*)|*.*'
    if ($ofd.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }
    $path = $ofd.FileName
    try {
        # The PBX log says WHEN the tunnel dropped. When the SBC is on this PC, its own
        # logs (local time) and Windows' restart events say WHY: a reboot, a stopped
        # service, or the site's DNS/internet.
        $r = Invoke-SecurityJob -Params @{ Path = $path } -Status 'Reading the 3CX event log...' -Script '
param($Src,$Path)
. ([scriptblock]::Create($Src))
$ev = Import-3cxEventLog -Path $Path
$ips = @(); $sbcEv = @(); $stops = @(); $win = @()
try { $ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | ForEach-Object { [string]$_.IPAddress }) } catch {}
$sp = Get-LocalSbcPath
try {
    if (Test-Path -LiteralPath $sp.Log) {
        $lg = ConvertFrom-SbcLog -Lines @(Get-Content -LiteralPath $sp.Log -Tail 50000 -ErrorAction Stop)
        $sbcEv = @($lg.Events | ForEach-Object { [pscustomobject]@{ TimeUtc = $_.Time.ToUniversalTime(); Kind = $_.Kind } })
    }
} catch {}
try {
    if (Test-Path -LiteralPath $sp.Mon) {
        $stops = @(ConvertFrom-SbcMonLog -Lines @(Get-Content -LiteralPath $sp.Mon -ErrorAction Stop) | ForEach-Object { [pscustomobject]@{ TimeUtc = $_.Time.ToUniversalTime(); Kind = $_.Kind } })
    }
} catch {}
$tm = @($ev | Where-Object { $_.TimeUtc } | Sort-Object TimeUtc)
if (@($tm).Count -gt 0) { $win = @(Get-WindowsRestartEvents -StartUtc $tm[0].TimeUtc.AddHours(-1) -EndUtc $tm[-1].TimeUtc.AddHours(1)) }
Get-3cxEventAnalysis -Events $ev -SbcEvents $sbcEv -SbcStops $stops -WinRestarts $win -LocalIps $ips
'
        if (-not $r) { throw 'The analysis returned nothing.' }
        $script:secEvents = $r
        $script:secEventPath = $path
        Update-SecurityView
        $script:sectionTimes['security.eventLog'] = Get-Date
        $script:lblStatus.Text = ('Event log read: {0} events.' -f $r.Count)
    } catch {
        $script:lblStatus.Text = 'Event log import failed.'
        [void][System.Windows.Forms.MessageBox]::Show($_.Exception.Message, '3CX Checker - event log', 'OK', 'Warning')
    }
}

function Show-BlacklistPasteDialog {
    $f = New-Object System.Windows.Forms.Form
    $f.Text = 'Paste the 3CX IP blacklist'
    $f.Size = New-Object System.Drawing.Size(700, 440)
    $f.StartPosition = 'CenterParent'
    $f.FormBorderStyle = 'FixedDialog'
    $f.MinimizeBox = $false; $f.MaximizeBox = $false
    $f.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $l = New-Object System.Windows.Forms.Label
    $l.Text = ('In the 3CX admin console, open the IP blacklist page, select its rows - with the header row if you can - copy, and paste them here.' + [Environment]::NewLine +
               'The text is only read by this tool: nothing is sent anywhere and nothing on the PBX changes.')
    $l.Location = New-Object System.Drawing.Point(10, 8)
    $l.Size = New-Object System.Drawing.Size(665, 36)
    $tb = New-Object System.Windows.Forms.TextBox
    $tb.Multiline = $true; $tb.ScrollBars = 'Both'; $tb.WordWrap = $false; $tb.AcceptsTab = $true
    $tb.Location = New-Object System.Drawing.Point(10, 48)
    $tb.Size = New-Object System.Drawing.Size(665, 300)
    $tb.Font = New-Object System.Drawing.Font('Consolas', 9)
    $tb.Text = $script:secBlText
    $ok = New-Object System.Windows.Forms.Button
    $ok.Text = 'Check'; $ok.DialogResult = 'OK'
    $ok.Location = New-Object System.Drawing.Point(504, 358); $ok.Size = New-Object System.Drawing.Size(84, 28)
    $cancel = New-Object System.Windows.Forms.Button
    $cancel.Text = 'Cancel'; $cancel.DialogResult = 'Cancel'
    $cancel.Location = New-Object System.Drawing.Point(592, 358); $cancel.Size = New-Object System.Drawing.Size(84, 28)
    $f.Controls.AddRange(@($l, $tb, $ok, $cancel))
    $f.CancelButton = $cancel
    $res = $f.ShowDialog($script:form)
    $text = $tb.Text
    $f.Dispose()
    if ($res -ne [System.Windows.Forms.DialogResult]::OK) { return $null }
    return $text
}

function Start-SecBlacklist {
    $t = Show-BlacklistPasteDialog
    if ($null -eq $t) { return }
    $script:secBlText = $t
    $script:secBlacklist = @(ConvertFrom-3cxBlacklistText -Text $t)
    Update-SecurityView
    $script:sectionTimes['security.blacklist'] = Get-Date
    $script:lblStatus.Text = ('Blacklist read: {0} entr(ies).' -f @($script:secBlacklist).Count)
}

function Clear-Security {
    $script:secPc = $null; $script:secEvents = $null; $script:secEventPath = ''
    $script:secBlacklist = $null; $script:secBlText = ''
    foreach ($k in @('security.thisPc', 'security.eventLog', 'security.blacklist')) { $script:sectionTimes.Remove($k) }
    Update-SecurityView
}

# ---------------------------------------------------------------------------
# FQDN box vs this PC's SBC
# ---------------------------------------------------------------------------
$script:localSbcPbx   = ''      # TunnelAddr of the 3CX SBC on this PC, if any
$script:fqdnConfirmed = ''      # a mismatched name the technician chose to test anyway

function Get-FqdnBoxText {
    # What is typed in the FQDN box, or '' while it still holds the <test>
    # template (or any unfilled <...> part) - that is not a name to test, and it
    # would have marked every phone as provisioning from "another PBX".
    $t = $script:txtFqdn.Text.Trim()
    if ($t -match '[<>]') { return '' }
    return $t
}

function Get-FqdnBoxHost {
    # The host part of whatever is typed - the box also takes a URL.
    $t = Get-FqdnBoxText
    return ((($t -replace '^\s*https?://', '') -replace '/.*$', '') -replace ':\d+$', '')
}

function Select-FqdnTemplatePart {
    # Selects the "<test>" part, so typing the site name replaces just that.
    $t = $script:txtFqdn.Text
    $a = $t.IndexOf('<'); $b = $t.IndexOf('>')
    if ($a -ge 0 -and $b -gt $a) { $script:txtFqdn.Select($a, $b - $a + 1) }
}

function Update-FqdnHint {
    # Name comparison only (no DNS on every keystroke); Start-Scan does the
    # resolving check before it asks.
    $pbx = $script:localSbcPbx
    $h = Get-FqdnBoxHost
    # The template reads grey until a real name replaces it.
    if ($script:txtFqdn.Text -match '[<>]') { $script:txtFqdn.ForeColor = [System.Drawing.SystemColors]::GrayText }
    else { $script:txtFqdn.ForeColor = [System.Drawing.SystemColors]::WindowText }
    $mis = [bool]($pbx -and $h -and (Test-SbcPbxMismatch -TestFqdn $h -TunnelAddr $pbx -SkipResolve))
    if ($mis) {
        $script:txtFqdn.BackColor = [System.Drawing.Color]::FromArgb(255, 226, 160)
        $script:tipTop.SetToolTip($script:txtFqdn, ('This PC runs the 3CX SBC, and it is paired with ' + $pbx + ' - not ' + $h + '. Every 3CX and media result is for whichever PBX is in this box.'))
    } else {
        $script:txtFqdn.BackColor = [System.Drawing.SystemColors]::Window
        $script:tipTop.SetToolTip($script:txtFqdn, 'The PBX to test: a name such as examplepbx.3cx.us, or its URL.')
    }
    # Offered when the box names another PBX, and when it is empty.
    if ($pbx -and ($mis -or -not $h)) {
        $script:lnkUseSbcPbx.Text = ('Use ' + $pbx + ' (this PC''s SBC)')
        $script:tipTop.SetToolTip($script:lnkUseSbcPbx, ('This PC''s 3CX SBC is paired with ' + $pbx + '. Click to test that PBX.'))
        $script:lnkUseSbcPbx.Visible = $true
    } else {
        $script:lnkUseSbcPbx.Visible = $false
    }
}

function Confirm-SbcPbxTarget {
    # Last chance before testing a PBX other than the one this PC's SBC uses.
    # Returns $false to cancel. Asks once per name: "test it anyway" sticks.
    param([string]$Mode)
    if (-not $script:localSbcPbx) { return $true }
    if (-not ($Mode -eq 'Cx' -or $Mode -eq 'All' -or $Mode -eq 'Media')) { return $true }
    $h = Get-FqdnBoxHost
    if (-not $h -or $script:fqdnConfirmed -eq $h.ToLower()) { return $true }
    if (-not (Test-SbcPbxMismatch -TestFqdn $h -TunnelAddr $script:localSbcPbx)) { return $true }
    $nl = [Environment]::NewLine
    $msg = ('This PC runs the 3CX SBC, paired with:' + $nl + '    ' + $script:localSbcPbx + $nl + $nl +
            'The box says:' + $nl + '    ' + $h + $nl + $nl +
            'Yes  - test ' + $script:localSbcPbx + ' instead' + $nl +
            'No   - test ' + $h + ' as typed' + $nl +
            'Cancel - do nothing')
    $a = [System.Windows.Forms.MessageBox]::Show($msg, '3CX Checker - which PBX?', 'YesNoCancel', 'Question')
    if ($a -eq 'Cancel') { return $false }
    if ($a -eq 'Yes') {
        $script:txtFqdn.Text = $script:localSbcPbx
        Sync-SbcCommands; Show-SbcCommandNote
    } else {
        $script:fqdnConfirmed = $h.ToLower()
    }
    return $true
}

# ---------------------------------------------------------------------------
# Phone passwords: typed into the Yealink grid, one row per phone
# ---------------------------------------------------------------------------
# Held for this session only, keyed by MAC - never written to disk, the log, an
# export or the report. The grid only ever shows asterisks (or the password,
# with Show passwords ticked); the real value lives here.
$script:phoneCredStore = @{}
$script:afterScan      = ''
# Show = Show passwords ticked; Armed = typing goes to the store; Tb = the hooked
# editor; Caret = re-opened cell keeps the caret at the end instead of selecting.
$script:phGrid = @{ Show = $false; Armed = $false; Tb = $null; Caret = $false }

function ConvertTo-MacKey {
    param([string]$Mac)
    return ($Mac -replace '[^0-9A-Fa-f]', '').ToUpper()
}

function Get-PhoneRowKey {
    # The row's phone, by its MAC cell - never by row index: the rows are rebuilt
    # and can be sorted.
    param($Row)
    if (-not $Row) { return '' }
    return (ConvertTo-MacKey ([string]$Row.Cells['phMac'].Value))
}

function Get-PhoneCredEntry {
    param([string]$Key)
    if (-not $script:phoneCredStore.ContainsKey($Key)) { $script:phoneCredStore[$Key] = @{ User = 'admin'; Pass = '' } }
    return $script:phoneCredStore[$Key]
}

function Get-StoredPhoneCreds {
    # The grid's passwords as credential entries, tagged by MAC so each is only
    # ever tried on its own phone. With -Phones, only those phones' entries.
    param($Phones = $null)
    $keys = @($script:phoneCredStore.Keys)
    if ($null -ne $Phones) { $keys = @(@($Phones) | ForEach-Object { ConvertTo-MacKey $_.MAC } | Where-Object { $_ -and $script:phoneCredStore.ContainsKey($_) }) }
    return @(foreach ($k in $keys) {
        $e = $script:phoneCredStore[$k]
        if ($e -and $e.Pass) {
            $u = [string]$e.User; if (-not $u) { $u = 'admin' }
            [pscustomobject]@{ Id = [string]$k; User = $u; Pass = [string]$e.Pass }
        }
    })
}

function Update-PhoneLoginButton {
    # "Find phones" until the grid has some; then "Log in to N phone(s)", N being
    # the listed phones with a password typed in. Follows the typing live.
    $b = $script:btnPhonePwds
    $phones = @($script:lastPhones | Where-Object { $_ -and $_.MAC })
    if ($phones.Count -eq 0) { $b.Text = 'Find phones'; $b.Enabled = -not $script:scanActive; return }
    $n = @(Get-StoredPhoneCreds -Phones $phones).Count
    $b.Text = ('Log in to {0} phone(s)' -f $n)
    $b.Enabled = ($n -gt 0 -and -not $script:scanActive)
}

function Update-PhonePassCells {
    # Display only, and only once editing has ended. Nothing is ever read back
    # from what the grid shows - a masked value copied back would silently replace
    # a password with "********".
    foreach ($row in @($script:gridPhones.Rows)) {
        $k = Get-PhoneRowKey $row
        if (-not $k) { continue }
        $v = ''
        if ($script:phoneCredStore.ContainsKey($k)) { $v = [string]$script:phoneCredStore[$k].Pass }
        $row.Cells['phPass'].Value = $(if ($script:phGrid.Show) { $v } else { '*' * $v.Length })
    }
    Update-PhoneLoginButton
}

function Invoke-PhoneGridPaste {
    # Several lines (or tab-separated cells) pasted into the grid: fill down from
    # the current cell, and across for tabs, so User and Password can come from a
    # spreadsheet together. Only User and Password are ever written. Returns the
    # number of cells filled.
    param([string]$Text)
    $g = $script:gridPhones
    if (-not $g.CurrentCell) { return 0 }
    $script:phGrid.Armed = $false
    if ($g.IsCurrentCellInEditMode) { [void]$g.CancelEdit(); [void]$g.EndEdit() }
    $lines = @($Text -split "`r?`n")
    if ($lines.Count -gt 1 -and $lines[-1] -eq '') { $lines = $lines[0..($lines.Count - 2)] }
    $r0 = $g.CurrentCell.RowIndex; $c0 = $g.CurrentCell.ColumnIndex
    $n = 0
    for ($k = 0; $k -lt $lines.Count -and ($r0 + $k) -lt $g.Rows.Count; $k++) {
        $row = $g.Rows[$r0 + $k]
        $key = Get-PhoneRowKey $row
        if (-not $key) { continue }
        $en = Get-PhoneCredEntry $key
        $cells = @($lines[$k] -split "`t")
        for ($j = 0; $j -lt $cells.Count -and ($c0 + $j) -lt $g.Columns.Count; $j++) {
            $name = $g.Columns[$c0 + $j].Name
            if ($name -eq 'phPass') {
                $en.Pass = $cells[$j]
                if ($cells[$j]) { $script:chkProbe.Checked = $true }
                $n++
            } elseif ($name -eq 'phUser') {
                $u = $cells[$j].Trim(); if (-not $u) { $u = 'admin' }
                $en.User = $u
                $row.Cells['phUser'].Value = $u
                $n++
            }
        }
    }
    Update-PhonePassCells
    return $n
}

# Editing a Password cell: the editor starts with the real value (masked unless
# shown), selected so typing replaces it, and every keystroke goes straight to the
# store - so the Log in button follows as you type.
$script:gridPhones.Add_EditingControlShowing({
    param($s, $e)
    $g = $script:gridPhones; $st = $script:phGrid
    $tb = $e.Control -as [System.Windows.Forms.TextBox]
    if (-not $tb -or -not $g.CurrentCell) { return }
    $st.Armed = $false
    if (-not [object]::ReferenceEquals($st.Tb, $tb)) {
        $st.Tb = $tb
        $tb.Add_TextChanged({
            $g = $script:gridPhones; $st = $script:phGrid
            if (-not ($st.Armed -and $g.CurrentCell)) { return }
            if ($g.Columns[$g.CurrentCell.ColumnIndex].Name -ne 'phPass') { return }
            $k = Get-PhoneRowKey $g.Rows[$g.CurrentCell.RowIndex]
            if (-not $k) { return }
            $en = Get-PhoneCredEntry $k
            $en.Pass = $st.Tb.Text
            # A password typed means the phones should be read on later Scan LAN /
            # Run All too, not only on Log in.
            if ($en.Pass) { $script:chkProbe.Checked = $true }
            Update-PhoneLoginButton
        })
    }
    $isPw = ($g.Columns[$g.CurrentCell.ColumnIndex].Name -eq 'phPass')
    $tb.UseSystemPasswordChar = ($isPw -and -not $st.Show)
    if ($isPw) {
        $k = Get-PhoneRowKey $g.Rows[$g.CurrentCell.RowIndex]
        $tb.Text = $(if ($k -and $script:phoneCredStore.ContainsKey($k)) { [string]$script:phoneCredStore[$k].Pass } else { '' })
    }
    if ($st.Caret) { $tb.SelectionStart = $tb.Text.Length; $tb.SelectionLength = 0 } else { $tb.SelectAll() }
    $st.Armed = $isPw
})
$script:gridPhones.Add_CellEndEdit({
    param($s, $e)
    $g = $script:gridPhones
    $script:phGrid.Armed = $false
    $row = $g.Rows[$e.RowIndex]
    $k = Get-PhoneRowKey $row
    if (-not $k) { return }
    $col = $g.Columns[$e.ColumnIndex].Name
    if ($col -eq 'phUser') {
        # User is plain text, so the cell itself is the value.
        $u = ([string]$row.Cells['phUser'].Value).Trim(); if (-not $u) { $u = 'admin' }
        $en = Get-PhoneCredEntry $k; $en.User = $u
        $row.Cells['phUser'].Value = $u
    } elseif ($col -eq 'phPass') {
        Update-PhonePassCells
    }
})
# Ctrl+V with several lines (or tabs) on the clipboard, anywhere in the grid. A
# single value pastes into the cell as normal.
$script:form.KeyPreview = $true
$script:form.Add_KeyDown({
    param($s, $e)
    if (-not ($e.Control -and $e.KeyCode -eq 'V')) { return }
    if (-not $script:gridPhones.ContainsFocus -or -not $script:gridPhones.CurrentCell) { return }
    $txt = ''
    try { $txt = [System.Windows.Forms.Clipboard]::GetText() } catch {}
    if (-not $txt -or ($txt.TrimEnd("`r", "`n") -notmatch "[`r`n`t]")) { return }
    $e.Handled = $true; $e.SuppressKeyPress = $true
    [void](Invoke-PhoneGridPaste -Text $txt)
})
$script:chkShowPw.Add_CheckedChanged({
    $script:phGrid.Armed = $false
    if ($script:gridPhones.IsCurrentCellInEditMode) { [void]$script:gridPhones.EndEdit() }
    $script:phGrid.Show = $script:chkShowPw.Checked
    Update-PhonePassCells
})

function Start-PhonePasswordFlow {
    # One button, two jobs. No phones yet: find them - no login anywhere. Phones
    # listed: log in to the ones with a password in the grid, without a rescan;
    # a phone left blank gets no login attempt at all.
    if ($script:scanActive) { return }
    if ($script:gridPhones.IsCurrentCellInEditMode) { [void]$script:gridPhones.EndEdit() }
    $phones = @($script:lastPhones | Where-Object { $_ -and $_.MAC })
    if ($phones.Count -eq 0) {
        if ([string]::IsNullOrWhiteSpace($script:txtSubnet.Text)) {
            [void][System.Windows.Forms.MessageBox]::Show('Enter the subnet (CIDR) first, so the phones can be found.', '3CX Checker', 'OK', 'Warning'); return
        }
        $script:afterScan = 'findphones'
        $script:lblStatus.Text = 'Finding the phones...'
        Start-Scan 'Lan' -NoProbe
        return
    }
    $creds = @(Get-StoredPhoneCreds -Phones $phones)
    if ($creds.Count -eq 0) { $script:lblStatus.Text = 'Type a password into at least one phone''s row first.'; return }
    $script:chkProbe.Checked = $true
    Start-Scan 'Probe' -CredObjects $creds
}

# ---------------------------------------------------------------------------
# Open a phone's web page
# ---------------------------------------------------------------------------
# In a ScreenConnect Backstage session there is no default browser, so the
# portable Pale Moon the technicians keep in C:\temp is used instead.
$script:PaleMoonPath   = 'C:\temp\Palemoon-Portable.exe'
$script:isBackstage    = $null    # worked out on first use
$script:paleMoonOkHash = ''       # the exact file the technician agreed to run

function Confirm-PaleMoon {
    # Backstage runs as SYSTEM, and on a default Windows install any signed-in
    # user can replace files in C:\temp - so a file there could be anything.
    # Signed by Pale Moon's publisher: run it. Otherwise ask, once per exact file.
    $p = $script:PaleMoonPath
    $sig = $null
    try { $sig = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop } catch {}
    if ($sig -and $sig.Status -eq 'Valid' -and [string]$sig.SignerCertificate.Subject -match 'Moonchild') { return $true }
    $h = ''
    try { $h = (Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction Stop).Hash } catch {}
    if ($h -and $h -eq $script:paleMoonOkHash) { return $true }
    $why = 'is not signed'
    if ($sig -and $sig.Status -eq 'Valid') { $why = ('is signed by ' + $sig.SignerCertificate.Subject + ', not Pale Moon''s publisher') }
    elseif ($sig -and $sig.Status -ne 'NotSigned') { $why = ('has a signature that does not check out (' + $sig.Status + ')') }
    $nl = [Environment]::NewLine
    $who = 'this session'
    if ($script:isBackstage) { $who = 'this Backstage session, which runs as SYSTEM' }
    $a = [System.Windows.Forms.MessageBox]::Show(($p + ' ' + $why + '.' + $nl + $nl + 'It would run in ' + $who + ', and on most PCs any user can replace files in C:\temp.' + $nl + $nl + 'Run it anyway?'), '3CX Checker - open the phone''s web page', 'YesNo', 'Warning')
    if ($a -ne 'Yes') { return $false }
    $script:paleMoonOkHash = $h
    return $true
}

function Start-PaleMoon {
    param([string]$Url)
    if (-not (Test-Path -LiteralPath $script:PaleMoonPath -PathType Leaf)) { return $false }
    if (-not (Confirm-PaleMoon)) { $script:lblStatus.Text = 'Not opened.'; return $true }   # declined: handled
    Start-Process -FilePath $script:PaleMoonPath -ArgumentList $Url
    $script:lblStatus.Text = ('Opened ' + $Url + ' in Pale Moon.')
    return $true
}

function Open-PhoneWebPage {
    # The phone in the given row (else the current one) in a browser. Phones use
    # self-signed certificates, so expect the browser's certificate warning.
    param($Row = $null)
    $g = $script:gridPhones
    if (-not $Row -and $g.CurrentCell) { $Row = $g.Rows[$g.CurrentCell.RowIndex] }
    $k = Get-PhoneRowKey $Row
    $ph = $null
    if ($k) { $ph = @($script:lastPhones | Where-Object { $_ -and (ConvertTo-MacKey $_.MAC) -eq $k }) | Select-Object -First 1 }
    if (-not $ph) { $script:lblStatus.Text = 'Click a phone in the Yealink grid first.'; return }
    $wu = ''; if ($ph.PSObject.Properties['WebUi']) { $wu = [string]$ph.WebUi }
    $url = Get-PhoneWebUrl -Ip ([string]$ph.IP) -WebUi $wu
    if (-not $url) { $script:lblStatus.Text = ('Not a usable address: ' + [string]$ph.IP); return }
    if ($null -eq $script:isBackstage) { $script:isBackstage = [bool](Test-BackstageSession) }
    if ($script:isBackstage) {
        if (Start-PaleMoon -Url $url) { return }
        [void][System.Windows.Forms.MessageBox]::Show(('This looks like a ScreenConnect Backstage session, which has no default browser, and ' + $script:PaleMoonPath + ' is not there.' + [Environment]::NewLine + [Environment]::NewLine + 'Put Pale Moon Portable there, or open ' + $url + ' from a normal session.'), '3CX Checker', 'OK', 'Information')
        return
    }
    try {
        Start-Process -FilePath $url -ErrorAction Stop
        $script:lblStatus.Text = ('Opened ' + $url + ' in the default browser.')
    } catch {
        # No browser registered for https here: the portable one, if it is there.
        if (Start-PaleMoon -Url $url) { return }
        [void][System.Windows.Forms.MessageBox]::Show(('No default browser could open ' + $url + ': ' + $_.Exception.Message), '3CX Checker', 'OK', 'Warning')
    }
}

$script:btnPhoneWeb.Add_Click({ Open-PhoneWebPage })
# Double-click a phone's row (any column but User / Password, which edit).
$script:gridPhones.Add_CellDoubleClick({
    param($s, $e)
    if ($e.RowIndex -lt 0 -or $e.ColumnIndex -lt 0) { return }
    if (-not $script:gridPhones.Columns[$e.ColumnIndex].ReadOnly) { return }
    Open-PhoneWebPage -Row $script:gridPhones.Rows[$e.RowIndex]
})
# Right-click a row: open its web page, or copy its IP / MAC.
$script:phMenu = New-Object System.Windows.Forms.ContextMenuStrip
$script:phMenuRow = $null
$miWeb = $script:phMenu.Items.Add('Open phone web page')
$miWeb.Font = New-Object System.Drawing.Font($miWeb.Font, [System.Drawing.FontStyle]::Bold)
$miWeb.Add_Click({ Open-PhoneWebPage -Row $script:phMenuRow })
$miIp = $script:phMenu.Items.Add('Copy IP address')
$miIp.Add_Click({ try { [System.Windows.Forms.Clipboard]::SetText([string]$script:phMenuRow.Cells['phIp'].Value) } catch {} })
$miMac = $script:phMenu.Items.Add('Copy MAC address')
$miMac.Add_Click({ try { [System.Windows.Forms.Clipboard]::SetText([string]$script:phMenuRow.Cells['phMac'].Value) } catch {} })
$script:phMenu.Add_Opening({
    param($s, $e)
    $g = $script:gridPhones
    $hit = $g.HitTest($g.PointToClient([System.Windows.Forms.Control]::MousePosition).X, $g.PointToClient([System.Windows.Forms.Control]::MousePosition).Y)
    $script:phMenuRow = $null
    if ($hit.RowIndex -ge 0) {
        $row = $g.Rows[$hit.RowIndex]
        if (Get-PhoneRowKey $row) {
            $script:phMenuRow = $row
            # Highlight the row's IP cell - a read-only cell, so no editor opens.
            try { $g.CurrentCell = $row.Cells['phIp'] } catch {}
        }
    }
    if (-not $script:phMenuRow) { $e.Cancel = $true }
})
$script:gridPhones.ContextMenuStrip = $script:phMenu

# ---------------------------------------------------------------------------
# Site name and the JSON report
# ---------------------------------------------------------------------------
function Update-SiteAuto {
    # Fills the site name from the 3CX instance - the FQDN box, else the PBX this
    # PC's SBC is paired with. Only while the box is empty or still holds the last
    # value it filled in: once the technician types, it is theirs.
    $cand = Get-SiteNameFromPbx -PbxHost (Get-FqdnBoxHost) -Exclude $script:DefaultFqdn
    if (-not $cand -and $script:localSbcPbx) { $cand = Get-SiteNameFromPbx -PbxHost $script:localSbcPbx -Exclude $script:DefaultFqdn }
    $cur = $script:txtSite.Text.Trim()
    if ($cur -and $cur -ne $script:siteAutoValue) { return }
    $script:siteAutoValue = $cand
    $script:txtSite.Text = $cand
}

function Get-ReportOutputDir {
    # "Output" next to the script (reports describe real sites, so mind where this
    # folder syncs to), else Documents\3CX-Checker\Output when that is not writable.
    if ($script:ReportDirOverride) { New-Item -ItemType Directory -Path $script:ReportDirOverride -Force | Out-Null; return $script:ReportDirOverride }
    $d = Join-Path $PSScriptRoot 'Output'
    try {
        if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force -ErrorAction Stop | Out-Null }
        $probe = Join-Path $d ('.write-test-' + [guid]::NewGuid().ToString('N'))
        [System.IO.File]::WriteAllText($probe, '')
        Remove-Item -LiteralPath $probe -Force
        return $d
    } catch {}
    $d2 = Join-Path ([Environment]::GetFolderPath('MyDocuments')) '3CX-Checker\Output'
    New-Item -ItemType Directory -Path $d2 -Force | Out-Null
    return $d2
}

function Open-InNotepad {
    param([string]$Path)
    try { Start-Process -FilePath 'notepad.exe' -ArgumentList ('"' + $Path + '"') -ErrorAction Stop } catch {}
}

function Get-CurrentReport {
    # Everything the report needs, handed over explicitly - passwords, the SSH box
    # and raw event text are never among it.
    $secPosture = $null; if ($script:secPc) { $secPosture = $script:secPc.Posture }
    $site = [ordered]@{
        name = $script:txtSite.Text.Trim(); computer = $env:COMPUTERNAME; subnet = $script:txtSubnet.Text.Trim()
        pbxFqdn = (Get-FqdnBoxHost); publicIp = $script:lastPublicIp; localSbcPbx = $script:localSbcPbx
    }
    return (New-3cxReportObject -ToolVersion $script:ToolVersion -Site $site -Options $script:lastRunOptions -Times $script:sectionTimes `
        -Cx $script:lastCx -CxSummary $script:lastCxSummary `
        -Media $script:lastMedia -MediaSummary $script:lastMediaSummary -Health $script:lastHealth -MediaMetrics $script:lastMediaMetrics `
        -Phones $script:lastPhones -SbcRows $script:lastSbc -LocalSbc $script:lastLocalSbc -Roles $script:lastRoles -Listeners $script:lastListeners `
        -SecFindings $script:lastSec -SecPosture $secPosture -SecEvents $script:secEvents -SecEventFile $script:secEventPath -Blacklist $script:secBlacklist `
        -Log $script:lastRunLog)
}

function Export-Report {
    # JSON for Generate-3cxReport.ps1: saved to Output, copied to the clipboard
    # between the BEGIN/END markers the generator looks for (they let it spot a
    # truncated paste), and opened in Notepad.
    if ($script:scanActive) { return }
    if ($script:sectionTimes.Count -eq 0) {
        [void][System.Windows.Forms.MessageBox]::Show('Nothing to report yet - run a check first.', '3CX Checker', 'OK', 'Information'); return
    }
    try {
        $json = ConvertTo-3cxReportJson (Get-CurrentReport)
        $slug = Get-ReportFileSlug -Name $script:txtSite.Text -Fallback $env:COMPUTERNAME
        $path = Join-Path (Get-ReportOutputDir) ('3CX-Report_{0}_{1}.json' -f $slug, (Get-Date -Format 'yyyyMMdd_HHmmss'))
        # UTF-8 with a BOM: Windows PowerShell 5.1 reads a BOM-less file as ANSI.
        [System.IO.File]::WriteAllText($path, $json, (New-Object System.Text.UTF8Encoding($true)))
        $clip = $false
        try {
            [System.Windows.Forms.Clipboard]::SetText(('--- BEGIN JSON OUTPUT ---' + "`r`n" + $json + "`r`n" + '--- END JSON OUTPUT ---'))
            $clip = $true
        } catch {}
        Open-InNotepad -Path $path
        $script:lblStatus.Text = ('Report saved: {0}{1}; opened in Notepad.' -f $path, $(if ($clip) { ' - copied to the clipboard' } else { ' (clipboard unavailable)' }))
        return $path
    } catch {
        [void][System.Windows.Forms.MessageBox]::Show(('The report could not be exported: ' + $_.Exception.Message), '3CX Checker', 'OK', 'Warning')
    }
}

function Start-Scan {
    param([string]$Mode,[switch]$NoProbe,$CredObjects = $null)
    if ($script:scanActive) { return }
    # A User being typed reaches the store when its edit ends.
    if ($script:gridPhones.IsCurrentCellInEditMode) { [void]$script:gridPhones.EndEdit() }
    if (-not (Confirm-SbcPbxTarget -Mode $Mode)) { return }
    $target = Get-FqdnBoxText
    $cidr   = $script:txtSubnet.Text.Trim()
    if (($Mode -eq 'Cx' -or $Mode -eq 'All' -or $Mode -eq 'Media') -and [string]::IsNullOrWhiteSpace($target)) {
        [void][System.Windows.Forms.MessageBox]::Show('Enter the site''s 3CX FQDN first (replace <test> in the box), or its URL.', '3CX Checker', 'OK', 'Warning')
        [void]$script:txtFqdn.Focus(); Select-FqdnTemplatePart
        return
    }
    if ($Mode -eq 'Probe' -and @($script:lastPhones | Where-Object { $_ -and $_.MAC }).Count -eq 0) { return }
    if (($Mode -eq 'Lan' -or $Mode -eq 'All') -and [string]::IsNullOrWhiteSpace($cidr)) {
        [void][System.Windows.Forms.MessageBox]::Show('Enter a subnet (CIDR) first.', '3CX Checker', 'OK', 'Warning'); return
    }
    if ($Mode -eq 'Lan' -or $Mode -eq 'All') {
        $sweepCheck = Get-SweepTargets -Cidr $cidr
        if ($sweepCheck.Error) {
            [void][System.Windows.Forms.MessageBox]::Show(('The Subnet box cannot be swept: ' + $sweepCheck.Error + '.'), '3CX Checker', 'OK', 'Warning'); return
        }
    }
    if (($Mode -eq 'Media' -or $Mode -eq 'All') -and [string]::IsNullOrWhiteSpace($target)) {
        [void][System.Windows.Forms.MessageBox]::Show('Enter a 3CX FQDN or URL first.', '3CX Checker', 'OK', 'Warning'); return
    }

    # Build the media options up front so the cooldown can be checked before
    # anything starts.
    $soakMinutes = 0
    switch ($script:cboSoak.SelectedIndex) { 1 { $soakMinutes = 5 } 2 { $soakMinutes = 15 } 3 { $soakMinutes = 60 } }
    $mediaOpts = [pscustomobject]@{
        Train       = [bool]$script:chkMediaTrain.Checked
        Gentle      = [bool]$script:chkMediaGentle.Checked
        Nat         = [bool]$script:chkMediaNat.Checked
        Path        = [bool]$script:chkMediaPath.Checked
        Binding     = [bool]$script:chkMediaBinding.Checked
        SoakMinutes = $soakMinutes
        PhoneCount  = [int]$script:numPhones.Value
    }
    $mediaWanted = ($mediaOpts.Train -or $mediaOpts.Nat -or $mediaOpts.Path -or $mediaOpts.Binding -or $mediaOpts.SoakMinutes -gt 0)

    if ($Mode -eq 'Media' -and -not $mediaWanted) {
        [void][System.Windows.Forms.MessageBox]::Show('Tick at least one check on the Media / Path Quality tab.', '3CX Checker', 'OK', 'Warning'); return
    }
    # Run All only pulls in the media stage if something there is ticked -
    # otherwise a 30-second scan would silently become a multi-minute one.
    if ($Mode -eq 'All' -and -not $mediaWanted) { $mediaOpts.Train = $false }

    if (($Mode -eq 'Media' -or ($Mode -eq 'All' -and $mediaWanted)) -and $mediaOpts.Train) {
        $since = ([DateTime]::UtcNow - $script:lastTrainAt).TotalSeconds
        if ($since -lt 60) {
            [void][System.Windows.Forms.MessageBox]::Show(
                ('The UDP path test sends a burst of SIP OPTIONS at the PBX. Please wait {0} more second(s) before running it again - back-to-back bursts are what trip 3CX anti-hacking.' -f [int](60 - $since)),
                '3CX Checker', 'OK', 'Information'); return
        }
        $script:lastTrainAt = [DateTime]::UtcNow
    }

    $script:scanActive           = $true
    $script:logIndex             = 0
    $script:cxRendered           = $false
    $script:phonesVersionRendered = -1
    $script:listenersRendered    = $false
    $script:rolesRendered        = $false
    $script:sbcVersionRendered   = -1
    $script:mediaVersionRendered = -1
    $script:txtLog.Clear()
    $script:progress.Value = 0
    $script:lblStatus.Text = 'Starting...'
    Set-Busy $true

    $shared = [hashtable]::Synchronized(@{})
    $shared.Log = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $shared.Progress = 0
    $shared.Status = ''
    $shared.Done = $false
    $shared.Error = $null
    $shared.Cx = $null;        $shared.CxSummary = ''; $shared.CxReady = $false; $shared.CxCert = $null; $shared.PublicIp = ''
    $shared.Phones = $null;    $shared.PhonesReady = $false; $shared.PhonesVersion = 0
    $shared.Listeners = $null; $shared.ListenersReady = $false
    $shared.Roles = $null;     $shared.RolesReady = $false
    $shared.Sbc = $null;       $shared.SbcReady = $false; $shared.SbcVersion = 0
    $shared.LocalSbc = $null
    $shared.Media = $null;     $shared.MediaReady = $false; $shared.MediaVersion = 0; $shared.MediaSummary = ''
    $shared.Cancel = $false
    $shared.Health = $null;    $shared.MediaMetrics = $null
    $script:shared = $shared
    $script:lastRunOptions = [ordered]@{
        mode = $Mode; pbxFqdn = $target; subnet = $cidr
        probePhones = [bool](($script:chkProbe.Checked -and -not $NoProbe) -or $Mode -eq 'Probe')
        readVq = [bool](($script:chkProbe.Checked -or $Mode -eq 'Probe') -and $script:chkVq.Checked -and -not $NoProbe)
        sbcScan = [bool]$script:chkSbc.Checked; saveRaw = [bool]$script:chkRaw.Checked
        media = $mediaOpts
    }

    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $rs = [runspacefactory]::CreateRunspace($iss)
    $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript($WorkerScript.ToString())
    [void]$ps.AddParameter('Shared', $shared)
    [void]$ps.AddParameter('HelpersSource', $HelpersSource)
    [void]$ps.AddParameter('Mode', $Mode)
    [void]$ps.AddParameter('Target', $target)
    [void]$ps.AddParameter('Cidr', $cidr)
    [void]$ps.AddParameter('Ports', $PortDefs)
    [void]$ps.AddParameter('Ouis', $YealinkOui)
    [void]$ps.AddParameter('ProbePhones', [bool]($script:chkProbe.Checked -and -not $NoProbe))
    [void]$ps.AddParameter('SaveRaw', [bool]$script:chkRaw.Checked)
    [void]$ps.AddParameter('FindSbc', [bool]$script:chkSbc.Checked)
    [void]$ps.AddParameter('ProbeVq', [bool](($script:chkProbe.Checked -or $Mode -eq 'Probe') -and $script:chkVq.Checked -and -not $NoProbe))
    $probeList = $null
    if ($Mode -eq 'Probe') { $probeList = @($script:lastPhones | Where-Object { $_ -and $_.MAC }) }
    [void]$ps.AddParameter('ProbeList', $probeList)
    if ($null -eq $CredObjects -and ($Mode -eq 'Lan' -or $Mode -eq 'All') -and $script:chkProbe.Checked -and -not $NoProbe) {
        $CredObjects = @(Get-StoredPhoneCreds)
    }
    [void]$ps.AddParameter('CredObjects', $CredObjects)
    [void]$ps.AddParameter('MediaOpts', $mediaOpts)
    $script:ps = $ps
    $script:rs = $rs
    $script:async = $ps.BeginInvoke()
    $script:timer.Start()
}

function Export-Results {
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($r in @($script:lastCx))        { $rows.Add([pscustomobject]@{ Section='3CX';      Item=$r.Check;        Detail1=$r.Target;   Detail2=$r.Port;  Detail3=$r.Result; Detail4=$r.Detail }) }
    foreach ($r in @($script:lastPhones))    { $rows.Add([pscustomobject]@{ Section='Yealink';  Item=$r.IP;           Detail1=$r.MAC;      Detail2=$r.Model;  Detail3=('sip=' + $r.SipServer); Detail4=('fw=' + $r.Firmware + ' reg=' + $r.Reg + ' host=' + $r.Hostname + $(if ($r.VqDetail) { ' vq=' + $r.Vq + ' | ' + $r.VqDetail } else { '' }) + $(if ($r.PSObject.Properties['ProvHost'] -and $r.ProvHost) { ' prov=' + $r.ProvHost + $(if ($r.ProvMismatch) { ' (' + $r.ProvNote + ')' } else { '' }) } else { '' })) }) }
    foreach ($r in @($script:lastListeners)) { $rows.Add([pscustomobject]@{ Section='Listener'; Item=$r.LocalAddress; Detail1=$r.LocalPort; Detail2=$r.State; Detail3=$r.OwningProcess; Detail4=$r.ProcessName }) }
    foreach ($r in @($script:lastRoles))     { $rows.Add([pscustomobject]@{ Section='Network';  Item=$r.Role;         Detail1=$r.IP;        Detail2=$r.MAC;       Detail3=$r.Vendor;   Detail4=$r.Note }) }
    foreach ($r in @($script:lastSbc))       { $rows.Add([pscustomobject]@{ Section='SBC';      Item=$r.IP;           Detail1=$r.Confidence; Detail2=('platform=' + $r.Platform + ' vendor=' + $r.Vendor + ' host=' + $r.Hostname + ' os=' + $r.Os); Detail3=('ports=' + $r.OpenPorts + ' sip=' + $r.SipType); Detail4=$r.Detail }) }
    foreach ($r in @($script:lastMedia))     { $rows.Add([pscustomobject]@{ Section='Media';    Item=$r.Group;        Detail1=$r.Check;     Detail2=$r.Result;    Detail3=$r.Status;   Detail4=$r.Detail }) }
    foreach ($r in @($script:lastSec))       { $rows.Add([pscustomobject]@{ Section='Security'; Item=$r.Area;         Detail1=$r.Severity;  Detail2=$r.Finding;   Detail3='';          Detail4=$r.Action }) }
    if ($rows.Count -eq 0) {
        [void][System.Windows.Forms.MessageBox]::Show('No results to export yet - run a check first.', '3CX Checker', 'OK', 'Information'); return
    }
    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter = 'CSV files (*.csv)|*.csv'
    $sfd.FileName = ('3CX-Check_{0}.csv' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        # Device-supplied text is neutralised so Excel cannot run it as a formula.
        $safe = foreach ($r in $rows) {
            $o = [ordered]@{}
            foreach ($p in $r.PSObject.Properties) { $o[$p.Name] = ConvertTo-CsvSafeText $p.Value }
            [pscustomobject]$o
        }
        @($safe) | Export-Csv -LiteralPath $sfd.FileName -NoTypeInformation -Encoding UTF8
        $script:lblStatus.Text = ('Exported: {0}' -f $sfd.FileName)
    }
}

function Copy-Results {
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('=== 3CX Connectivity ===')
    [void]$sb.AppendLine([string]$script:txtCxSummary.Text)
    foreach ($r in @($script:lastCx)) { [void]$sb.AppendLine(('{0}`t{1}`t{2}`t{3}`t{4}' -f $r.Check, $r.Target, $r.Port, $r.Result, $r.Detail)) }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('=== Yealink Phones ===')
    foreach ($r in @($script:lastPhones)) {
        $pv = ''
        if ($r.PSObject.Properties['ProvHost'] -and $r.ProvHost) { $pv = $r.ProvHost; if ($r.ProvMismatch) { $pv += (' (' + $r.ProvNote + ')') } }
        [void]$sb.AppendLine(('{0}`t{1}`tmodel={2}`tfw={3}`tsip={4}`treg={5}`t{6}`tvq={7}`tprov={8}' -f $r.IP, $r.MAC, $r.Model, $r.Firmware, $r.SipServer, $r.Reg, $r.Hostname, $r.Vq, $pv))
    }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('=== Local Listeners ===')
    foreach ($r in @($script:lastListeners)) { [void]$sb.AppendLine(('{0}`t{1}`t{2}`t{3}`t{4}' -f $r.LocalAddress, $r.LocalPort, $r.State, $r.OwningProcess, $r.ProcessName)) }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('=== Network (gateway / DHCP roles) ===')
    foreach ($r in @($script:lastRoles)) { [void]$sb.AppendLine(('{0}`t{1}`t{2}`t{3}' -f $r.Role, $r.IP, $r.MAC, $r.Note)) }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('=== SIP / SBC (IP, verdict, platform, OS, ports, why) ===')
    foreach ($r in @($script:lastSbc)) { [void]$sb.AppendLine(('{0}`t{1}`t{2}`t{3}`t{4}`t{5}' -f $r.IP, $r.Confidence, $r.Platform, $r.Os, $r.OpenPorts, $r.Detail)) }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('=== Media / Path Quality ===')
    [void]$sb.AppendLine([string]$script:txtMediaSummary.Text)
    foreach ($r in @($script:lastMedia)) { [void]$sb.AppendLine(('{0}`t{1}`t{2}`t{3}' -f $r.Group, $r.Check, $r.Result, $r.Detail)) }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('=== Security ===')
    foreach ($r in @($script:lastSec)) { [void]$sb.AppendLine(('{0}`t{1}`t{2}`t{3}' -f $r.Severity, $r.Area, $r.Finding, $r.Action)) }
    if ($script:txtSecReport.Text) { [void]$sb.AppendLine(''); [void]$sb.AppendLine([string]$script:txtSecReport.Text) }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('=== Log ===')
    [void]$sb.AppendLine([string]$script:txtLog.Text)
    try {
        [System.Windows.Forms.Clipboard]::SetText($sb.ToString())
        $script:lblStatus.Text = 'Results copied to clipboard.'
    } catch {
        [void][System.Windows.Forms.MessageBox]::Show('Could not access the clipboard.', '3CX Checker', 'OK', 'Warning')
    }
}

function Clear-All {
    if ($script:scanActive) { return }
    $script:gridCx.Rows.Clear()
    # The session's passwords stay: the next scan re-attaches them by MAC. They
    # are gone when the tool closes.
    if ($script:gridPhones.IsCurrentCellInEditMode) { [void]$script:gridPhones.EndEdit() }
    $script:gridPhones.Rows.Clear()
    $script:gridListeners.Rows.Clear()
    $script:gridRoles.Rows.Clear()
    $script:gridSbc.Rows.Clear()
    $script:gridMedia.Rows.Clear()
    $script:txtLog.Clear()
    $script:txtCxSummary.Clear()
    $script:txtMediaSummary.Clear()
    $script:txtSbcOut.Clear()
    $script:progress.Value = 0
    $script:lblStatus.Text = 'Cleared.'
    $script:lastCx = @(); $script:lastPhones = @(); $script:lastListeners = @(); $script:lastRoles = @(); $script:lastSbc = @(); $script:lastMedia = @()
    $script:sectionTimes = @{}; $script:lastCxSummary = ''; $script:lastMediaSummary = ''
    $script:lastHealth = $null; $script:lastMediaMetrics = $null; $script:lastLocalSbc = $null; $script:lastRunLog = @()
    Update-PhoneLoginButton
    Clear-Security
}

# ---- Timer polls the shared state and updates the UI ----
$script:timer = New-Object System.Windows.Forms.Timer
$script:timer.Interval = 200
$script:timer.Add_Tick({
    $sh = $script:shared
    if (-not $sh) { return }

    $count = $sh.Log.Count
    while ($script:logIndex -lt $count) {
        $script:txtLog.AppendText([string]$sh.Log[$script:logIndex] + [Environment]::NewLine)
        $script:logIndex++
    }

    $p = [int]$sh.Progress
    if ($p -lt 0) { $p = 0 }
    if ($p -gt 100) { $p = 100 }
    $script:progress.Value = $p
    $script:lblStatus.Text = [string]$sh.Status

    if ($sh.CxReady        -and -not $script:cxRendered)        { Render-Cx $sh;        $script:cxRendered = $true }
    if ($sh.PhonesReady    -and $sh.PhonesVersion -ne $script:phonesVersionRendered) { Render-Phones $sh; $script:phonesVersionRendered = $sh.PhonesVersion }
    if ($sh.ListenersReady -and -not $script:listenersRendered) { Render-Listeners $sh; $script:listenersRendered = $true }
    if ($sh.RolesReady     -and -not $script:rolesRendered)     { Render-Roles $sh;     $script:rolesRendered = $true }
    if ($sh.SbcReady       -and $sh.SbcVersion -ne $script:sbcVersionRendered) { Render-Sbc $sh; $script:sbcVersionRendered = $sh.SbcVersion }
    # Version-based, not one-shot: the media stage runs for 20s minimum and up to
    # an hour in soak mode, so the grid has to fill as it goes.
    if ($sh.MediaReady     -and $sh.MediaVersion -ne $script:mediaVersionRendered) { Render-Media $sh; $script:mediaVersionRendered = $sh.MediaVersion }

    if ($sh.Done) {
        $script:timer.Stop()
        if ($sh.LocalSbc -and [string]$sh.LocalSbc.TunnelAddr -and -not $script:localSbcPbx) {
            $script:localSbcPbx = [string]$sh.LocalSbc.TunnelAddr
            Update-FqdnHint
            Update-SiteAuto
        }
        if ($sh.LocalSbc) { $script:lastLocalSbc = $sh.LocalSbc }
        if ($sh.MediaReady) { $script:lastHealth = $sh.Health; $script:lastMediaMetrics = $sh.MediaMetrics }
        $script:lastRunLog = @($sh.Log | ForEach-Object { [string]$_ })
        try { $script:ps.EndInvoke($script:async) } catch {}
        try { $script:ps.Dispose() } catch {}
        try { $script:rs.Close(); $script:rs.Dispose() } catch {}
        $script:scanActive = $false
        Set-Busy $false
        $script:lblStatus.Text = if ($sh.Error) { 'Error: ' + $sh.Error } elseif ($sh.Cancel) { 'Stopped.' } else { 'Done.' }
        if ($script:afterScan -eq 'findphones') {
            $script:afterScan = ''
            if (-not $sh.Error -and -not $sh.Cancel) {
                $found = @($script:lastPhones | Where-Object { $_ -and $_.MAC })
                if ($found.Count -gt 0) {
                    # Straight to the first phone still without a password.
                    $tab.SelectedTab = $tabPhones
                    $g = $script:gridPhones
                    $target = @(@($g.Rows) | Where-Object { $k = Get-PhoneRowKey $_; $k -and -not ($script:phoneCredStore.ContainsKey($k) -and $script:phoneCredStore[$k].Pass) }) | Select-Object -First 1
                    if (-not $target -and $g.Rows.Count -gt 0) { $target = $g.Rows[0] }
                    if ($target) { [void]$g.Focus(); $g.CurrentCell = $target.Cells['phPass'] }
                    $script:lblStatus.Text = ('Found {0} phone(s). Type each phone''s web password into its row, then click "Log in".' -f $found.Count)
                }
                else { [void][System.Windows.Forms.MessageBox]::Show(('No Yealink phones were found on this subnet.' + [Environment]::NewLine + [Environment]::NewLine + 'Discovery reads this PC''s ARP table, so phones on a separate voice VLAN or another routed subnet are invisible from here. Run the tool from a PC on the phones'' VLAN or switch port.'), '3CX Checker', 'OK', 'Information') }
            }
        }
    }
})

# ---- Wire events ----
$script:btnCheckCx.Add_Click({ Start-Scan 'Cx' })
$script:btnReport.Add_Click({ [void](Export-Report) })
$script:txtFqdn.Add_TextChanged({ Update-SiteAuto })
$script:btnPhonePwds.Add_Click({ Start-PhonePasswordFlow })
$script:btnScanLan.Add_Click({ Start-Scan 'Lan' })
$script:btnRunAll.Add_Click({ Start-Scan 'All' })
$script:btnMedia.Add_Click({
    if ($script:scanActive) {
        if ($script:shared) { $script:shared.Cancel = $true }
        $script:lblStatus.Text = 'Stopping...'
        $script:btnMedia.Enabled = $false
    } else {
        Start-Scan 'Media'
    }
})
$script:btnExport.Add_Click({ Export-Results })
$script:btnVqTemplate.Add_Click({
    try {
        [System.Windows.Forms.Clipboard]::SetText((Get-VqTemplateLines))
        $script:lblStatus.Text = 'VQ template lines copied - paste into a COPIED 3CX phone template (Admin > Advanced > Templates).'
    } catch {
        [void][System.Windows.Forms.MessageBox]::Show('Could not access the clipboard.', '3CX Checker', 'OK', 'Warning')
    }
})
$script:gridSbc.Add_SelectionChanged({ Set-SbcTargetFromGrid })
$script:gridSbc.Add_CellClick({ Set-SbcTargetFromGrid -Force })
$script:txtSbcTarget.Add_TextChanged({ Sync-SbcTarget })
$script:cboSbcCmd.Add_SelectedIndexChanged({ Show-SbcCommandNote })
$script:txtFqdn.Add_Leave({ Sync-SbcCommands; Show-SbcCommandNote })
$script:txtFqdn.Add_TextChanged({ Update-FqdnHint })
# First click or Tab into the box while it holds the template: "<test>" is
# selected, so typing the site name replaces just that part. Deferred, because a
# mouse click places the caret after Enter has run.
$script:txtFqdn.Add_Enter({
    if ($script:txtFqdn.Text -match '[<>]') { [void]$script:txtFqdn.BeginInvoke([Action]{ Select-FqdnTemplatePart }) }
})
$script:txtFqdn.Add_MouseUp({
    if ($script:txtFqdn.Text -match '[<>]' -and $script:txtFqdn.SelectionLength -eq 0) { Select-FqdnTemplatePart }
})
$script:lnkUseSbcPbx.Add_LinkClicked({
    if (-not $script:localSbcPbx) { return }
    $script:txtFqdn.Text = $script:localSbcPbx
    Sync-SbcCommands; Show-SbcCommandNote
    $script:lblStatus.Text = ('Testing ' + $script:localSbcPbx + ' - the PBX this PC''s SBC is paired with.')
})
$script:btnSshTerm.Add_Click({
    if (-not $script:sbcTargetIp) {
        [void][System.Windows.Forms.MessageBox]::Show('Click a host in the grid, or type its IP address or name in the Target box.', '3CX Checker', 'OK', 'Information'); return
    }
    $u = $script:txtSshUser.Text.Trim()
    if (-not $u) { [void][System.Windows.Forms.MessageBox]::Show('Enter the SSH user first.', '3CX Checker', 'OK', 'Warning'); return }
    if (-not (Test-SshUserName $u)) {
        [void][System.Windows.Forms.MessageBox]::Show('The SSH user may only contain letters, digits, dot, underscore and hyphen, and must not start with a hyphen.', '3CX Checker', 'OK', 'Warning'); return
    }
    try {
        $launched = Start-SshTerminal -ComputerName $script:sbcTargetIp -User $u -Clients $script:sshClients
        $script:lblStatus.Text = ('Opened ' + $launched)
    } catch {
        [void][System.Windows.Forms.MessageBox]::Show($_.Exception.Message, '3CX Checker', 'OK', 'Warning')
    }
})
$script:btnSbcCopy.Add_Click({
    $c = Get-SelectedSbcCommand
    if (-not $c) { return }
    try {
        [System.Windows.Forms.Clipboard]::SetText([string]$c.Text)
        $script:lblStatus.Text = ('Copied: ' + $c.Title)
    } catch {
        [void][System.Windows.Forms.MessageBox]::Show('Could not access the clipboard.', '3CX Checker', 'OK', 'Warning')
    }
})
$script:btnSbcRun.Add_Click({
    $c = Get-SelectedSbcCommand
    if ($c) { Invoke-SbcCommandUi -Cmd $c }
})
$script:btnCopy.Add_Click({ Copy-Results })
$script:btnClear.Add_Click({ Clear-All })
$script:btnSecPc.Add_Click({ Start-SecPcCheck })
$script:btnSecEvents.Add_Click({ Start-SecEventImport })
$script:btnSecBlacklist.Add_Click({ Start-SecBlacklist })
$script:btnSecClear.Add_Click({ Clear-Security })

$script:form.Add_FormClosing({
    try { $script:timer.Stop() } catch {}
    try { if ($script:ps) { $script:ps.Dispose() } } catch {}
    try { if ($script:rs) { $script:rs.Close(); $script:rs.Dispose() } } catch {}
})

# ---- Seed the SBC and Security tabs ----
Update-SecurityView
Sync-SbcCommands
Show-SbcCommandNote
Sync-SshState
Update-FqdnHint

# ---- Is this PC itself a 3CX SBC? ----
# Found on a real site: the tool ran on the SBC box itself, the FQDN box still held
# the default, and every 3CX result was for the wrong PBX. Cheap to check here -
# a service lookup and one local file - and it never changes the box for you.
try {
    if (Get-Service -Name '3CXSBC' -ErrorAction SilentlyContinue) {
        $sbcCfgPath = (Get-LocalSbcPath).Config
        $sbcPbx = ''
        if (Test-Path -LiteralPath $sbcCfgPath) {
            $sbcCfg = ConvertFrom-SbcConfig -Text (Get-Content -LiteralPath $sbcCfgPath -Raw -ErrorAction Stop)
            if ($sbcCfg.ContainsKey('TunnelAddr')) { $sbcPbx = $sbcCfg['TunnelAddr'] }
        }
        $script:localSbcPbx = $sbcPbx
        Update-FqdnHint
        if ($sbcPbx -and -not (Get-FqdnBoxHost)) {
            $script:lblStatus.Text = ('This PC runs a 3CX SBC paired with {0}. Click "Use {0}" to test it, or type the FQDN.' -f $sbcPbx)
        } elseif ($sbcPbx -and $sbcPbx.ToLower() -ne (Get-FqdnBoxHost).ToLower()) {
            $script:lblStatus.Text = ('This PC runs a 3CX SBC paired with {0} - the FQDN box says {1}. Click "Use {0}" to test this site''s PBX.' -f $sbcPbx, (Get-FqdnBoxText))
        } elseif ($sbcPbx) {
            $script:lblStatus.Text = ('This PC runs a 3CX SBC paired with {0}.' -f $sbcPbx)
        } else {
            $script:lblStatus.Text = 'This PC runs a 3CX SBC (its config needs an elevated run to read).'
        }
    }
} catch {}

# ---- Site name from the 3CX instance, if known yet ----
try { Update-SiteAuto } catch {}

# ---- Auto-fill the subnet box ----
# The real prefix of the adapter this PC routes through. Never a guessed
# 192.168.1.0/24 - that used to sweep somebody else's numbering without a word.
try {
    $subnetInfo = Get-LocalSubnetInfo
    $script:txtSubnet.Text = $subnetInfo.Cidr
    if ($script:lblStatus.Text -eq 'Ready.') {
        if (-not $subnetInfo.Cidr) {
            $script:lblStatus.Text = 'Could not work out this PC''s subnet - type it into the Subnet box before scanning the LAN.'
        } elseif (@($subnetInfo.Others).Count -gt 0) {
            $script:lblStatus.Text = ('Subnet taken from {0}. This PC is also on {1} - change the Subnet box if the phones are there.' -f $subnetInfo.Interface, (@($subnetInfo.Others) -join ', '))
        }
    }
} catch { $script:txtSubnet.Text = '' }

# ---- Headless self-test (Tests\Run-Tests.ps1 sets this; never set in normal use) ----
# Builds the real form, lays out every tab, checks each control sits inside its
# parent, saves a PNG of the window, then exits instead of waiting for a user.
# Exit code = hard errors (the form failing to build or render). A control that
# overflows its parent is printed as a warning - a clipped label is cosmetic,
# but it is still worth seeing.
if ($env:THREECX_CHECKER_SELFTEST) {
    $selfErr  = [System.Collections.Generic.List[string]]::new()
    $selfWarn = [System.Collections.Generic.List[string]]::new()
    try {
        $script:form.Show()
        1..20 | ForEach-Object { [System.Windows.Forms.Application]::DoEvents(); Start-Sleep -Milliseconds 40 }
        $keepTab = $tab.SelectedTab
        $walk = {
            param($parent, $where)
            foreach ($ctl in @($parent.Controls)) {
                if (-not $ctl.Visible) { continue }
                if ($ctl.Right -gt ($parent.ClientSize.Width + 2) -or $ctl.Bottom -gt ($parent.ClientSize.Height + 2)) {
                    $txt = ([string]$ctl.Text -replace '\s+', ' ')
                    if ($txt.Length -gt 40) { $txt = $txt.Substring(0, 40) + '...' }
                    [void]$selfWarn.Add(('{0}: {1} "{2}" ends at {3},{4} inside a {5}x{6} parent' -f $where, $ctl.GetType().Name, $txt, $ctl.Right, $ctl.Bottom, $parent.ClientSize.Width, $parent.ClientSize.Height))
                }
                if ($ctl.Controls.Count -gt 0 -and $ctl -isnot [System.Windows.Forms.DataGridView]) { & $walk $ctl $where }
            }
        }
        foreach ($pg in @($tab.TabPages)) {
            $tab.SelectedTab = $pg
            $pg.PerformLayout()
            1..3 | ForEach-Object { [System.Windows.Forms.Application]::DoEvents() }
            & $walk $pg $pg.Text
        }
        $tab.SelectedTab = $keepTab
        1..5 | ForEach-Object { [System.Windows.Forms.Application]::DoEvents() }
        $bmp = New-Object System.Drawing.Bitmap($script:form.Width, $script:form.Height)
        $script:form.DrawToBitmap($bmp, (New-Object System.Drawing.Rectangle(0, 0, $script:form.Width, $script:form.Height)))
        $bmp.Save($env:THREECX_CHECKER_SELFTEST, [System.Drawing.Imaging.ImageFormat]::Png)
        $bmp.Dispose()
    } catch { [void]$selfErr.Add(('self-test failed: ' + $_.Exception.Message)) }

    # The Yealink grid's passwords: masked, editable only where they should be,
    # held per MAC, and kept across Clear. Fake phones (TEST-NET addresses), after
    # the screenshot so they never appear in it.
    try {
        $gf = { param($m) [void]$selfErr.Add('phones grid: ' + $m) }
        $g = $script:gridPhones
        $script:phoneCredStore['805EC0112233'] = @{ User = 'admin'; Pass = 'Secr3t!' }
        $fake = @(
            [pscustomobject]@{ IP = '192.0.2.110'; MAC = '80-5E-C0-11-22-33'; Model = 'T57W'; Firmware = '96.86.0.70'; SipServer = 'site.3cx.us'; Reg = 'Registered (2)'; Hostname = 'SIP-T57W'; Vq = 'ready - collector route viable'; VqDetail = ''; ProvHost = 'site.3cx.us'; ProvMismatch = $false; ProvNote = '' }
            [pscustomobject]@{ IP = '192.0.2.111'; MAC = '80-5E-C0-44-55-66'; Model = 'T46U'; Firmware = '108.86.0.45'; SipServer = ''; Reg = 'web login LOCKED by the phone after failed logins - try again in about 6 min'; Hostname = ''; Vq = ''; VqDetail = '' }
        )
        Render-Phones ([pscustomobject]@{ Phones = $fake })
        # The Yealink tab as a technician sees it, saved beside the main screenshot.
        # Short columns must show their whole value - IP and MAC were cut off when
        # eleven columns shared the width by weight.
        $tab.SelectedTab = $tabPhones
        1..5 | ForEach-Object { [System.Windows.Forms.Application]::DoEvents() }
        foreach ($cn in @('phIp', 'phMac', 'phModel', 'phFw')) {
            foreach ($row in @($g.Rows)) {
                $v = [string]$row.Cells[$cn].Value
                $need = [System.Windows.Forms.TextRenderer]::MeasureText($v, $g.Font).Width + 6
                if ($v -and $need -gt $g.Columns[$cn].Width) { & $gf ('{0} "{1}" needs {2} px, column is {3}' -f $cn, $v, $need, $g.Columns[$cn].Width) }
            }
        }
        if (-not $g.Columns['phIp'].Frozen) { & $gf 'IP column is not frozen' }
        $pbmp = New-Object System.Drawing.Bitmap($script:form.Width, $script:form.Height)
        $script:form.DrawToBitmap($pbmp, (New-Object System.Drawing.Rectangle(0, 0, $script:form.Width, $script:form.Height)))
        $pbmp.Save(($env:THREECX_CHECKER_SELFTEST -replace '\.png$', '-phones.png'), [System.Drawing.Imaging.ImageFormat]::Png)
        $pbmp.Dispose()
        $tab.SelectedTab = $keepTab
        if (-not $script:chkSbc.Checked) { [void]$selfErr.Add('SBC scan is not ticked by default') }
        # The FQDN box opens with the template, which is never tested as a name.
        if ($script:txtFqdn.Text -ne $script:FqdnTemplate) { [void]$selfErr.Add('FQDN box: does not open with the template') }
        if (Get-FqdnBoxText) { [void]$selfErr.Add('FQDN box: the template is read as a name to test') }
        if ($g.Rows.Count -ne 2) { & $gf ('expected 2 rows, got ' + $g.Rows.Count) }
        if ([string]$g.Rows[0].Cells['phPass'].Value -ne '*******') { & $gf ('stored password not shown as its mask: "' + $g.Rows[0].Cells['phPass'].Value + '"') }
        if ([string]$g.Rows[1].Cells['phPass'].Value -ne '') { & $gf 'a phone with no password shows one' }
        if ([string]$g.Rows[1].Cells['phUser'].Value -ne 'admin') { & $gf 'User does not default to admin' }
        if ($g.ReadOnly -or $g.Columns['phUser'].ReadOnly -or $g.Columns['phPass'].ReadOnly) { & $gf 'User / Password are not editable' }
        $rw = @(@($g.Columns) | Where-Object { $_.Name -ne 'phUser' -and $_.Name -ne 'phPass' -and -not $_.ReadOnly } | ForEach-Object { $_.Name })
        if ($rw.Count -gt 0) { & $gf ('editable column(s) that should be read-only: ' + ($rw -join ', ')) }
        if ($script:btnPhonePwds.Text -ne 'Log in to 1 phone(s)') { & $gf ('button says "' + $script:btnPhonePwds.Text + '"') }
        # The worker re-publishes the same phones per phone read: rows update in place.
        $fake[1].Reg = 'Registered (2)'
        Render-Phones ([pscustomobject]@{ Phones = $fake })
        if ([string]$g.Rows[1].Cells['phReg'].Value -ne 'Registered (2)') { & $gf 'in-place update lost the new Reg value' }
        # A column of two passwords pasted from the first Password cell.
        $g.CurrentCell = $g.Rows[0].Cells['phPass']
        $filled = Invoke-PhoneGridPaste -Text ("pw-one`r`npw-two`r`n")
        if ($filled -ne 2 -or $script:phoneCredStore['805EC0445566'].Pass -ne 'pw-two') { & $gf 'pasted column did not fill down by MAC' }
        if ([string]$g.Rows[0].Cells['phPass'].Value -ne '******') { & $gf 'pasted password shown in clear' }
        if ($script:btnPhonePwds.Text -ne 'Log in to 2 phone(s)') { & $gf ('after paste the button says "' + $script:btnPhonePwds.Text + '"') }
        $script:chkShowPw.Checked = $true
        if ([string]$g.Rows[0].Cells['phPass'].Value -ne 'pw-one') { & $gf 'Show passwords did not reveal the value' }
        $script:chkShowPw.Checked = $false
        if ([string]$g.Rows[0].Cells['phPass'].Value -ne '******') { & $gf 'unticking Show passwords did not re-mask' }
        $cr = @(Get-StoredPhoneCreds -Phones @($fake[1]))
        if ($cr.Count -ne 1 -or $cr[0].Id -ne '805EC0445566' -or $cr[0].Pass -ne 'pw-two') { & $gf 'credentials not tagged by MAC for only the phones asked for' }
        Clear-All
        if ($script:btnPhonePwds.Text -ne 'Find phones') { & $gf ('after Clear the button says "' + $script:btnPhonePwds.Text + '"') }
        if (@(Get-StoredPhoneCreds).Count -ne 2) { & $gf 'Clear dropped the session''s passwords' }
    } catch { [void]$selfErr.Add(('phones grid self-test failed: ' + $_.Exception.Message)) }
    try { $script:form.Close() } catch {}
    foreach ($w in $selfWarn) { Write-Output ('WARN ' + $w) }
    foreach ($e in $selfErr)  { Write-Output ('FAIL ' + $e) }
    Write-Output ('SELFTEST tabs={0} warnings={1} errors={2}' -f @($tab.TabPages).Count, $selfWarn.Count, $selfErr.Count)
    exit $selfErr.Count
}

[void]$script:form.ShowDialog()
$script:form.Dispose()
