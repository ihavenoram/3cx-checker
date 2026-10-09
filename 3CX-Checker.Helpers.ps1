<#
    3CX Desk-Phone Connectivity Checker - worker helpers
    ----------------------------------------------------
    Loaded as TEXT by 3CX-Checker.ps1 (Get-Content -Raw) and dot-sourced into
    BOTH the UI thread and the background runspace from that single definition.

    Rules for anything added here:
      * Windows PowerShell 5.1 only. No PS7 syntax (no ternary, no ?., no ??,
        no -Parallel, no -SkipCertificateCheck) and no [System.Buffers.*]
        (BinaryPrimitives does not exist in .NET Framework 4.x).
      * Function definitions ONLY - nothing may execute at load time, because
        this file is dot-sourced onto the UI thread during form construction.
      * The runspace does not inherit script variables, so helpers must not
        reference $PortDefs, $YealinkOui or any other script-scope state.
        Pass it in, or return it from a function.
#>
function Test-TcpPort {
    param([string]$ComputerName,[int]$Port,[int]$TimeoutMs = 1500)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $client = [System.Net.Sockets.TcpClient]::new()
    $open = $false
    try {
        $iar = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            try { $client.EndConnect($iar); $open = $client.Connected } catch { $open = $false }
        }
    } catch { $open = $false } finally { try { $client.Close() } catch {} }
    $sw.Stop()
    [pscustomobject]@{ Port = $Port; Open = $open; LatencyMs = [int]$sw.ElapsedMilliseconds }
}

function Get-TlsCertInfo {
    # Reads the PBX certificate AND what Windows makes of it.
    #
    # The validation callback still accepts everything - a broken certificate is
    # exactly what a diagnostic has to be able to look at - but it now records the
    # verdict instead of discarding it. Before, a hostname mismatch, a self-signed
    # certificate or a missing intermediate all showed as a green "cert N days".
    #
    # Missing intermediates get their own check. Windows (like a browser) quietly
    # fetches a missing intermediate itself, so the chain still builds and the
    # policy errors say None - but a Yealink phone does NOT fetch it, and TLS
    # provisioning fails. So the intermediates in the chain Windows built are
    # compared with the certificates the server actually sent, which SslStream
    # hands the callback in the chain's ExtraStore.
    param([string]$ComputerName,[int]$Port,[int]$TimeoutMs = 4000)
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $iar = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return $null }
        $client.EndConnect($iar)
        # Filled INSIDE the callback: the chain object is reset once it returns.
        $tls = @{ Errors = 'None'; Status = @(); Built = @(); Sent = @() }
        $cb = [System.Net.Security.RemoteCertificateValidationCallback]({
            param($s, $c, $h, $e)
            $tls.Errors = [string]$e
            if ($h) {
                $tls.Status = @($h.ChainStatus | ForEach-Object { [string]$_.Status })
                $tls.Built  = @($h.ChainElements | ForEach-Object { [pscustomobject]@{ Thumbprint = $_.Certificate.Thumbprint; Subject = $_.Certificate.Subject; Issuer = $_.Certificate.Issuer } })
                $tls.Sent   = @($h.ChainPolicy.ExtraStore | ForEach-Object { $_.Thumbprint })
            }
            $true
        }.GetNewClosure())
        $ssl = [System.Net.Security.SslStream]::new($client.GetStream(), $false, $cb)
        try {
            $ssl.AuthenticateAsClient($ComputerName)
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)
            $days = [int][math]::Floor(($cert.NotAfter - (Get-Date)).TotalDays)

            $cn = { param($subject) ([string]$subject -replace '^.*?CN=([^,]+).*$', '$1') }
            $statuses = @($tls.Status | Where-Object { $_ -and $_ -ne 'NoError' -and $_ -ne 'RevocationStatusUnknown' -and $_ -ne 'OfflineRevocation' })
            # Intermediates: every built element except the leaf and a self-signed root.
            $inter = @($tls.Built | Select-Object -Skip 1 | Where-Object { $_.Subject -ne $_.Issuer })
            $missing = @()
            if (@($tls.Sent).Count -gt 0) { $missing = @($inter | Where-Object { @($tls.Sent) -notcontains $_.Thumbprint }) }

            $problems = [System.Collections.Generic.List[string]]::new()
            if ($tls.Errors -match 'RemoteCertificateNameMismatch') {
                $issued = $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::DnsName, $false)
                [void]$problems.Add(('issued for {0}, not {1}' -f $issued, $ComputerName))
            }
            if ($statuses -contains 'NotTimeValid') { [void]$problems.Add('expired or not yet valid') }
            if ($statuses -contains 'UntrustedRoot') { [void]$problems.Add('does not chain to a trusted root (self-signed or a private CA)') }
            elseif ($statuses -contains 'PartialChain') { [void]$problems.Add('the chain is incomplete - an intermediate certificate is missing') }
            elseif (@($missing).Count -gt 0) {
                [void]$problems.Add(('the server does not send part of its chain ({0}) - Windows and browsers fetch missing certificates themselves, Yealink phones do not' -f ((@($missing) | ForEach-Object { & $cn $_.Subject }) -join ', ')))
            }
            $other = @($statuses | Where-Object { @('NotTimeValid', 'UntrustedRoot', 'PartialChain') -notcontains $_ })
            if (@($other).Count -gt 0) { [void]$problems.Add(('chain status: ' + ($other -join ', '))) }
            if ($tls.Errors -match 'RemoteCertificateChainErrors' -and $problems.Count -eq 0) { [void]$problems.Add('Windows rejected the certificate chain') }

            [pscustomobject]@{
                Subject              = $cert.Subject
                Issuer               = $cert.Issuer
                NotBefore            = $cert.NotBefore
                NotAfter             = $cert.NotAfter
                DaysToExpiry         = $days
                Thumbprint           = $cert.Thumbprint
                PolicyErrors         = $tls.Errors
                ChainStatus          = ($statuses -join ', ')
                SentCount            = @($tls.Sent).Count
                MissingIntermediates = @($missing | ForEach-Object { & $cn $_.Subject })
                Problem              = ($problems -join '; ')
                Trusted              = ($problems.Count -eq 0)
            }
        } finally { $ssl.Dispose() }
    } catch { return $null } finally { try { $client.Close() } catch {} }
}

function Invoke-HttpsHead {
    param([string]$Url,[int]$TimeoutMs = 6000)
    try {
        $req = [System.Net.HttpWebRequest]::Create($Url)
        $req.Method = 'HEAD'
        $req.Timeout = $TimeoutMs
        $req.AllowAutoRedirect = $false
        $req.UserAgent = '3CX-Checker'
        try {
            $resp = $req.GetResponse()
            $code = [int]$resp.StatusCode
            $desc = $resp.StatusDescription
            $srv  = $resp.Headers['Server']
            $resp.Close()
            [pscustomobject]@{ Ok = $true; StatusCode = $code; Status = ('{0} {1}' -f $code,$desc); Server = $srv }
        } catch [System.Net.WebException] {
            $r = $_.Exception.Response
            if ($r) {
                $code = [int]$r.StatusCode
                [pscustomobject]@{ Ok = $true; StatusCode = $code; Status = ('{0} {1}' -f $code, $r.StatusDescription); Server = $r.Headers['Server'] }
            } else {
                [pscustomobject]@{ Ok = $false; StatusCode = 0; Status = $_.Exception.Message; Server = '' }
            }
        }
    } catch {
        [pscustomobject]@{ Ok = $false; StatusCode = 0; Status = $_.Exception.Message; Server = '' }
    }
}

function Resolve-3cxTarget {
    param([string]$InputText)
    $t = $InputText.Trim()
    $t = $t -replace '^\s*https?://',''
    $t = $t -replace '/.*$',''
    $t = $t -replace ':\d+$',''
    $ip = ''
    $ok = $false
    try {
        $addrs = [System.Net.Dns]::GetHostAddresses($t) | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork }
        if ($addrs -and @($addrs).Count -gt 0) {
            $ip = (@($addrs) | ForEach-Object { $_.IPAddressToString }) -join ', '
            $ok = $true
        }
    } catch { $ok = $false }
    [pscustomobject]@{ Fqdn = $t; Ip = $ip; ResolveOk = $ok }
}

function ConvertTo-IPv4Number {
    # Dotted quad -> [long], or $null if it is not a valid IPv4 address.
    param([string]$Ip)
    $p = ([string]$Ip).Trim().Split('.')
    if (@($p).Count -ne 4) { return $null }
    [long]$n = 0
    foreach ($o in $p) {
        if ($o -notmatch '^\d{1,3}$') { return $null }
        $v = [int]$o
        if ($v -gt 255) { return $null }
        $n = ($n * 256) + $v
    }
    return $n
}

function ConvertFrom-IPv4Number {
    param([long]$N)
    return ('{0}.{1}.{2}.{3}' -f (($N -shr 24) -band 255), (($N -shr 16) -band 255), (($N -shr 8) -band 255), ($N -band 255))
}

function Get-IPv4Mask {
    param([int]$Prefix)
    if ($Prefix -le 0) { return [long]0 }
    return ([long](4294967295 -shl (32 - $Prefix)) -band 4294967295)
}

function ConvertTo-NetworkCidr {
    # 192.168.16.77 + 22 -> "192.168.16.0/22". Empty string if either is invalid.
    param([string]$Ip,[int]$Prefix)
    $n = ConvertTo-IPv4Number $Ip
    if ($null -eq $n -or $Prefix -lt 0 -or $Prefix -gt 32) { return '' }
    return ('{0}/{1}' -f (ConvertFrom-IPv4Number ($n -band (Get-IPv4Mask $Prefix))), $Prefix)
}

function Get-LocalIPv4Numbers {
    $o = [System.Collections.Generic.List[long]]::new()
    try {
        foreach ($a in @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop)) {
            $v = ConvertTo-IPv4Number $a.IPAddress
            if ($null -ne $v) { [void]$o.Add($v) }
        }
    } catch {}
    return @($o.ToArray())
}

function Get-LocalSubnetInfo {
    # The network this PC reaches the internet through - the adapter whose default
    # route has the lowest metric - with its REAL prefix length. Before, this took
    # the first adapter that happened to have a gateway and always called it a
    # /24, so on a /22 office LAN most of the phones were never swept.
    #
    # Others lists the other networks that also have a default route (Wi-Fi beside
    # wired, a VPN) so the UI can say which one it picked. An empty Cidr means
    # nothing usable was found; the caller must say so rather than guess - the old
    # fallback quietly swept 192.168.1.0/24, which is usually somebody else's LAN.
    $out = [pscustomobject]@{ Cidr = ''; Interface = ''; Others = @() }
    $cands = [System.Collections.Generic.List[object]]::new()
    $usable = { param($a) $a -and $a.IPAddress -notlike '169.254.*' -and $a.IPAddress -notlike '127.*' -and [int]$a.PrefixLength -lt 31 }
    try {
        foreach ($rt in @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction Stop)) {
            $a = @(Get-NetIPAddress -InterfaceIndex $rt.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { & $usable $_ }) | Select-Object -First 1
            if (-not $a) { continue }
            $c = ConvertTo-NetworkCidr -Ip $a.IPAddress -Prefix ([int]$a.PrefixLength)
            if ($c) { [void]$cands.Add([pscustomobject]@{ Cidr = $c; Interface = [string]$rt.InterfaceAlias; Metric = ([int]$rt.RouteMetric + [int]$rt.InterfaceMetric) }) }
        }
    } catch {}
    if ($cands.Count -eq 0) {
        # No default route at all (offline, or an isolated voice VLAN): any real
        # address, skipping Hyper-V's internal switch.
        try {
            $a = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { (& $usable $_) -and $_.InterfaceAlias -notlike 'vEthernet*' }) | Select-Object -First 1
            if ($a) {
                $c = ConvertTo-NetworkCidr -Ip $a.IPAddress -Prefix ([int]$a.PrefixLength)
                if ($c) { [void]$cands.Add([pscustomobject]@{ Cidr = $c; Interface = [string]$a.InterfaceAlias; Metric = [int]::MaxValue }) }
            }
        } catch {}
    }
    if ($cands.Count -eq 0) { return $out }
    $sorted = @($cands | Sort-Object Metric)
    $out.Cidr      = $sorted[0].Cidr
    $out.Interface = $sorted[0].Interface
    $out.Others    = @($sorted | Select-Object -Skip 1 | Where-Object { $_.Cidr -ne $out.Cidr } | ForEach-Object { ('{0} ({1})' -f $_.Cidr, $_.Interface) })
    return $out
}

function Get-LocalSubnet {
    return (Get-LocalSubnetInfo).Cidr
}

function Get-SweepTargets {
    # The host addresses a sweep of $Cidr should ping, honouring the prefix. The
    # old sweep read only the first three octets, so "10.0.0.0/22" silently swept
    # 10.0.0.1-254 and three quarters of the LAN was never looked at.
    #
    # Capped at /$MaxPrefix: a /16 is 65,534 pings and an ARP table nobody should
    # wade through. A larger network narrows to the /$MaxPrefix block containing
    # this PC, and Note says so - a partial sweep must never pass for a whole one.
    param([string]$Cidr,[int]$MaxPrefix = 22)
    $out = [pscustomobject]@{ Hosts = @(); Effective = ''; Note = ''; Error = '' }
    $t = ([string]$Cidr).Trim()
    if (-not $t) { $out.Error = 'no subnet given'; return $out }
    $m = [regex]::Match($t, '^(\d{1,3}(?:\.\d{1,3}){3})(?:\s*/\s*(\d{1,2}))?$')
    if (-not $m.Success) { $out.Error = ('"{0}" is not an IPv4 subnet such as 192.168.1.0/24' -f $t); return $out }
    $n = ConvertTo-IPv4Number $m.Groups[1].Value
    if ($null -eq $n) { $out.Error = ('"{0}" is not a valid IPv4 address' -f $m.Groups[1].Value); return $out }
    $prefix = 24
    if ($m.Groups[2].Success) { $prefix = [int]$m.Groups[2].Value }
    if ($prefix -lt 8 -or $prefix -gt 32) { $out.Error = ('/{0} is not a usable prefix - use /8 to /32' -f $prefix); return $out }

    $mask = Get-IPv4Mask $prefix
    $net  = $n -band $mask
    if ($prefix -lt $MaxPrefix) {
        $sub = Get-IPv4Mask $MaxPrefix
        $anchor = $null
        foreach ($a in @(Get-LocalIPv4Numbers)) { if (($a -band $mask) -eq $net) { $anchor = $a; break } }
        $narrow = $net
        $where  = ''
        if ($null -ne $anchor) { $narrow = $anchor -band $sub; $where = ', the block this PC is in' }
        $out.Note = ('{0}/{1} is larger than the /{2} sweep limit, so only {3}/{2} was swept{4}. Phones elsewhere in that network are not found - enter a narrower subnet to sweep another part of it.' -f (ConvertFrom-IPv4Number $net), $prefix, $MaxPrefix, (ConvertFrom-IPv4Number $narrow), $where)
        $net = $narrow; $prefix = $MaxPrefix; $mask = $sub
    }
    $bcast = $net -bor ((-bnot $mask) -band 4294967295)
    if ($prefix -ge 31) { $first = $net; $last = $bcast } else { $first = $net + 1; $last = $bcast - 1 }
    $hosts = [System.Collections.Generic.List[string]]::new()
    for ($v = [long]$first; $v -le $last; $v++) { [void]$hosts.Add((ConvertFrom-IPv4Number $v)) }
    $out.Hosts     = $hosts.ToArray()
    $out.Effective = ('{0}/{1}' -f (ConvertFrom-IPv4Number $net), $prefix)
    return $out
}

function Invoke-PingSweep {
    # Pings every host so the ARP cache fills. Takes -Hosts from Get-SweepTargets;
    # -Cidr still works for a caller holding only the box text. At most 256 pings
    # are in flight at once, so a /22 does not open a thousand sockets together.
    param([string]$Cidr,[string[]]$Hosts,[int]$TimeoutMs = 400)
    if (-not $Hosts) {
        if (-not $Cidr) { return }
        $Hosts = @((Get-SweepTargets -Cidr $Cidr).Hosts)
    }
    $list = @($Hosts)
    for ($i = 0; $i -lt $list.Count; $i += 256) {
        $chunk = @($list[$i..([Math]::Min($i + 255, $list.Count - 1))])
        $tasks = [System.Collections.Generic.List[object]]::new()
        $pings = [System.Collections.Generic.List[object]]::new()
        foreach ($h in $chunk) {
            try {
                $p = [System.Net.NetworkInformation.Ping]::new()
                $pings.Add($p)
                $tasks.Add($p.SendPingAsync($h, $TimeoutMs))
            } catch {}
        }
        try { [void][System.Threading.Tasks.Task]::WaitAll($tasks.ToArray(), 10000) } catch {}
        foreach ($p in $pings) { try { $p.Dispose() } catch {} }
    }
}

function Get-YealinkOui {
    # Yealink MAC prefixes: 6 hex chars, uppercase, no separators.
    # Single source of truth - 3CX-Checker.ps1 assigns $YealinkOui from this
    # rather than carrying its own copy, so the two cannot drift apart.
    return @('249AD8','44DBD2','805E0C','805EC0','C4FC22','EC1DA9','001565','644F56','3497D7','B061A9','F01653')
}

function Get-RaspberryPiOui {
    # Raspberry Pi Foundation / Raspberry Pi (Trading) Ltd - all eight IEEE MA-L
    # (24-bit) assignments, verified against standards-oui.ieee.org.
    #
    # A wrong prefix here fails SILENTLY - it simply never matches, so the Pi
    # quietly stops being identified and nothing says why. That is why these were
    # checked rather than assumed: the reference tool next door ships 'ab-cd-ef'
    # in its Ubiquiti list, which was never a real IEEE assignment.
    return @(
        'B827EB',   # Raspberry Pi Foundation    (Pi 1/2/3, Zero W)
        'DCA632',   # Raspberry Pi Trading Ltd   (Pi 4 era)
        'E45F01',   # Raspberry Pi Trading Ltd
        '28CDC1',   # Raspberry Pi Trading Ltd
        'D83ADD',   # Raspberry Pi Trading Ltd
        '2CCF67',   # Raspberry Pi (Trading) Ltd (Pi 5 era)
        '88A29E',   # Raspberry Pi (Trading) Ltd
        '98FE54'    # Raspberry Pi (Trading) Ltd
    )
}

function Get-RaspberryPiLongPrefix {
    # Raspberry Pi also holds two IEEE blocks LONGER than 24 bits, matched at
    # full length against the normalised 12-hex MAC.
    #
    # Truncating either to six characters would be actively wrong rather than
    # merely imprecise: 'F040AF' is registered to the IEEE Registration Authority
    # and shared with fifteen unrelated companies, and '8C1F64' is shared with
    # some 2,900 MA-S holders. Six-char matching on those would report a good
    # part of a datacentre as Raspberry Pis.
    return @(
        'F040AF9',    # MA-M  (28-bit): Pi owns only F0:40:AF:9x
        '8C1F6434A'   # MA-S  (36-bit)
    )
}

function Get-MacVendor {
    # Coarse vendor from a MAC prefix. Returns '' when unrecognised - an empty
    # string rather than 'Unknown', so a caller can test it as falsy.
    param([string]$MacNorm)
    if (-not $MacNorm -or $MacNorm.Length -lt 6) { return '' }
    $oui = $MacNorm.Substring(0,6).ToUpper()
    if ((Get-YealinkOui)     -contains $oui) { return 'Yealink' }
    if ((Get-RaspberryPiOui) -contains $oui) { return 'Raspberry Pi' }
    # Longer-than-24-bit blocks, matched at full length - see the comment on
    # Get-RaspberryPiLongPrefix for why these must not be shortened.
    $full = $MacNorm.ToUpper()
    foreach ($lp in (Get-RaspberryPiLongPrefix)) {
        if ($full.StartsWith($lp)) { return 'Raspberry Pi' }
    }
    # Microsoft's OUI for Hyper-V virtual network adapters. Found on a real site:
    # the Windows SBC ran on a Hyper-V server VM and showed no vendor at all. Says
    # nothing about the guest OS - the platform still comes from SSH / ports / TTL.
    if ($oui -eq '00155D') { return 'Hyper-V virtual machine' }
    return ''
}

function Get-ArpTable {
    # One parse of `arp -a` for every consumer. The same regex used to be
    # duplicated in Get-YealinkArp and Get-ArpHosts, and adding Raspberry Pi
    # detection would have made a third copy.
    #
    # Nothing is filtered here. Unicast and Type are computed and returned so
    # each caller keeps its own semantics: Get-ArpHosts wants real routable
    # hosts, Get-YealinkArp does not care, and those two already behaved
    # differently before this was factored out.
    $out = [System.Collections.Generic.List[object]]::new()
    $lines = @()
    try { $lines = & arp -a } catch {}
    foreach ($line in $lines) {
        if ($line -match '(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})(?:\s+(\w+))?') {
            $ip      = $matches[1]
            $macNorm = ($matches[2] -replace '[-:]','').ToUpper()
            $type    = ''
            if ($matches.Count -ge 4) { $type = [string]$matches[3] }
            $o   = $ip.Split('.')
            $uni = $true
            if ([int]$o[0] -ge 224) { $uni = $false }   # 224+ multicast / reserved
            if ($o[3] -eq '255')    { $uni = $false }   # broadcast
            $out.Add([pscustomobject]@{
                IP      = $ip
                MAC     = ($macNorm -replace '(..)(?=.)','$1-')
                MacNorm = $macNorm
                Oui     = $macNorm.Substring(0,6)
                Type    = $type
                Unicast = $uni
                Vendor  = (Get-MacVendor -MacNorm $macNorm)
            })
        }
    }
    return @($out.ToArray())
}

function Resolve-PtrName {
    # Reverse DNS with a hard cap. A slow or dead resolver must not be able to
    # stall a LAN sweep one host at a time.
    param([string]$Ip,[int]$TimeoutMs = 500)
    try {
        $tt = [System.Net.Dns]::GetHostEntryAsync($Ip)
        if ($tt.Wait($TimeoutMs)) { return [string]$tt.Result.HostName }
    } catch {}
    return ''
}

function Get-YealinkArp {
    param([string[]]$OuiList)
    $result = [System.Collections.Generic.List[object]]::new()
    foreach ($a in (Get-ArpTable)) {
        if ($OuiList -contains $a.Oui) {
            $result.Add([pscustomobject]@{ IP = $a.IP; MAC = $a.MAC; Vendor = 'Yealink'; Hostname = (Resolve-PtrName -Ip $a.IP);
                                           Model = ''; Firmware = ''; SipServer = ''; Reg = ''; Vq = ''; VqDetail = '';
                                           ProvHost = ''; ProvNote = ''; ProvMismatch = $false })
        }
    }
    return @($result.ToArray())
}

function Get-LocalListeners {
    $out = [System.Collections.Generic.List[object]]::new()
    try {
        $conns = Get-NetTCPConnection -LocalPort 5001,5060,5061,5090 -ErrorAction SilentlyContinue
        foreach ($c in @($conns)) {
            $pname = ''
            try { $pp = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue; if ($pp) { $pname = $pp.ProcessName } } catch {}
            $out.Add([pscustomobject]@{
                LocalAddress  = [string]$c.LocalAddress
                LocalPort     = [int]$c.LocalPort
                State         = [string]$c.State
                OwningProcess = [int]$c.OwningProcess
                ProcessName   = $pname
            })
        }
        # UDP too. The 3CX SBC listens on UDP 5060 only, so the TCP-only view that
        # was here reported a running SBC as "nothing listening" - found on a real
        # site where the SBC was on the very PC running the tool.
        $udp = Get-NetUDPEndpoint -LocalPort 5060,5090 -ErrorAction SilentlyContinue
        foreach ($u in @($udp)) {
            if ($null -eq $u) { continue }
            $pname = ''
            try { $pp = Get-Process -Id $u.OwningProcess -ErrorAction SilentlyContinue; if ($pp) { $pname = $pp.ProcessName } } catch {}
            $out.Add([pscustomobject]@{
                LocalAddress  = [string]$u.LocalAddress
                LocalPort     = [int]$u.LocalPort
                State         = 'UDP (bound)'
                OwningProcess = [int]$u.OwningProcess
                ProcessName   = $pname
            })
        }
    } catch {}
    return @($out.ToArray())
}

function New-SipProbeIds {
    # Fresh transaction identifiers for one OPTIONS probe.
    param([string]$LocalIp)
    [pscustomobject]@{
        Branch = 'z9hG4bK' + ([guid]::NewGuid().ToString('N').Substring(0,16))
        Tag    = [guid]::NewGuid().ToString('N').Substring(0,8)
        CallId = [guid]::NewGuid().ToString('N') + '@' + $LocalIp
    }
}

function New-SipOptionsMessage {
    # The one wire format used by every SIP probe in this tool. Branch, Call-ID
    # and tag are parameters rather than generated here so a caller can key a
    # pending-request table on the branch it issued - the OPTIONS train matches
    # replies by branch, which is the RFC 3261 transaction identifier and the
    # same Via header that carries the SIP ALG evidence.
    param(
        [string]$TargetHost,
        [string]$LocalIp,
        [int]$LocalPort,
        [string]$Branch,
        [string]$CallId,
        [string]$Tag,
        [int]$CSeq = 1,
        [string]$UserAgent = '3CX-Checker-Probe'
    )
    $CRLF = [string][char]13 + [string][char]10
    return 'OPTIONS sip:' + $TargetHost + ' SIP/2.0' + $CRLF +
           'Via: SIP/2.0/UDP ' + $LocalIp + ':' + $LocalPort + ';branch=' + $Branch + ';rport' + $CRLF +
           'Max-Forwards: 70' + $CRLF +
           'From: <sip:probe@' + $LocalIp + '>;tag=' + $Tag + $CRLF +
           'To: <sip:' + $TargetHost + '>' + $CRLF +
           'Call-ID: ' + $CallId + $CRLF +
           'CSeq: ' + $CSeq + ' OPTIONS' + $CRLF +
           'Contact: <sip:probe@' + $LocalIp + ':' + $LocalPort + '>' + $CRLF +
           'User-Agent: ' + $UserAgent + $CRLF +
           'Content-Length: 0' + $CRLF + $CRLF
}

function Test-SipUdp {
    param([string]$ComputerName,[int]$Port = 5060,[int]$TimeoutMs = 3000)
    $udp = New-Object System.Net.Sockets.UdpClient
    try {
        $udp.Connect($ComputerName, $Port)
        $local = $udp.Client.LocalEndPoint
        $lip   = $local.Address.ToString()
        $lport = $local.Port
        $ids = New-SipProbeIds -LocalIp $lip
        $msg = New-SipOptionsMessage -TargetHost $ComputerName -LocalIp $lip -LocalPort $lport -Branch $ids.Branch -CallId $ids.CallId -Tag $ids.Tag
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($msg)
        [void]$udp.Send($bytes, $bytes.Length)
        $udp.Client.ReceiveTimeout = $TimeoutMs
        $remoteEP = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        try {
            $resp = $udp.Receive([ref]$remoteEP)
            $text = [System.Text.Encoding]::ASCII.GetString($resp)
            $first = ($text.Split([char]10))[0].Trim()
            return [pscustomobject]@{ Ok = $true; FirstLine = $first }
        } catch [System.Net.Sockets.SocketException] {
            return [pscustomobject]@{ Ok = $false; FirstLine = 'no reply (timeout)' }
        }
    } catch {
        return [pscustomobject]@{ Ok = $false; FirstLine = $_.Exception.Message }
    } finally { try { $udp.Close() } catch {} }
}

function Get-PublicIp {
    param([int]$TimeoutMs = 3000)
    foreach ($u in @('https://checkip.amazonaws.com','https://api.ipify.org','https://ifconfig.me/ip')) {
        try {
            $req = [System.Net.HttpWebRequest]::Create($u)
            $req.Timeout = $TimeoutMs
            $req.UserAgent = '3CX-Checker'
            $resp = $req.GetResponse()
            $sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
            $txt = $sr.ReadToEnd().Trim()
            $sr.Close(); $resp.Close()
            $m = [regex]::Match($txt, '\d{1,3}(?:\.\d{1,3}){3}')
            if ($m.Success) { return $m.Value }
        } catch {}
    }
    return ''
}

function Test-YealinkNewLoginModel {
    # Models whose current firmware has the newer web UI, where the servlet login
    # and status pages this probe uses do not work. Seen: T57W, and T54W on a real
    # site, where a known-good password still read nothing. A failure on these says
    # nothing about the password, and must not be reported as if it did.
    param([string]$Model)
    return [bool]($Model -match '(?i)^(SIP-)?T5\d')
}

function Get-YealinkWebIdentity {
    # Which port a phone serves its web UI on, and its model from the page title -
    # with no credentials and no login attempt. The discovery scan uses it so each
    # row of the Yealink grid can be matched to the per-phone passwords in the 3CX
    # admin console before anything is logged in to; Get-YealinkPhoneInfo uses it
    # before it does log in.
    #
    # Every open web port is collected, then the first one that answers HTTP at all
    # is used - some phones accept TCP on 443 but only really serve the UI over HTTP.
    # Any status counts as an answer: on a real site three phones answered 401
    # (Basic auth) or 403 with an empty or error body, were reported "no HTTP
    # response", and were never logged in to. Two of those 403s were the phone
    # saying its web login was locked - reported here, so nobody adds to the lock.
    param([string]$Ip,[int]$ConnectMs = 1200,[int]$TimeoutMs = 2500,[string]$RawLogPath = '')
    $o = [pscustomobject]@{ Base = ''; WebUI = ''; Model = ''; Note = ''; Status = 0; Locked = $false }
    $candidates = [System.Collections.Generic.List[object]]::new()
    foreach ($sp in @(@{ P = 443; S = 'https' }, @{ P = 80; S = 'http' })) {
        $c = [System.Net.Sockets.TcpClient]::new()
        try {
            $iar = $c.BeginConnect($Ip, $sp.P, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne($ConnectMs, $false)) {
                try { $c.EndConnect($iar); if ($c.Connected) { $candidates.Add(('{0}://{1}' -f $sp.S, $Ip)) } } catch {}
            }
        } catch {} finally { try { $c.Close() } catch {} }
    }
    if (@($candidates).Count -eq 0) { $o.WebUI = 'unreachable'; $o.Note = 'web UI not reachable'; return $o }

    foreach ($cand in @($candidates)) {
        $pr = Invoke-PhoneHttpProbe -Url ($cand + '/') -TimeoutMs $TimeoutMs
        Write-PhoneRaw -Path $RawLogPath -Url ('PROBE ' + $cand + '/  (HTTP ' + $pr.Status + ')') -Text $pr.Text
        if ($pr.Status -gt 0) {
            $o.Base = $cand
            $o.Status = $pr.Status
            if ($pr.Status -ge 200 -and $pr.Status -lt 300 -and $pr.Text) {
                $o.Model = (ConvertFrom-YealinkPayload -Text $pr.Text).Model
                # Older firmware (a T40P on a real site) serves a script redirect to
                # its login form, and only that page's title names the model. One
                # hop, and only to a path on the same phone.
                $jm = [regex]::Match($pr.Text, '(?i)(?:window\.)?location(?:\.href)?\s*=\s*["''](/[^/"''][^"'']*)["'']')
                if (-not $o.Model -and $jm.Success) {
                    $p2 = Invoke-PhoneHttpProbe -Url ($cand + $jm.Groups[1].Value) -TimeoutMs $TimeoutMs
                    Write-PhoneRaw -Path $RawLogPath -Url ('PROBE ' + $cand + $jm.Groups[1].Value + '  (HTTP ' + $p2.Status + ')') -Text $p2.Text
                    if ($p2.Status -ge 200 -and $p2.Status -lt 300 -and $p2.Text) { $o.Model = (ConvertFrom-YealinkPayload -Text $p2.Text).Model }
                }
            }
            $lk = Get-YealinkLockState -Text $pr.Text
            if ($lk.Locked) {
                $o.Locked = $true
                $o.Note = 'web login LOCKED by the phone after failed logins - '
                if ($lk.Minutes -gt 0) { $o.Note += ('try again in about {0} min' -f $lk.Minutes) } else { $o.Note += 'wait before trying again' }
            } elseif ($pr.Status -eq 403) {
                $o.Note = 'its web UI refused this PC (HTTP 403)'
            }
            break
        }
    }
    if (-not $o.Base) {
        $o.WebUI = @($candidates)[0]
        $o.Note  = 'web port open but no HTTP response'
        return $o
    }
    $o.WebUI = $o.Base
    return $o
}

function Get-YealinkPhoneInfo {
    param([string]$Ip,$CredList,[int]$TimeoutMs = 2500,[int]$BudgetMs = 20000,[string]$RawLogPath = '',[switch]$ProbeVq)
    $info = [pscustomobject]@{ WebUI = ''; Model = ''; Firmware = ''; SipServer = ''; Reg = ''; UsedCred = ''; Vq = $null; LoginUnsupported = $false; ApiOutcome = ''; ApiNote = ''; Cleartext = $false; ProvHost = '' }

    $id = Get-YealinkWebIdentity -Ip $Ip -TimeoutMs $TimeoutMs -RawLogPath $RawLogPath
    $info.WebUI = $id.WebUI
    if ($id.Model) { $info.Model = $id.Model }
    if (-not $id.Base) { $info.Reg = $id.Note; return $info }
    # Locked: not one password is tried - each attempt would only extend the lock.
    if ($id.Locked) { $info.Reg = ('not logged in - ' + $id.Note); return $info }
    $base = $id.Base

    # Bound total time per phone so a slow/unresponsive web UI cannot stall the scan.
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $tried = 0
    $timedOut = $false
    # T5x firmware has a JSON web API with an RSA-encrypted login; the servlet
    # pages the older models serve do not exist there.
    $useApi = Test-YealinkNewLoginModel $info.Model
    # The T5x login RSA-encrypts the password even over HTTP; the legacy servlet
    # login and Basic header do not, so flag it for the log when that is the path.
    $info.Cleartext = ($base -like 'http://*') -and (-not $useApi) -and (@($CredList).Count -gt 0)
    foreach ($cred in @($CredList)) {
        if ($sw.ElapsedMilliseconds -gt $BudgetMs) { $timedOut = $true; break }
        $tried++
        Write-PhoneRaw -Path $RawLogPath -Url ('##### ' + $Ip + '  (user ' + $cred.User + ') #####') -Text ''
        if ($useApi) { $r = Read-YealinkT5x -Base $base -User $cred.User -Pass $cred.Pass -TimeoutMs $TimeoutMs -RawLogPath $RawLogPath -ProbeVq:$ProbeVq }
        else         { $r = Read-YealinkConfig -Base $base -User $cred.User -Pass $cred.Pass -TimeoutMs $TimeoutMs -RawLogPath $RawLogPath -ProbeVq:$ProbeVq }
        # Keep whatever this attempt did manage to read, even if it wasn't conclusive.
        if ($r.Model     -and -not $info.Model)     { $info.Model     = $r.Model }
        if ($r.Firmware  -and -not $info.Firmware)  { $info.Firmware  = $r.Firmware }
        if ($r.SipServer -and -not $info.SipServer) { $info.SipServer = $r.SipServer }
        if ($r.Reg       -and -not $info.Reg)       { $info.Reg       = $r.Reg }
        if ($r.ProvHost  -and -not $info.ProvHost)  { $info.ProvHost  = $r.ProvHost }
        if ($r.GotData) { $info.UsedCred = $cred.User; $info.Vq = $r.Vq; return $info }
        if ($useApi) {
            $info.ApiOutcome = $r.Outcome; $info.ApiNote = $r.Note
            # A lock or a busy session ends the attempts on this phone: another
            # password would only add to the lock, or fight the person logged in.
            # A missing login key will not appear for the next password either.
            if (@('locked', 'busy', 'no-key', 'logged-in-no-data') -contains $r.Outcome) { break }
        }
    }
    $sw.Stop()
    # Model alone does not mean the login worked (it comes from the public page
    # title), so the failure note depends only on the authenticated fields.
    if (-not ($info.SipServer -or $info.Reg)) {
        if ($timedOut) {
            $info.Reg = ('timed out after {0} credential(s)' -f $tried)
        } elseif ($useApi -and $info.ApiOutcome -and $info.ApiOutcome -ne 'no-key') {
            $info.Reg = switch ($info.ApiOutcome) {
                'wrong-password'    { ('password rejected by the phone ({0} credential(s) tried)' -f $tried) }
                'locked'            { ('not read - ' + $info.ApiNote + '. Wait before trying again.') }
                'busy'              { ('not read - ' + $info.ApiNote) }
                'logged-in-no-data' { 'logged in, but the SIP server was not in the reply - tick Save raw probe data and send the capture' }
                default             { ('not read - ' + $info.ApiNote) }
            }
        } elseif ($useApi) {
            $info.LoginUnsupported = $true
            $info.Reg = ('not read - the {0} uses a newer web login than this tool knows (it handed out no login key), so this says nothing about the password' -f $info.Model)
        } else {
            $info.Reg = ('login failed / config not read after {0} credential(s) - a wrong password, or a web login this tool does not handle' -f $tried)
        }
    }
    return $info
}

function Invoke-PhoneHttpProbe {
    # One GET with no credentials that reports what came back, error statuses
    # included: a phone answering 401 or 403 has a working web UI, and a 403 page
    # is where a Yealink says its web login is locked. A .NET method's exception
    # reaches PowerShell wrapped, so the WebException - and its Response - is
    # found by walking InnerException.
    param([string]$Url,[int]$TimeoutMs = 2500)
    $o = [pscustomobject]@{ Status = 0; Text = ''; Auth = '' }
    $resp = $null
    try {
        $r = [System.Net.HttpWebRequest]::Create($Url)
        $r.Method = 'GET'
        $r.Timeout = $TimeoutMs
        $r.ReadWriteTimeout = $TimeoutMs
        $r.UserAgent = '3CX-Checker'
        $r.AllowAutoRedirect = $true
        $r.CookieContainer = New-Object System.Net.CookieContainer
        $resp = $r.GetResponse()
    } catch {
        $ex = $_.Exception
        while ($ex -and -not ($ex -is [System.Net.WebException])) { $ex = $ex.InnerException }
        if ($ex) { $resp = $ex.Response }
    }
    if (-not $resp) { return $o }
    try {
        $o.Status = [int]$resp.StatusCode
        $o.Auth   = [string]$resp.Headers['WWW-Authenticate']
        $sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
        $o.Text = $sr.ReadToEnd(); $sr.Close()
    } catch {} finally { try { $resp.Close() } catch {} }
    return $o
}

function Get-YealinkLockState {
    # A Yealink that has locked its web login after failed attempts serves an HTTP
    # 403 page carrying {"authstatus":"lock","locktime":"3"} - the wait in minutes.
    param([string]$Text)
    $o = [pscustomobject]@{ Locked = $false; Minutes = 0 }
    if ([string]$Text -match '"authstatus"\s*:\s*"lock"') {
        $o.Locked = $true
        $m = [regex]::Match($Text, '"locktime"\s*:\s*"?(\d+)')
        if ($m.Success) { $o.Minutes = [int]$m.Groups[1].Value }
    }
    return $o
}

function Get-PhoneWebUrl {
    # A phone's own web page: the scheme that answered during the scan, else
    # HTTPS. Built from a plain IPv4 address only, so nothing a device or the
    # network supplies can reach the browser's command line.
    param([string]$Ip,[string]$WebUi = '')
    # No leading zeros: .NET reads "010" as octal, so the page opened would not be
    # the address shown.
    if ([string]$Ip -notmatch '^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$') { return '' }
    foreach ($o in $Ip.Split('.')) { if ([int]$o -gt 255) { return '' } }
    $scheme = 'https'
    if ([string]$WebUi -like 'http://*') { $scheme = 'http' }
    return ('{0}://{1}/' -f $scheme, $Ip)
}

function Test-BackstageSession {
    # ConnectWise ScreenConnect's Backstage: a separate desktop that runs as
    # SYSTEM, with no Explorer shell and no default browser to hand a URL to.
    # Either sign counts - running as SYSTEM, or the Backstage shell among this
    # process's ancestors.
    try { if ([Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) { return $true } } catch {}
    try {
        $all = @{}
        foreach ($p in @(Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId, Name -ErrorAction Stop)) { $all[[int]$p.ProcessId] = $p }
        $cur = $PID
        for ($i = 0; $i -lt 10 -and $all.ContainsKey($cur); $i++) {
            $p = $all[$cur]
            if ([string]$p.Name -like 'ScreenConnect.WindowsBackstageShell*') { return $true }
            $next = [int]$p.ParentProcessId
            if ($next -le 4 -or $next -eq $cur) { break }
            $cur = $next
        }
    } catch {}
    return $false
}

function Invoke-PhoneHttp {
    param($Url,$Method,$Body,$Cookies,$Basic,$TimeoutMs)
    try {
        $r = [System.Net.HttpWebRequest]::Create($Url)
        $r.Method = $Method
        $r.Timeout = $TimeoutMs
        $r.ReadWriteTimeout = $TimeoutMs
        $r.CookieContainer = $Cookies
        if ($Basic) { $r.Headers['Authorization'] = $Basic }
        $r.UserAgent = '3CX-Checker'
        $r.AllowAutoRedirect = $true
        if ($Method -eq 'POST' -and $Body) {
            $r.ContentType = 'application/x-www-form-urlencoded'
            $b = [System.Text.Encoding]::ASCII.GetBytes($Body)
            $r.ContentLength = $b.Length
            $s = $r.GetRequestStream(); $s.Write($b, 0, $b.Length); $s.Close()
        }
        $resp = $r.GetResponse()
        $sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
        $txt = $sr.ReadToEnd(); $sr.Close(); $resp.Close()
        return $txt
    } catch {
        $rr = $_.Exception.Response
        if ($rr) { try { $s2 = New-Object System.IO.StreamReader($rr.GetResponseStream()); $t = $s2.ReadToEnd(); $s2.Close(); return $t } catch {} }
        return ''
    }
}

function Get-HostFromUrl {
    # Host only: "https://pbx.example.com:5001/provisioning/abc/x.cfg" -> "pbx.example.com".
    # A provisioning path is a secret - it hands out the device's whole config, SIP
    # credentials included - so the host is the only part of one the tool keeps,
    # shows, logs or exports.
    param([string]$Url)
    $m = [regex]::Match(([string]$Url).Trim(), '(?i)^(?:[a-z][a-z0-9+.-]*://)?(?:[^@/\s]*@)?(\[[^\]]+\]|[^/:?#\s]+)')
    if (-not $m.Success) { return '' }
    return $m.Groups[1].Value.ToLowerInvariant()
}

function Get-ProvisioningHostFromText {
    # The Auto Provision server's HOST from a settings page: the value of the
    # auto_provision...server...url setting if it is named, else the first 3CX
    # provisioning link in the text. '' if neither is there. Never the path.
    param([string]$Text)
    if (-not $Text) { return '' }
    $m = [regex]::Match($Text, '(?is)auto_?provision[._]?server[._]?url["'']?\s*(?:value\s*)?[:=,]\s*["'']?((?:https?|ftps?|tftp)://[^"''\s<>\\]+)')
    if ($m.Success) { return (Get-HostFromUrl $m.Groups[1].Value) }
    $m = [regex]::Match($Text, '(?i)(?:https?|ftps?|tftp)://[^"''\s<>/\\]+/provisioning/')
    if ($m.Success) { return (Get-HostFromUrl $m.Value) }
    return ''
}

function Get-ProvisioningVerdict {
    # Where a phone provisions from, against the PBX under test - hosts only.
    # Found on a real site: a W60B DECT base still provisioned from an older 3CX
    # instance, so every reboot re-applied that instance's config (a retired SBC)
    # and both handsets lost service. Fixing the base by hand cannot stick while
    # this points elsewhere.
    param([string]$ProvHost,[string]$PbxHost)
    $o = [pscustomobject]@{ Mismatch = $false; Note = '' }
    $p = ([string]$ProvHost).Trim().ToLowerInvariant()
    $x = (Get-HostFromUrl $PbxHost)
    if (-not $p) { return $o }
    if ($x -and $p -eq $x) { $o.Note = 'provisions from this PBX'; return $o }
    if ($p -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)') {
        $o.Mismatch = $true
        $o.Note = ('provisions from a LAN address (' + $p + ') - an old SBC or on-site PBX?')
        return $o
    }
    if ($x) {
        $o.Mismatch = $true
        $o.Note = ('provisions from ' + $p + ', not ' + $x + ' - its next provisioning cycle (a reboot, say) applies that PBX''s config')
        return $o
    }
    $o.Note = ('provisions from ' + $p)
    return $o
}

function ConvertFrom-SipSbcReply {
    # What a SIP reply says about a 3CX SBC in its path. Measured on a real 3CX
    # Router Phone (a T57W): it relays OPTIONS through its tunnel to the PBX and
    # answers with
    #     Record-Route: <sip:3CXSBC@<its IP>:5060;user=proxy;tnlid=sbc.<id>>
    #     To: <sip:<the PBX's FQDN>:5060>;tag=...
    # The Record-Route is the 3CX SBC code naming itself - the PBX answering
    # directly adds no such header - and the To host is the PBX it forwards to.
    param([string]$Text,[string]$ProbedIp = '')
    $o = [pscustomobject]@{ SbcMarker = $false; TunnelId = ''; ForwardsTo = '' }
    if (-not $Text) { return $o }
    $rr = [regex]::Match($Text, '(?im)^Record-Route:[^\r\n]*<sip:3CXSBC@[^>\r\n]*>')
    if (-not $rr.Success) { return $o }
    $o.SbcMarker = $true
    $t = [regex]::Match($rr.Value, '(?i)tnlid=([^;>\s]+)')
    if ($t.Success) { $o.TunnelId = $t.Groups[1].Value }
    $to = [regex]::Match($Text, '(?im)^(?:To|t)\s*:\s*(?:"[^"]*"\s*)?<?sips?:(?:[^@>;\s]+@)?([^:;>\s]+)')
    if ($to.Success) {
        $h = $to.Groups[1].Value.ToLowerInvariant()
        if ($h -and $h -ne $ProbedIp) { $o.ForwardsTo = $h }
    }
    return $o
}

function Protect-RawCaptureText {
    # The raw capture exists to be sent to whoever tunes the parser, so it must
    # never carry a provisioning secret. Keep the host, drop the path, and blank
    # any provisioning user name or password value outright. The named setting is
    # handled first, so the generic /provisioning/ pass does not double up on it.
    param([string]$Text)
    if (-not $Text) { return $Text }
    $t = [regex]::Replace($Text, '(?is)(auto_?provision[._]?server[._]?url["'']?\s*(?:value\s*)?[:=,]\s*["'']?(?:https?|ftps?|tftp)://[^/\s"''<>\\]+)[^\s"''<>\\]*', '$1/<redacted>')
    $t = [regex]::Replace($t, '(?is)(auto_?provision[._]?server[._]?(?:user_?name|password)["'']?\s*(?:value\s*)?[:=,]\s*["'']?)[^"''\s<>&]*', '$1<redacted>')
    $t = [regex]::Replace($t, '(?i)((?:https?|ftps?|tftp)://[^/\s"''<>\\]+)/provisioning/[^\s"''<>\\]*', '$1/provisioning/<redacted>')
    return $t
}

function Write-PhoneRaw {
    # Appends the raw response text so unknown firmware payloads can be inspected.
    # Provisioning secrets are redacted on the way in - see Protect-RawCaptureText.
    param([string]$Path,[string]$Url,[string]$Text)
    if (-not $Path) { return }
    try {
        $CRLF = [string][char]13 + [string][char]10
        $Text = Protect-RawCaptureText $Text
        $body = if ($Text) { if ($Text.Length -gt 200000) { $Text.Substring(0,200000) + '...[truncated]' } else { $Text } } else { '(empty)' }
        $entry = $CRLF + '===== ' + $Url + '  [' + $body.Length + ' chars] =====' + $CRLF + $body + $CRLF
        [System.IO.File]::AppendAllText($Path, $entry)
    } catch {}
}

function Get-RegStatusText {
    param([string]$Text)
    if (-not $Text) { return '' }
    # Prefer an explicit key = value.
    $m = [regex]::Match($Text, '(?i)"?(?:reg_?status|register_?status|account_?status|line_?status|regstatus|sip_reg_status)"?\s*[:=]\s*"?\s*([A-Za-z0-9_ ]{1,24})')
    if ($m.Success) {
        $v = $m.Groups[1].Value.Trim().Trim('"')
        if ($v -match '^\d+$') {
            if ([int]$v -eq 0) { return 'Unregistered / Disabled (0)' }
            if ([int]$v -eq 1) { return 'Register Failed / Registering (1)' }
            if ([int]$v -eq 2) { return 'Registered (2)' }
            return ('status code ' + $v)
        }
        if ($v) { return ($v -replace '_',' ') }
    }
    # Fall back to literal wording, but only across VISIBLE page text: strip
    # script/style blocks and every HTML tag first, so markup attributes such as
    # <input disabled> or <button disabled> cannot be mistaken for a SIP state.
    # ('Disabled' is deliberately not matched on its own - far too common in markup.)
    $visible = $Text
    $visible = [regex]::Replace($visible, '(?is)<script.*?</script>', ' ')
    $visible = [regex]::Replace($visible, '(?is)<style.*?</style>', ' ')
    $visible = [regex]::Replace($visible, '(?s)<[^>]*>', ' ')
    $m = [regex]::Match($visible, '(?i)(Register\s*Failed|Registration\s*Failed|Register\s*Timeout|Unregistered|Registering|Registered)')
    if ($m.Success) { return $m.Groups[1].Value }
    return ''
}

function ConvertFrom-YealinkPayload {
    param([string]$Text)
    $o = [pscustomobject]@{ Model = ''; Firmware = ''; SipServer = ''; Reg = '' }
    if (-not $Text) { return $o }
    # Yealink web UIs (including the newer single-page-app firmware) put the
    # model in the page title, and that needs no credentials at all.
    $m = [regex]::Match($Text, '(?i)<title>\s*Yealink\s+([A-Za-z0-9\-]{2,15})')
    if ($m.Success) { $o.Model = $m.Groups[1].Value.Trim() }
    if (-not $o.Model) {
        $m = [regex]::Match($Text, '(?i)"?(?:device_model|phone_model|product_name|device_type|model)"?\s*[:=]\s*"?\s*([A-Za-z0-9][A-Za-z0-9\-_ ]{1,24})')
        if ($m.Success) { $o.Model = $m.Groups[1].Value.Trim().Trim('"') }
    }
    $m = [regex]::Match($Text, '(?i)"?(?:firmware_version|firmware|fw_version|software_version|version)"?\s*[:=]\s*"?\s*([0-9][0-9A-Za-z\.]{2,30})')
    if ($m.Success) { $o.Firmware = $m.Groups[1].Value.Trim().Trim('"') }
    $m = [regex]::Match($Text, '(?i)(?:sip_server\.\d+\.address|sip_server_host|sip_server_address|sip_server|server_host|outbound_host|registrar_server|registrar)[^0-9A-Za-z]{0,8}?[:=][^0-9A-Za-z]{0,8}([0-9]{1,3}(?:\.[0-9]{1,3}){3}|[A-Za-z0-9][A-Za-z0-9\.\-]{3,60})')
    if ($m.Success) { $o.SipServer = $m.Groups[1].Value.Trim().Trim('"') }
    $o.Reg = Get-RegStatusText -Text $Text
    return $o
}

function ConvertTo-PhoneLoginBody {
    # Form-encodes the legacy servlet login. Sent raw, a password containing
    # & + % # = was cut short or altered on the way, and the phone just answered
    # "login failed" - indistinguishable from a wrong password.
    param([string]$User,[string]$Pass)
    return ('username={0}&pwd={1}' -f [Uri]::EscapeDataString([string]$User), [Uri]::EscapeDataString([string]$Pass))
}

function Read-YealinkConfig {
    param([string]$Base,[string]$User,[string]$Pass,[int]$TimeoutMs = 2500,[string]$RawLogPath = '',
          [switch]$ProbeVq,[int]$VqBudgetMs = 8000)
    $LF = [string][char]10
    $out = [pscustomobject]@{ GotData = $false; Model = ''; Firmware = ''; SipServer = ''; Reg = ''; Vq = $null; ProvHost = '' }
    $cookies = New-Object System.Net.CookieContainer
    $basic = 'Basic ' + [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(($User + ':' + $Pass)))

    # Modern Yealink web login (session cookie); older models fall back to Basic auth.
    $login = Invoke-PhoneHttp -Url ($Base + '/servlet?m=mod_data&p=login&q=login') -Method 'POST' -Body (ConvertTo-PhoneLoginBody -User $User -Pass $Pass) -Cookies $cookies -Basic $basic -TimeoutMs $TimeoutMs
    Write-PhoneRaw -Path $RawLogPath -Url 'POST /servlet?m=mod_data&p=login&q=login' -Text $login

    $paths = @(
        '/servlet?m=mod_data&p=status&q=load',
        '/servlet?m=mod_data&p=account-register&q=load',
        '/servlet?m=mod_data&p=status-account&q=load',
        '/servlet?m=mod_data&p=accounts&q=load',
        '/servlet?m=mod_listener&p=status&q=load',
        '/cgi-bin/cgiServer.exx?command=GetStatus',
        '/status.htm',
        '/'
    )
    $all = ''
    $fetched = @{}
    foreach ($path in $paths) {
        $fetched[$path] = $true
        $t = Invoke-PhoneHttp -Url ($Base + $path) -Method 'GET' -Body $null -Cookies $cookies -Basic $basic -TimeoutMs $TimeoutMs
        Write-PhoneRaw -Path $RawLogPath -Url ('GET ' + $path) -Text $t
        if ($t) { $all = $all + $LF + $t }
        $p = ConvertFrom-YealinkPayload -Text $all
        if ($p.SipServer -and $p.Reg) { break }   # enough to answer the question
    }

    $parsed = ConvertFrom-YealinkPayload -Text $all
    $out.Model     = $parsed.Model
    $out.Firmware  = $parsed.Firmware
    $out.SipServer = $parsed.SipServer
    $out.Reg       = $parsed.Reg
    # Only SIP server / registration prove we actually read config; model and
    # firmware strings also appear on login pages, so they must not end the
    # credential loop early (they are still kept as partial results).
    $out.GotData = [bool]($out.SipServer -or $out.Reg)

    # Where the phone provisions from - host only. One extra page, fetched only once
    # a login has demonstrably worked, in the same session. A phone provisioning
    # from a different PBX re-applies that PBX's config at its next cycle.
    if ($out.GotData) {
        $ap = '/servlet?m=mod_data&p=settings-autop&q=load'
        $apText = $all
        if (-not $fetched.ContainsKey($ap)) {
            $fetched[$ap] = $true
            $at = Invoke-PhoneHttp -Url ($Base + $ap) -Method 'GET' -Body $null -Cookies $cookies -Basic $basic -TimeoutMs ([int][math]::Min($TimeoutMs, 1500))
            Write-PhoneRaw -Path $RawLogPath -Url ('GET ' + $ap + '   [auto-provision settings]') -Text $at
            if ($at) { $apText = $apText + $LF + $at }
        }
        $out.ProvHost = Get-ProvisioningHostFromText -Text $apText
    }

    # Voice-quality readiness, read in the SAME authenticated session and only once
    # a login has demonstrably worked - so a wrong password never costs a single
    # extra request. Pages already fetched above are reused, not re-requested (the
    # status loop can stop before reaching account-register). The pass has its own
    # time budget and a shorter per-request timeout because it runs inside the
    # per-phone budget of Get-YealinkPhoneInfo; on a real phone an unknown page
    # answers 404 at once, so the budget only bites on a hung web server.
    if ($ProbeVq -and $out.GotData) {
        $vqText = $all
        $vqSw = [System.Diagnostics.Stopwatch]::StartNew()
        $vqTimeout = [int][math]::Min($TimeoutMs, 1500)
        foreach ($vp in (Get-YealinkVqProbePath)) {
            if ($fetched.ContainsKey($vp)) { continue }
            if ($vqSw.ElapsedMilliseconds -gt $VqBudgetMs) {
                Write-PhoneRaw -Path $RawLogPath -Url ('VQ probe time budget spent before ' + $vp) -Text ''
                break
            }
            $fetched[$vp] = $true
            $vt = Invoke-PhoneHttp -Url ($Base + $vp) -Method 'GET' -Body $null -Cookies $cookies -Basic $basic -TimeoutMs $vqTimeout
            Write-PhoneRaw -Path $RawLogPath -Url ('GET ' + $vp + '   [VQ candidate - undocumented path]') -Text $vt
            if ($vt) { $vqText = $vqText + $LF + $vt }
        }
        $vqSw.Stop()
        $out.Vq = ConvertFrom-YealinkVq -Text $vqText
    }
    return $out
}

# ---------------------------------------------------------------------------
# Yealink T5x web API (newer firmware: T54W 96.87.0.22 on a real site)
# ---------------------------------------------------------------------------
# Read from the phone's own web app (app.js, saved from a real T54W):
#   * the password is RSA-encrypted in the browser - jsbn, PKCS#1 v1.5, hex output
#     without leading zeros, prefixed "__WUI_ENC__:" - with a key fetched by
#     POST /api/common/info {"idlist":["wui.common.rsaN","wui.common.rsaE"]}
#   * POST /api/auth/login, form-encoded username=..&pwd=..; replies are
#     {"ret":"ok","data":..} or {"ret":"failed", ..webStatus/msg..}
#   * every request carries ?p=<page>&t=<ms> and an X-CSRFToken header
#   * settings are read by name: POST /api/inner/readconfig {"formData":[names]}
#     (this firmware sends plain names - its isSupportConfigIdToM7() is false)
#   * ONE web session at a time: a second login gets "auth_err_user_busy", so the
#     probe always logs out, and never pushes past a busy or locked phone.
# Read-only: nothing here calls a write endpoint. The password and its encrypted
# form are never written to the raw capture.
# ---------------------------------------------------------------------------

function ConvertFrom-HexString {
    param([string]$Hex)
    $h = ([string]$Hex -replace '[^0-9A-Fa-f]', '')
    if ($h.Length % 2) { $h = '0' + $h }
    $b = New-Object byte[] ($h.Length / 2)
    for ($i = 0; $i -lt $b.Length; $i++) { $b[$i] = [Convert]::ToByte($h.Substring(2 * $i, 2), 16) }
    return ,$b
}

function Protect-YealinkWuiPassword {
    # Reproduces the web UI's RSAEncrypt exactly: PKCS#1 v1.5 (what .NET's RSA does
    # with fOAEP = $false), lowercase hex with leading zeros dropped and padded to
    # an even length as jsbn's toString(16) does, then the "__WUI_ENC__:" prefix.
    param([string]$Password,[string]$ModulusHex,[string]$ExponentHex)
    $n = ConvertFrom-HexString $ModulusHex
    $i = 0; while ($i -lt $n.Length - 1 -and $n[$i] -eq 0) { $i++ }
    if ($i -gt 0) { $n = $n[$i..($n.Length - 1)] }
    $e = ConvertFrom-HexString $ExponentHex
    $j = 0; while ($j -lt $e.Length - 1 -and $e[$j] -eq 0) { $j++ }
    if ($j -gt 0) { $e = $e[$j..($e.Length - 1)] }
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    try {
        $p = New-Object System.Security.Cryptography.RSAParameters
        $p.Modulus = [byte[]]$n; $p.Exponent = [byte[]]$e
        $rsa.ImportParameters($p)
        $c = $rsa.Encrypt([System.Text.Encoding]::UTF8.GetBytes([string]$Password), $false)
    } finally { $rsa.Dispose() }
    $hex = (-join ($c | ForEach-Object { $_.ToString('x2') })).TrimStart('0')
    if ($hex.Length % 2) { $hex = '0' + $hex }
    return ('__WUI_ENC__:' + $hex)
}

function Invoke-YealinkApi {
    # One call to the T5x web API. Returns the status, raw text and parsed JSON.
    param([string]$Base,[string]$Path,[string]$Page,[string]$Json = '',[string]$Form = '',$Cookies,[string]$Token = '',[int]$TimeoutMs = 2500)
    $sep = '?'; if ($Path.Contains('?')) { $sep = '&' }
    $url = ('{0}{1}{2}p={3}&t={4}' -f $Base, $Path, $sep, $Page, [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())
    $o = [pscustomobject]@{ Status = 0; Text = ''; Obj = $null }
    try {
        $r = [System.Net.HttpWebRequest]::Create($url)
        $r.Method = 'POST'
        $r.Timeout = $TimeoutMs; $r.ReadWriteTimeout = $TimeoutMs
        $r.CookieContainer = $Cookies
        $r.UserAgent = '3CX-Checker'
        $r.Accept = 'application/json, text/plain, */*'
        $r.Headers['X-CSRFToken'] = $Token
        $body = $Json; $r.ContentType = 'application/json;charset=UTF-8'
        if ($Form) { $body = $Form; $r.ContentType = 'application/x-www-form-urlencoded' }
        $b = [System.Text.Encoding]::UTF8.GetBytes([string]$body)
        $r.ContentLength = $b.Length
        $s = $r.GetRequestStream(); $s.Write($b, 0, $b.Length); $s.Close()
        $resp = $r.GetResponse()
        $o.Status = [int]$resp.StatusCode
        $sr = New-Object System.IO.StreamReader($resp.GetResponseStream()); $o.Text = $sr.ReadToEnd(); $sr.Close(); $resp.Close()
    } catch {
        $rr = $_.Exception.Response
        if ($rr) {
            try { $o.Status = [int]$rr.StatusCode } catch {}
            try { $s2 = New-Object System.IO.StreamReader($rr.GetResponseStream()); $o.Text = $s2.ReadToEnd(); $s2.Close() } catch {}
        }
    }
    if ($o.Text -and $o.Text.TrimStart().StartsWith('{')) { try { $o.Obj = $o.Text | ConvertFrom-Json } catch {} }
    return $o
}

function Get-JsonField {
    # A property that may sit under .data or at the top, under its full dotted
    # name or its short one (the web app reads both, e.g. rsaN / wui.common.rsaN).
    param($Obj,[string[]]$Names)
    if (-not $Obj) { return '' }
    foreach ($holder in @($Obj.PSObject.Properties['data'], $Obj.PSObject.Properties['error'])) {
        if ($holder -and $holder.Value -and $holder.Value.PSObject) {
            foreach ($n in $Names) { $p = $holder.Value.PSObject.Properties[$n]; if ($p -and $null -ne $p.Value) { return [string]$p.Value } }
        }
    }
    foreach ($n in $Names) { $p = $Obj.PSObject.Properties[$n]; if ($p -and $null -ne $p.Value) { return [string]$p.Value } }
    return ''
}

function Get-YealinkT5xConfigIds {
    # The settings the probe asks for, by name - never the whole configuration.
    return @(
        'account.1.sip_server.1.address', 'account.1.sip_server.1.port', 'account.1.sip_server_host',
        'account.1.outbound_proxy_enable', 'account.1.outbound_host', 'account.1.enable',
        'phone_setting.vq_rtcpxr.session_report.enable', 'phone_setting.vq_rtcpxr.interval_report.enable',
        'phone_setting.vq_rtcpxr.states_show_on_web.enable', 'phone_setting.vq_rtcpxr.states_show_on_gui.enable',
        'account.1.vq_rtcpxr.collector_server_host', 'account.1.vq_rtcpxr.collector_server_port',
        'static.auto_provision.custom.protect',
        # Read so its HOST can be compared with the PBX under test. The value is
        # reduced to the host straight away and redacted in the raw capture.
        'static.auto_provision.server.url'
    )
}

function Read-YealinkT5x {
    # Same result shape as Read-YealinkConfig, plus Outcome/Note saying exactly how
    # far it got: ok, logged-in-no-data, wrong-password, locked, busy, no-key, error.
    param([string]$Base,[string]$User,[string]$Pass,[int]$TimeoutMs = 2500,[string]$RawLogPath = '',[switch]$ProbeVq)
    $out = [pscustomobject]@{ GotData = $false; Model = ''; Firmware = ''; SipServer = ''; Reg = ''; Vq = $null; Outcome = 'error'; Note = ''; ProvHost = '' }
    $ck = New-Object System.Net.CookieContainer
    $uri = [Uri]$Base
    $st = @{ Tok = '' }        # CSRF token, if the phone hands one out
    $tokOf = { $cc = $ck.GetCookies($uri)['csrftoken']; if ($cc) { return $cc.Value }; return $st.Tok }

    # 1. The login key.
    $k = Invoke-YealinkApi -Base $Base -Path '/api/common/info' -Page 'Login' -Json '{"idlist":["wui.common.rsaN","wui.common.rsaE"]}' -Cookies $ck -Token (& $tokOf) -TimeoutMs $TimeoutMs
    Write-PhoneRaw -Path $RawLogPath -Url ('T5x POST /api/common/info (login key)  [HTTP ' + $k.Status + ']') -Text $k.Text
    $n = Get-JsonField $k.Obj @('wui.common.rsaN', 'rsaN')
    $e = Get-JsonField $k.Obj @('wui.common.rsaE', 'rsaE')
    if (-not $n -or -not $e) {
        $out.Outcome = 'no-key'
        $out.Note = 'the phone did not hand out a login key'
        return $out
    }

    # 2. Log in. The request body is not recorded: it holds the encrypted password.
    try { $enc = Protect-YealinkWuiPassword -Password $Pass -ModulusHex $n -ExponentHex $e }
    catch { $out.Outcome = 'no-key'; $out.Note = ('the login key could not be used: ' + $_.Exception.Message); return $out }
    $form = ('username={0}&pwd={1}' -f [Uri]::EscapeDataString($User), [Uri]::EscapeDataString($enc))
    $l = Invoke-YealinkApi -Base $Base -Path '/api/auth/login' -Page 'Login' -Form $form -Cookies $ck -Token (& $tokOf) -TimeoutMs $TimeoutMs
    Write-PhoneRaw -Path $RawLogPath -Url ('T5x POST /api/auth/login (user ' + $User + '; password sent encrypted, not recorded)  [HTTP ' + $l.Status + ']') -Text $l.Text
    $ret = Get-JsonField $l.Obj @('ret')
    if (@('ok', 'true') -notcontains $ret.ToLower()) {
        $ws  = Get-JsonField $l.Obj @('webStatus')
        $msg = Get-JsonField $l.Obj @('msg')
        if ($ws -eq 'lock' -or $l.Text -match '"webStatus"\s*:\s*"lock"') {
            $lt = Get-JsonField $l.Obj @('lockTime')
            $out.Outcome = 'locked'
            $out.Note = 'the phone has LOCKED its web login after too many failed attempts'
            if ($lt) { $out.Note += (' (for ' + $lt + ' s)') }
        } elseif ($msg -eq 'auth_err_user_busy' -or $l.Text -match 'auth_err_user_busy') {
            $who = Get-JsonField $l.Obj @('lineIp')
            $out.Outcome = 'busy'
            $out.Note = 'someone is logged in to its web page'
            if ($who) { $out.Note += (' from ' + $who) }
            $out.Note += ' - the phone allows one session, and the tool does not push them out'
        } elseif (@('403', '503') -contains $ws) {
            $out.Outcome = 'error'
            $out.Note = ('the phone refused the request (web status ' + $ws + '), which is not a password verdict')
        } elseif ($l.Obj) {
            # What the phone's own login page shows for every other refusal.
            $out.Outcome = 'wrong-password'
            $out.Note = 'the phone rejected the username or password'
        } else {
            $out.Outcome = 'error'
            $out.Note = ('no usable reply to the login (HTTP ' + $l.Status + ')')
        }
        return $out
    }

    # 3. Read - then ALWAYS log out, or the phone stays "busy" for a technician.
    try {
        $i = Invoke-YealinkApi -Base $Base -Path '/api/common/info' -Page 'Status' -Json '{"idlist":["wui.common.token","wui.device.firmware"]}' -Cookies $ck -Token (& $tokOf) -TimeoutMs $TimeoutMs
        Write-PhoneRaw -Path $RawLogPath -Url ('T5x POST /api/common/info (token, firmware)  [HTTP ' + $i.Status + ']') -Text $i.Text
        $t = Get-JsonField $i.Obj @('wui.common.token', 'token')
        if ($t) { $st.Tok = $t }
        $out.Firmware = Get-JsonField $i.Obj @('wui.device.firmware', 'firmware')

        $ids = @(Get-YealinkT5xConfigIds)
        $body = (@{ formData = $ids } | ConvertTo-Json -Compress)
        $c = Invoke-YealinkApi -Base $Base -Path '/api/inner/readconfig' -Page 'Status' -Json $body -Cookies $ck -Token (& $tokOf) -TimeoutMs $TimeoutMs
        Write-PhoneRaw -Path $RawLogPath -Url ('T5x POST /api/inner/readconfig (named settings only)  [HTTP ' + $c.Status + ']') -Text $c.Text
        $fd = $null
        if ($c.Obj -and $c.Obj.PSObject.Properties['data'] -and $c.Obj.data -and $c.Obj.data.PSObject.Properties['formData']) { $fd = $c.Obj.data.formData }
        $get = { param($id) if ($fd -and $fd.PSObject.Properties[$id] -and $null -ne $fd.PSObject.Properties[$id].Value) { return [string]$fd.PSObject.Properties[$id].Value }; return '' }
        $srv = & $get 'account.1.sip_server.1.address'
        if (-not $srv) { $srv = & $get 'account.1.sip_server_host' }
        $port = & $get 'account.1.sip_server.1.port'
        if ($srv -and $port -and $port -ne '5060' -and $port -ne '0') { $srv = ($srv + ':' + $port) }
        $out.SipServer = $srv
        $out.ProvHost  = Get-HostFromUrl (& $get 'static.auto_provision.server.url')

        # Registration state: best-effort - the page that reads it was not in the
        # saved web app, so the reply format is not known yet.
        $a = Invoke-YealinkApi -Base $Base -Path '/api/account/status' -Page 'Status' -Json '{}' -Cookies $ck -Token (& $tokOf) -TimeoutMs $TimeoutMs
        Write-PhoneRaw -Path $RawLogPath -Url ('T5x POST /api/account/status  [HTTP ' + $a.Status + ']') -Text $a.Text
        $out.Reg = Get-RegStatusText -Text $a.Text

        $out.GotData = [bool]($out.SipServer -or $out.Reg)
        if ($out.GotData) {
            $out.Outcome = 'ok'
        } else {
            $out.Outcome = 'logged-in-no-data'
            $out.Note = 'logged in, but the SIP server was not in what the phone returned'
        }
        if ($ProbeVq -and $out.GotData) {
            $vqText = $c.Text
            $rt = Invoke-YealinkApi -Base $Base -Path '/api/diagnosis/rtp/status' -Page 'Status' -Json '{}' -Cookies $ck -Token (& $tokOf) -TimeoutMs ([int][math]::Min($TimeoutMs, 1500))
            Write-PhoneRaw -Path $RawLogPath -Url ('T5x POST /api/diagnosis/rtp/status  [HTTP ' + $rt.Status + ']') -Text $rt.Text
            if ($rt.Text) { $vqText = $vqText + [string][char]10 + $rt.Text }
            $out.Vq = ConvertFrom-YealinkVq -Text $vqText
        }
    } finally {
        $lo = Invoke-YealinkApi -Base $Base -Path '/api/auth/logout' -Page 'Status' -Json '{}' -Cookies $ck -Token (& $tokOf) -TimeoutMs $TimeoutMs
        Write-PhoneRaw -Path $RawLogPath -Url ('T5x POST /api/auth/logout  [HTTP ' + $lo.Status + ']') -Text $lo.Text
    }
    return $out
}

# ---------------------------------------------------------------------------
# Voice-quality (VQ-RTCPXR, RFC 6035) readiness
# ---------------------------------------------------------------------------
# Yealink phones can report REAL per-call quality measured by their own DSP -
# MOS-LQ/MOS-CQ, jitter, loss - which is the one thing the Media tab cannot
# measure, because nothing answers on the RTP range. It is off by default.
#
# This section is deliberately READ-ONLY. It never changes a phone setting: a
# web-UI change would likely be wiped at the next 3CX provisioning cycle anyway,
# and the durable route is the site's custom 3CX template (see
# Get-VqTemplateLines).
#
# The servlet pages that carry these settings are NOT documented by Yealink. The
# paths below are the best leads available, and the raw capture of whatever comes
# back is the real deliverable until they have been confirmed on a real phone.
# ---------------------------------------------------------------------------

function Get-YealinkVqProbePath {
    # Candidate pages, fetched inside the already-authenticated session. None is
    # documented by Yealink; every one is a harmless GET.
    return @(
        # The Register page carries the outbound-proxy settings, which decide
        # whether a collector could ever receive reports (see Get-VqReadiness).
        '/servlet?m=mod_data&p=account-register&q=load',
        # Seen in a third-party Yealink web client.
        '/servlet?m=mod_data&p=settings-voicemonitoring&q=load',
        # The variant given in the VQ-RTCPXR note.
        '/servlet?m=mod_data&p=settings-voice_monitoring&q=load',
        # Guess: Account > Advanced holds the per-account collector address.
        '/servlet?m=mod_data&p=account-adv&q=load',
        # Guess: Settings > Auto Provision holds custom.protect.
        '/servlet?m=mod_data&p=settings-autop&q=load',
        # Guess: Status > RTP Status holds the last call's metrics.
        '/servlet?m=mod_data&p=status-rtp&q=load'
    )
}

function Get-VqKeyValue {
    # Finds one config key in whatever format the phone returned it - JSON-ish
    # "key":"value", or cfg-style key = value - and returns its value.
    #
    # $null means the key is NOT PRESENT; '' means present but blank. The two must
    # never be conflated: "no collector set" is a finding, "collector not found in
    # the page" is only an absence of evidence.
    param([string]$Text,[string]$Key)
    if (-not $Text) { return $null }
    $q = '["' + [string][char]39 + ']'
    $pat = '(?i)(?<![A-Za-z0-9_])' + $q + '?(?:[A-Za-z0-9_]+\.)*' + $Key + $q + '?\s*[:=]\s*' + $q +
           '?([^"' + [string][char]39 + '\r\n,;}\]<]*)'
    $m = [regex]::Match($Text, $pat)
    if (-not $m.Success) { return $null }
    return $m.Groups[1].Value.Trim()
}

function ConvertTo-VqFlag {
    # '' = not found, '1' = on, '0' = off, 'default' = present but blank (Yealink
    # then applies its default, which for every VQ switch is off), '?' = present
    # with a value this does not recognise.
    param($Value)
    if ($null -eq $Value) { return '' }
    $v = ([string]$Value).Trim().ToLower()
    if ($v -eq '') { return 'default' }
    if (@('1','on','enabled','enable','true','yes') -contains $v)  { return '1' }
    if (@('0','off','disabled','disable','false','no') -contains $v) { return '0' }
    return '?'
}

function ConvertFrom-YealinkVq {
    # Pulls VQ-relevant settings and last-call metrics out of whatever the phone
    # returned. Best-effort by design: the response formats are undocumented, so
    # this only ever reports what it actually found, and says '' otherwise.
    param([string]$Text)
    $o = [pscustomobject]@{
        SessionReport      = ''
        IntervalReport     = ''
        ShowOnWeb          = ''
        ShowOnGui          = ''
        CollectorHost      = ''
        CollectorHostFound = $false
        CollectorPort      = ''
        OutboundProxy      = ''
        Protect            = ''
        MosLq              = ''
        MosCq              = ''
        Jitter             = ''
        PacketLoss         = ''
        Evidence           = @()
    }
    if (-not $Text) { return $o }
    $ev = [System.Collections.Generic.List[string]]::new()

    $o.SessionReport  = ConvertTo-VqFlag (Get-VqKeyValue -Text $Text -Key 'vq_rtcpxr[._]session_report[._]enable')
    $o.IntervalReport = ConvertTo-VqFlag (Get-VqKeyValue -Text $Text -Key 'vq_rtcpxr[._]interval_report[._]enable')
    $o.ShowOnWeb      = ConvertTo-VqFlag (Get-VqKeyValue -Text $Text -Key 'vq_rtcpxr[._]states_show_on_web[._]enable')
    $o.ShowOnGui      = ConvertTo-VqFlag (Get-VqKeyValue -Text $Text -Key 'vq_rtcpxr[._]states_show_on_gui[._]enable')
    $o.OutboundProxy  = ConvertTo-VqFlag (Get-VqKeyValue -Text $Text -Key 'outbound_proxy[._]enable')
    $o.Protect        = ConvertTo-VqFlag (Get-VqKeyValue -Text $Text -Key 'auto_provision[._]custom[._]protect')

    # The collector is per account (account.X.vq_rtcpxr.collector_server_host). The
    # first match is taken, which on a 3CX phone is the one registered account.
    $h = Get-VqKeyValue -Text $Text -Key 'vq_rtcpxr[._]collector_server_host'
    if ($null -ne $h) { $o.CollectorHostFound = $true; $o.CollectorHost = $h }
    $p = Get-VqKeyValue -Text $Text -Key 'vq_rtcpxr[._]collector_server_port'
    if ($null -ne $p -and $p -match '^\d{1,5}$') { $o.CollectorPort = $p }

    foreach ($f in @('SessionReport','IntervalReport','ShowOnWeb','ShowOnGui','OutboundProxy','Protect')) {
        if ($o.$f) { [void]$ev.Add(($f + '=' + $o.$f)) }
    }
    if ($o.CollectorHostFound) { [void]$ev.Add('CollectorHost=' + $(if ($o.CollectorHost) { $o.CollectorHost } else { '(blank)' })) }

    # Labels only prove the page exists on this firmware. A value is never inferred
    # from a label - that would be guessing.
    if ($Text -match '(?i)VQ\s*RTCP-?XR')  { [void]$ev.Add('page shows VQ RTCP-XR settings') }
    if ($Text -match '(?i)RTP\s*Status')   { [void]$ev.Add('page shows RTP Status') }

    # Last-call metrics, if an RTP status page returned any. MOS is range-checked
    # (1.0-5.0) so a stray number near the label cannot masquerade as a score - and
    # the WHOLE number is captured, because Yealink's MOS thresholds use a x10 scale
    # (e.g. 42): reading that as '4' would be a quietly wrong answer. Out of range
    # means not reported at all.
    $m = [regex]::Match($Text, '(?i)mos[\s_-]?lq[^0-9]{0,40}?([0-9]+(?:\.[0-9]+)?)')
    if ($m.Success) { $v = [double]$m.Groups[1].Value; if ($v -ge 1 -and $v -le 5) { $o.MosLq = $m.Groups[1].Value } }
    $m = [regex]::Match($Text, '(?i)mos[\s_-]?cq[^0-9]{0,40}?([0-9]+(?:\.[0-9]+)?)')
    if ($m.Success) { $v = [double]$m.Groups[1].Value; if ($v -ge 1 -and $v -le 5) { $o.MosCq = $m.Groups[1].Value } }
    # "Jitter" but not "JitterBuffer..." - a buffer size is not a jitter figure.
    $m = [regex]::Match($Text, '(?i)(?<![a-z_])jitter(?![\s_-]*buffer)[^0-9]{0,40}?([0-9]+(?:\.[0-9]+)?)')
    if ($m.Success) { $o.Jitter = $m.Groups[1].Value }
    $m = [regex]::Match($Text, '(?i)packet[\s_-]?loss(?:[\s_-]?rate)?[^0-9]{0,40}?([0-9]+(?:\.[0-9]+)?)')
    if ($m.Success) { $o.PacketLoss = $m.Groups[1].Value }
    if ($o.MosLq -or $o.MosCq) { [void]$ev.Add('last-call metrics found') }

    $o.Evidence = @($ev.ToArray())
    return $o
}

function Get-VqReadiness {
    # Turns what was found into a verdict. Every part says "unknown" when the
    # setting was not found - never "off".
    param($Vq)
    $o = [pscustomobject]@{
        Short          = 'not probed'
        Detail         = ''
        CollectorRoute = 'unknown'   # viable / blocked / unknown
        Reprovision    = 'unknown'   # overwrites / keeps / unknown
        Reporting      = 'unknown'   # on / off / unknown
    }
    if ($null -eq $Vq) { return $o }

    $parts  = [System.Collections.Generic.List[string]]::new()
    $detail = [System.Collections.Generic.List[string]]::new()

    # The outbound proxy is the single most decision-relevant fact. Yealink sends
    # VQ PUBLISH reports to the outbound proxy whenever one is enabled - its own
    # staff confirmed there is no way to change that - so on a 3CX phone the
    # reports would go to the PBX, which does not collect them.
    switch ($Vq.OutboundProxy) {
        '1'       { $o.CollectorRoute = 'blocked'
                    [void]$parts.Add('outbound proxy ON - collector blocked')
                    [void]$detail.Add('The outbound proxy is enabled, so Yealink would send any VQ report to the proxy (the PBX) rather than to a collector. A collector route cannot work on this phone as configured.') }
        { $_ -eq '0' -or $_ -eq 'default' } {
                    $o.CollectorRoute = 'viable'
                    [void]$parts.Add('no outbound proxy - collector viable')
                    [void]$detail.Add('No outbound proxy is enabled, so VQ reports would go straight to whatever collector is configured.') }
        default   { [void]$detail.Add('Outbound proxy setting not found, so whether a collector could receive reports is unknown.') }
    }

    switch ($Vq.SessionReport) {
        '1'       { $o.Reporting = 'on';  [void]$parts.Add('VQ reports on') }
        { $_ -eq '0' -or $_ -eq 'default' } { $o.Reporting = 'off'; [void]$parts.Add('VQ reports off') }
        default   { }
    }
    if ($Vq.ShowOnWeb -eq '1') { [void]$parts.Add('shown on web') }

    if ($Vq.CollectorHostFound) {
        if ($Vq.CollectorHost) {
            $c = $Vq.CollectorHost; if ($Vq.CollectorPort) { $c += (':' + $Vq.CollectorPort) }
            [void]$parts.Add('collector ' + $c)
            [void]$detail.Add('Collector configured: ' + $c + '.')
        } else {
            [void]$detail.Add('No VQ collector is configured.')
        }
    }

    switch ($Vq.Protect) {
        '1'       { $o.Reprovision = 'keeps'
                    [void]$detail.Add('custom.protect is on, so settings changed on the phone survive reprovisioning.') }
        { $_ -eq '0' -or $_ -eq 'default' } {
                    $o.Reprovision = 'overwrites'
                    [void]$detail.Add('custom.protect is off, so anything changed on the phone web UI is overwritten at the next 3CX provisioning cycle - enable VQ through the 3CX template instead.') }
        default   { }
    }

    if ($Vq.MosLq -or $Vq.MosCq -or $Vq.Jitter -or $Vq.PacketLoss) {
        $lc = ('last call: MOS-LQ {0}, MOS-CQ {1}, jitter {2}, loss {3}' -f
               $(if ($Vq.MosLq) { $Vq.MosLq } else { '?' }), $(if ($Vq.MosCq) { $Vq.MosCq } else { '?' }),
               $(if ($Vq.Jitter) { $Vq.Jitter } else { '?' }), $(if ($Vq.PacketLoss) { $Vq.PacketLoss } else { '?' }))
        [void]$parts.Add($lc)
        [void]$detail.Add('Measured by the phone itself on its last call: ' + $lc.Substring(11) + '.')
    }

    if (@($Vq.Evidence).Count -eq 0) {
        $o.Short  = 'VQ settings not readable on this firmware'
        $o.Detail = 'None of the candidate pages returned a VQ setting. The page paths are undocumented and differ by firmware; tick Save raw probe data and send the capture so the paths can be confirmed.'
        return $o
    }
    if (@($parts).Count -eq 0) { $o.Short = 'VQ pages found, no settings parsed' } else { $o.Short = (@($parts.ToArray()) -join '; ') }
    $o.Detail = (@($detail.ToArray()) -join ' ') + ' Evidence: ' + ((@($Vq.Evidence) -join ', ')) + '.'
    return $o
}

function Get-VqTemplateLines {
    # Lines for the site's custom 3CX phone template. This is how VQ gets switched
    # on - the tool itself never writes to a phone.
    #
    # Deliberately excluded:
    #   voice.rtcp_xr.enable   phone-to-phone RTCP-XR, not needed for this, and
    #                          older Yealink guides say changing it reboots the phone.
    #   collector host/port    a collector is not built yet, and 3CX advises against
    #                          hard-coding IPs in templates.
    $nl = [Environment]::NewLine
    return (@(
        '# --- VQ-RTCPXR: show last-call voice quality on the phone (web UI + LCD) ---',
        '# Paste into a COPIED 3CX phone template (Admin > Advanced > Templates), not',
        '# the base template, which 3CX overwrites. Phones pick it up at the next',
        '# provisioning cycle (about 24h) or on reprovision.',
        '# Read it on the phone: web UI Status > RTP Status, or Menu > Status > More > RTP.',
        '# Same parameters on every current Yealink model. The minimum set needed for',
        '# the web page to fill is unverified; these three are what Yealink documents.',
        'phone_setting.vq_rtcpxr.session_report.enable = 1',
        'phone_setting.vq_rtcpxr.states_show_on_web.enable = 1',
        'phone_setting.vq_rtcpxr.states_show_on_gui.enable = 1'
    ) -join $nl)
}

function Select-PhoneCreds {
    # The credentials for one phone: entries tagged with its IP or MAC. The Yealink
    # grid tags every password with its phone's MAC, so a phone only ever receives
    # the password typed against it. Untagged entries (none come from the grid) are
    # still capped at $MaxGeneral, because every wrong password counts towards the
    # phone's web-login lock-out.
    param($CredList,[string]$Ip,[string]$Mac,[int]$MaxGeneral = 3)
    $macN = ($Mac -replace '[^0-9A-Fa-f]','').ToUpper()
    $specific = [System.Collections.Generic.List[object]]::new()
    $general  = [System.Collections.Generic.List[object]]::new()
    foreach ($c in @($CredList)) {
        if (-not $c.Id) { $general.Add($c); continue }
        $idIp  = $c.Id.Trim().ToUpper()
        $idMac = ($c.Id -replace '[^0-9A-Fa-f]','').ToUpper()
        if ($idIp -eq $Ip.ToUpper() -or ($idMac.Length -eq 12 -and $idMac -eq $macN)) { $specific.Add($c) }
    }
    foreach ($c in @($general | Select-Object -First $MaxGeneral)) { $specific.Add($c) }
    return @($specific.ToArray())
}

# ---------------------------------------------------------------------------
# Local SBC detection
# ---------------------------------------------------------------------------
# At these sites the SBC is a Raspberry Pi running the standalone 3CX SBC. The
# SIP OPTIONS sweep below finds *a* SIP responder; these helpers work out what
# it actually is, so the tool can say "Pi running Raspbian, SSH open" instead of
# "some SIP device".
# ---------------------------------------------------------------------------

function Get-OsFromSshBanner {
    # Coarse OS hint from an SSH identification string.
    #
    # Deliberately coarse, and deliberately only a hint: the banner is free text
    # that an administrator can change, and current Raspberry Pi OS (Bookworm)
    # reports itself as plain Debian now that Raspbian branding has been dropped.
    # So a Pi will often NOT say "Raspbian" - the MAC OUI is the stronger signal
    # for "this is a Pi", and this only answers "what is it running".
    param([string]$Banner)
    if (-not $Banner) { return '' }
    if ($Banner -match '(?i)raspbian')          { return 'Raspbian / Pi OS (32-bit)' }
    if ($Banner -match '(?i)ubuntu')            { return 'Ubuntu' }
    if ($Banner -match '(?i)\bdebian\b')        { return 'Debian (or 64-bit Pi OS)' }
    if ($Banner -match '(?i)for_windows')       { return 'Windows' }
    if ($Banner -match '(?i)dropbear')          { return 'Dropbear (embedded)' }
    if ($Banner -match '(?i)mikrotik|routeros|rosssh') { return 'RouterOS' }
    if ($Banner -match '(?i)cisco')             { return 'Cisco' }
    if ($Banner -match '(?i)openssh')           { return 'OpenSSH (distro not stated)' }
    return 'other'
}

function Get-SshBanner {
    # Reads the SSH identification string the server volunteers.
    #
    # RFC 4253 s4.2: the server sends its version string BEFORE the client sends
    # anything. So this is a plain TCP read - no authentication is attempted and
    # not one byte is sent to the host, which is what makes it safe to fire at a
    # customer's device without asking first.
    param([string]$ComputerName,[int]$Port = 22,[int]$TimeoutMs = 2000)
    $out = [pscustomobject]@{ Ok = $false; Banner = ''; Os = ''; Err = '' }
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        # Same async-connect-with-timeout shape as Test-TcpPort: a blocking
        # Connect() has no timeout short enough for a LAN sweep.
        $iar = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { $out.Err = 'connect timeout'; return $out }
        try { $client.EndConnect($iar) } catch { $out.Err = 'closed or refused'; return $out }
        if (-not $client.Connected) { $out.Err = 'not connected'; return $out }

        $stream = $client.GetStream()
        $stream.ReadTimeout = $TimeoutMs
        $buf = New-Object byte[] 512
        $n = 0
        try { $n = $stream.Read($buf, 0, $buf.Length) }
        catch { $out.Err = 'open, but sent no banner within the timeout'; return $out }
        if ($n -le 0) { $out.Err = 'closed without sending a banner'; return $out }

        $text  = [System.Text.Encoding]::ASCII.GetString($buf, 0, $n)
        $first = (($text -split "`n")[0]).Trim([char]13, [char]10, [char]32)
        if ($first -notmatch '^SSH-\d') {
            # Something is listening but it is not SSH. Say so rather than
            # reporting a banner - a TLS server on 22 must not read as a Pi.
            $out.Err = ('port {0} answered but did not identify as SSH' -f $Port)
            return $out
        }
        $out.Banner = $first
        $out.Os     = Get-OsFromSshBanner -Banner $first
        $out.Ok     = $true
    } catch {
        $out.Err = $_.Exception.Message
    } finally { try { $client.Close() } catch {} }
    return $out
}

# ---------------------------------------------------------------------------
# SSH access to the SBC
# ---------------------------------------------------------------------------
# Two tiers, because they have different dependencies:
#
#   Interactive terminal  - ssh.exe (ships with Windows) or putty.exe if present.
#                           The user types the password into the real client, so
#                           this tool never handles it. Always available.
#   Captured in the GUI   - plink only. OpenSSH reads the password from the
#                           console rather than stdin, so it cannot be driven
#                           non-interactively with a password. This tier is an
#                           enhancement that appears when plink is found.
#
# The GUI must never gate the terminal behind "install something first".
# ---------------------------------------------------------------------------

function Get-SshToolDir {
    # Shared with the UniFi troubleshooter deliberately: a tech who fetched plink
    # for that tool already has it here, and the other way round.
    return 'C:\temp'
}

function Test-TrustedBinary {
    # A valid Authenticode signature - from $Publisher when one is named - or no.
    # Covers catalog-signed Windows binaries (OpenSSH in System32) as well as
    # embedded signatures (PuTTY is signed "CN=Simon Tatham").
    param([string]$Path,[string]$Publisher = '')
    $o = [pscustomobject]@{ Ok = $false; Reason = '' }
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { $o.Reason = 'not found'; return $o }
    try {
        $s = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        if ([string]$s.Status -ne 'Valid') { $o.Reason = ('signature ' + [string]$s.Status); return $o }
        $subj = [string]$s.SignerCertificate.Subject
        if ($Publisher -and $subj -notmatch ('(^|,\s*)CN=' + [regex]::Escape($Publisher) + '(,|$)')) {
            $o.Reason = ('signed by ' + ($subj -replace '^.*?CN=([^,]+).*$', '$1') + ', not ' + $Publisher)
            return $o
        }
        $o.Ok = $true
    } catch { $o.Reason = $_.Exception.Message }
    return $o
}

function Find-SshClient {
    # Cascade per binary: Program Files -> shared tool dir -> PATH, and a binary is
    # used only if it is validly signed by its publisher (PuTTY: Simon Tatham; the
    # OpenSSH in System32: Microsoft Windows).
    #
    # Why both: the shared tool dir is C:\temp, which every authenticated user can
    # write to (ProgramData subfolders are no better). A plink.exe dropped there
    # used to run the moment the GUI opened ('plink -V' below), and was later
    # handed the SSH and sudo passwords. Program Files is admin-only, so it is
    # looked at first, and the signature check stops a planted copy wherever it
    # sits. Anything refused is listed in Rejected so the UI can say why.
    #
    # ssh.exe matters most - it ships with Windows 10 1803+, so it is the path that
    # works with nothing installed.
    $out = [pscustomobject]@{ Ssh = ''; Putty = ''; Plink = ''; PlinkVersion = ''; PwFileOk = $false; Rejected = @() }
    $rej = [System.Collections.Generic.List[string]]::new()
    $dir = Get-SshToolDir
    foreach ($e in @('putty','plink')) {
        $cands = [System.Collections.Generic.List[string]]::new()
        foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) { if ($root) { [void]$cands.Add((Join-Path $root ('PuTTY\' + $e + '.exe'))) } }
        if ($dir) { [void]$cands.Add((Join-Path $dir ($e + '.exe'))) }
        try { foreach ($cmd in @(Get-Command ($e + '.exe') -All -ErrorAction Stop)) { if ($cmd.Source) { [void]$cands.Add($cmd.Source) } } } catch {}
        $found = ''
        $seen = @{}
        foreach ($c in $cands) {
            $k = $c.ToLowerInvariant()
            if ($seen.ContainsKey($k)) { continue }
            $seen[$k] = $true
            if (-not (Test-Path -LiteralPath $c -PathType Leaf)) { continue }
            $t = Test-TrustedBinary -Path $c -Publisher 'Simon Tatham'
            if ($t.Ok) { $found = $c; break }
            [void]$rej.Add(($c + ' (' + $t.Reason + ')'))
        }
        if ($e -eq 'putty') { $out.Putty = $found } else { $out.Plink = $found }
    }

    $sysSsh = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
    if (Test-Path -LiteralPath $sysSsh) {
        $t = Test-TrustedBinary -Path $sysSsh -Publisher 'Microsoft Windows'
        if ($t.Ok) { $out.Ssh = $sysSsh } else { [void]$rej.Add(($sysSsh + ' (' + $t.Reason + ')')) }
    }
    if (-not $out.Ssh) {
        # Another ssh.exe on PATH (Git for Windows, say): any valid publisher, but
        # never an unsigned one.
        try {
            foreach ($cmd in @(Get-Command 'ssh.exe' -All -ErrorAction Stop)) {
                if (-not $cmd.Source -or $cmd.Source -ieq $sysSsh) { continue }
                $t = Test-TrustedBinary -Path $cmd.Source
                if ($t.Ok) { $out.Ssh = $cmd.Source; break }
                [void]$rej.Add(($cmd.Source + ' (' + $t.Reason + ')'))
            }
        } catch {}
    }
    $out.Rejected = @($rej.ToArray())

    # -pwfile needs PuTTY 0.77+. Established up front so the UI can say what it
    # can and cannot do before a password is typed into it.
    if ($out.Plink) {
        try {
            $v = (& $out.Plink '-V' 2>&1 | Select-Object -First 1)
            $out.PlinkVersion = [string]$v
            $m = [regex]::Match($out.PlinkVersion, '(?i)release\s+(\d+)\.(\d+)')
            if ($m.Success) {
                $maj = [int]$m.Groups[1].Value; $min = [int]$m.Groups[2].Value
                $out.PwFileOk = (($maj -gt 0) -or ($maj -eq 0 -and $min -ge 77))
            }
        } catch {}
    }
    return $out
}

function Test-SshHostName {
    # Accepts only what a hostname or IPv4 address can contain.
    #
    # The host is written into a .cmd launcher (Start-SshTerminal) and into
    # plink's argument string (Invoke-PlinkCommand). Anything a shell would act on
    # - & | ; < > ^ % quotes spaces - must never get through, or a value like
    # "1.2.3.4 & calc" runs a command in the launched console. A leading hyphen is
    # refused as well: ssh and plink would parse it as an OPTION, which is how
    # "-oProxyCommand=..." style argument injection works.
    param([string]$Value)
    if (-not $Value) { return $false }
    if ($Value -notmatch '^[A-Za-z0-9.-]{1,253}$') { return $false }
    if ($Value -match '^[.-]') { return $false }
    return $true
}

function Test-SshUserName {
    # Same reasoning as Test-SshHostName: the user name lands in the launcher's
    # "user@host" token and in plink's -l argument.
    param([string]$Value)
    if (-not $Value) { return $false }
    if ($Value -notmatch '^[A-Za-z0-9._-]{1,32}$') { return $false }
    if ($Value -match '^-') { return $false }
    return $true
}

function Start-SshTerminal {
    # Opens a real terminal. Host and user only - a password on a client command
    # line would sit in the process list for anyone on this box to read.
    param([string]$ComputerName,[string]$User,[int]$Port = 22,$Clients = $null)
    if (-not $ComputerName) { throw 'No host given.' }
    if (-not $User) { throw 'No SSH user given.' }
    if (-not (Test-SshHostName $ComputerName)) { throw ('Not a valid host name or IP address: ' + $ComputerName) }
    if (-not (Test-SshUserName $User)) { throw ('Not a valid SSH user name: ' + $User + ' - letters, digits, dot, underscore and hyphen only, and not starting with a hyphen.') }
    if ($null -eq $Clients) { $Clients = Find-SshClient }

    # Checked again at launch, not just when the GUI opened: a binary in the shared
    # tool dir can be swapped in between.
    if ($Clients.Putty) {
        $t = Test-TrustedBinary -Path $Clients.Putty -Publisher 'Simon Tatham'
        if (-not $t.Ok) { throw ('Refusing to run ' + $Clients.Putty + ': ' + $t.Reason + '.') }
        $a = @('-ssh', ('{0}@{1}' -f $User, $ComputerName), '-P', [string]$Port)
        [void](Start-Process -FilePath $Clients.Putty -ArgumentList $a)
        return ('putty.exe -> {0}@{1}:{2}' -f $User, $ComputerName, $Port)
    }
    if ($Clients.Ssh) {
        $t = Test-TrustedBinary -Path $Clients.Ssh
        if (-not $t.Ok) { throw ('Refusing to run ' + $Clients.Ssh + ': ' + $t.Reason + '.') }
        # Launched through a tiny throwaway .cmd rather than by handing a command
        # line to cmd.exe. Two reasons:
        #   * Quoting. The cmd /k ""prog" args" idiom is fragile once the client
        #     path contains a space - measured, it mangles into '""C:\Program'.
        #     Inside a batch file the quoting is written by .NET and cannot be
        #     re-parsed by a shell on the way there.
        #   * The window has to outlive the session, or a refused connection
        #     prints the reason and vanishes before the technician can read it.
        # The script deletes itself on the way out, so nothing accumulates.
        $tmp = Join-Path $env:TEMP ('3cx-ssh-' + [guid]::NewGuid().ToString('N').Substring(0,8) + '.cmd')
        $q = [string][char]34
        $lines = @(
            '@echo off',
            ('title SSH {0}@{1}' -f $User, $ComputerName),
            ($q + $Clients.Ssh + $q + (' -p {0} {1}@{2}' -f $Port, $User, $ComputerName)),
            'echo.',
            'echo [session ended - press a key to close]',
            'pause >nul',
            ('del ' + $q + '%~f0' + $q)
        )
        [System.IO.File]::WriteAllLines($tmp, $lines, (New-Object System.Text.ASCIIEncoding))
        [void](Start-Process -FilePath $tmp)
        return ('ssh.exe -> {0}@{1}:{2}' -f $User, $ComputerName, $Port)
    }
    throw 'No SSH client found: Windows OpenSSH is absent and PuTTY is not installed.'
}

function Invoke-PlinkCommand {
    # Runs one command on the host and returns its output.
    #
    # -pwfile, never -pw. -pw puts the password in the command line, where the
    # process list exposes it to every user on this machine; -pwfile is what makes
    # this usable at all. An older plink is TOLD so rather than being silently
    # downgraded to -pw, which would quietly defeat the point.
    #
    # The password file goes in LOCALAPPDATA with an owner-only ACL. The reference
    # implementation puts it in ProgramData, which is world-readable by default -
    # short-lived, but needlessly readable for as long as it exists.
    #
    # The host key is accepted by answering "y" on stdin. -batch is deliberately
    # NOT used: it aborts on an unknown host key, and a customer's SBC is unknown
    # on first contact.
    param(
        [string]$PlinkPath,
        [string]$ComputerName,
        [string]$User,
        [string]$Password,
        [string]$Command,
        [int]$Port = 22,
        [int]$TimeoutMs = 30000,
        [switch]$Sudo
    )
    $out = [pscustomobject]@{ Command = $Command; Output = ''; Error = ''; ExitCode = -1; Ok = $false }
    if (-not $PlinkPath -or -not (Test-Path -LiteralPath $PlinkPath)) { $out.Error = 'plink.exe was not found.'; return $out }
    # Re-checked right before it is handed a password - see Find-SshClient.
    $tb = Test-TrustedBinary -Path $PlinkPath -Publisher 'Simon Tatham'
    if (-not $tb.Ok) { $out.Error = ('Refusing to run ' + $PlinkPath + ': ' + $tb.Reason + '. Use a PuTTY signed by Simon Tatham, ideally installed in Program Files.'); return $out }
    if (-not $ComputerName) { $out.Error = 'No host given.'; return $out }
    if (-not (Test-SshHostName $ComputerName)) { $out.Error = ('Not a valid host name or IP address: ' + $ComputerName); return $out }
    if (-not (Test-SshUserName $User)) { $out.Error = ('Not a valid SSH user name: ' + $User); return $out }
    if (-not $Command)      { $out.Error = 'No command given.'; return $out }

    # The argument string is wrapped in quotes but not escaped, so a command
    # containing a double quote would break parsing. Refuse rather than mangle.
    if ($Command.IndexOf([char]34) -ge 0) {
        $out.Error = 'Command contains a double quote, which cannot be passed safely here. Use single quotes.'
        return $out
    }

    # Raspberry Pi OS 6.2 (Trixie) disables passwordless sudo on new installs, and
    # the current 3CX SBC guide points at Trixie - so a plain 'sudo' command can sit
    # waiting for a prompt that a captured session never answers.
    #
    # sudo -S reads the password from STDIN (unlike ssh, which insists on a tty),
    # so the password goes down the pipe we already have open for the host key
    # rather than onto a command line. That keeps it out of the process list on
    # BOTH machines - piping it via printf on the remote would expose it in the
    # SBC's own process table.
    $remote = $Command
    if ($Sudo) { $remote = ('sudo -S -p ' + [string][char]39 + [string][char]39 + ' ' + $Command) }

    $pwFile = $null
    $proc = $null
    try {
        $dir = Join-Path $env:LOCALAPPDATA '3CX-Checker'
        if (-not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop) }
        $pwFile = Join-Path $dir ('.pw-' + [guid]::NewGuid().ToString('N'))
        # ASCII, no BOM - plink reads the file literally.
        [System.IO.File]::WriteAllText($pwFile, [string]$Password, (New-Object System.Text.ASCIIEncoding))
        try {
            $acl = Get-Acl -LiteralPath $pwFile
            $acl.SetAccessRuleProtection($true, $false)          # drop inheritance
            foreach ($r in @($acl.Access)) { [void]$acl.RemoveAccessRule($r) }
            $me   = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($me, 'FullControl', 'Allow')
            $acl.AddAccessRule($rule)
            Set-Acl -LiteralPath $pwFile -AclObject $acl
        } catch {
            # Could not lock it down, so do not use it. A readable password file
            # is worse than a command that did not run.
            $out.Error = 'Could not restrict permissions on the temporary password file, so it was not used: ' + $_.Exception.Message
            return $out
        }

        $q = [string][char]34
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName  = $PlinkPath
        $psi.Arguments = (@('-ssh','-P',[string]$Port,'-l',$User,'-pwfile',($q + $pwFile + $q),$ComputerName,($q + $remote + $q)) -join ' ')
        $psi.UseShellExecute        = $false
        $psi.CreateNoWindow         = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true
        $psi.RedirectStandardInput  = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        try { $proc.StandardInput.WriteLine('y') } catch {}          # accept the host key
        if ($Sudo) { try { $proc.StandardInput.WriteLine([string]$Password) } catch {} }
        try { $proc.StandardInput.Close() } catch {}

        # Async reads started BEFORE WaitForExit. A synchronous ReadToEnd on both
        # streams before waiting is the classic deadlock: the child blocks writing
        # into a full pipe while the parent blocks waiting for it to exit.
        $so = $proc.StandardOutput.ReadToEndAsync()
        $se = $proc.StandardError.ReadToEndAsync()
        if (-not $proc.WaitForExit($TimeoutMs)) {
            try { $proc.Kill() } catch {}
            $out.Error = ('plink did not finish within {0}s - check the IP, that SSH is reachable, and the credentials.' -f [int]($TimeoutMs / 1000))
            return $out
        }
        $out.Output   = [string]$so.Result
        $out.Error    = [string]$se.Result
        $out.ExitCode = $proc.ExitCode
        $out.Ok       = ($proc.ExitCode -eq 0)
        if ($out.Error -match '(?i)pwfile|unknown option|unrecognised') {
            $out.Error += ([Environment]::NewLine +
                'This plink build does not support -pwfile (PuTTY 0.77+ required). Open the SSH terminal and paste the command instead - falling back to -pw would put the password in the process list.')
        }
    } catch {
        $out.Error = $_.Exception.Message
    } finally {
        if ($proc) { try { $proc.Dispose() } catch {} }
        if ($pwFile -and (Test-Path -LiteralPath $pwFile)) {
            Remove-Item -LiteralPath $pwFile -Force -ErrorAction SilentlyContinue
        }
    }
    return $out
}

function Get-ArpHosts {
    # Every live IPv4 host in the ARP cache (excludes multicast / broadcast).
    # A Type is required: that is what separates a real cache entry from a stray
    # line, and it was implicit in the regex this function used to carry.
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($a in (Get-ArpTable)) {
        if (-not $a.Unicast) { continue }
        if (-not $a.Type)    { continue }
        $out.Add($a.IP)
    }
    return @($out.ToArray() | Select-Object -Unique)
}

function Invoke-SipSweep {
    # Fire a SIP OPTIONS at every host from one socket, then collect replies for
    # WaitMs. A 3CX SBC/PBX answers with a 3CX User-Agent; phones answer as Yealink.
    param([string[]]$Hosts,[int]$Port = 5060,[int]$WaitMs = 4000)
    $out = [System.Collections.Generic.List[object]]::new()
    if (@($Hosts).Count -eq 0) { return @($out.ToArray()) }
    $udp = New-Object System.Net.Sockets.UdpClient
    try {
        $udp.Client.Bind((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)))
        $lport = ([System.Net.IPEndPoint]$udp.Client.LocalEndPoint).Port
        $lip = '0.0.0.0'
        try {
            $s = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Dgram, [System.Net.Sockets.ProtocolType]::Udp)
            $s.Connect($Hosts[0], 9); $lip = ([System.Net.IPEndPoint]$s.LocalEndPoint).Address.ToString(); $s.Close()
        } catch {}
        foreach ($h in $Hosts) {
            try {
                $ids = New-SipProbeIds -LocalIp $lip
                $msg = New-SipOptionsMessage -TargetHost $h -LocalIp $lip -LocalPort $lport -Branch $ids.Branch -CallId $ids.CallId -Tag $ids.Tag
                $bytes = [System.Text.Encoding]::ASCII.GetBytes($msg)
                [void]$udp.Send($bytes, $bytes.Length, $h, $Port)
            } catch {}
        }
        $seen = @{}
        $udp.Client.ReceiveTimeout = 400
        $buf = New-Object byte[] 8192
        $deadline = [DateTime]::UtcNow.AddMilliseconds($WaitMs)
        while ([DateTime]::UtcNow -lt $deadline) {
            try {
                # ReceiveFrom reliably yields the sender endpoint (UdpClient.Receive
                # returns 0.0.0.0 for an unconnected socket under PowerShell).
                $ep = [System.Net.EndPoint](New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0))
                $n = $udp.Client.ReceiveFrom($buf, [ref]$ep)
                $ipr = ([System.Net.IPEndPoint]$ep).Address.ToString()
                if ($seen.ContainsKey($ipr)) { continue }
                $seen[$ipr] = $true
                $text = [System.Text.Encoding]::ASCII.GetString($buf, 0, $n)
                $ua = ''
                $mm = [regex]::Match($text, '(?im)^(?:User-Agent|Server):\s*(.+?)\s*$')
                if ($mm.Success) { $ua = $mm.Groups[1].Value.Trim() }
                $first = ($text.Split([char]10))[0].Trim()
                # 3CX presents no User-Agent, but its OPTIONS reply carries a
                # distinctive header signature.
                $matched = ''
                if     ($ua -match '(?i)3cx')                                 { $matched = 'user-agent' }
                elseif ($text -match '(?im)^Allow-Events:.*line-seize')       { $matched = 'line-seize' }
                elseif ($text -match '(?im)^Supported:\s*replaces,\s*timer') { $matched = 'supported-header' }
                # The SBC names itself in a Record-Route - conclusive, and it also
                # tells us which PBX it forwards to (see ConvertFrom-SipSbcReply).
                $sbc = ConvertFrom-SipSbcReply -Text $text -ProbedIp $ipr
                if ($sbc.SbcMarker) { $matched = 'Record-Route 3CXSBC' }
                $is3cx = [bool]$matched
                $type = if ($sbc.SbcMarker)           { '3CX SBC' }
                        elseif ($ua -match '(?i)yealink') { 'Yealink phone' }
                        elseif ($is3cx)               { '3CX (SBC or PBX)' }
                        else                          { 'SIP device' }
                # The whole reply is kept (capped) for the raw capture: the string
                # line-seize never appears in the 3CX SBC binary, so seeing exactly
                # which headers a real SBC sends is what tells us whether it answers
                # OPTIONS itself or relays the PBX's reply through the tunnel.
                $rawReply = $text
                if ($rawReply.Length -gt 4000) { $rawReply = $rawReply.Substring(0, 4000) + '...[truncated]' }
                $out.Add([pscustomobject]@{ IP = $ipr; Type = $type; UserAgent = $ua; Response = $first; Matched = $matched; Raw = $rawReply
                                            SbcMarker = $sbc.SbcMarker; TunnelId = $sbc.TunnelId; ForwardsTo = $sbc.ForwardsTo })
            } catch [System.Net.Sockets.SocketException] { }
        }
    } catch {} finally { try { $udp.Close() } catch {} }
    return @($out.ToArray())
}

function Get-TtlFingerprint {
    # Coarse OS tell from the reply TTL. Initial TTL is 64 on Linux/Unix and most
    # embedded stacks, 128 on Windows, 255 on a lot of network gear, so the value
    # observed 0-1 hops away is essentially the initial one.
    #
    # ONLY valid for on-link hosts, and this is called only for addresses that came
    # out of the ARP table, which are on-link by definition. Measured over 12 hops,
    # 8.8.8.8 returns TTL 116, which this would read as Windows - so do not point it
    # at anything off the LAN.
    #
    # PingReply.Options is NULL whenever Status is not Success, so reading .Ttl
    # without the guard throws. Confirmed on a timed-out reply.
    param([string]$ComputerName,[int]$TimeoutMs = 800,[int]$Retries = 1)
    $out = [pscustomobject]@{ Ok = $false; Ttl = 0; Guess = '' }
    $ping = New-Object System.Net.NetworkInformation.Ping
    try {
        for ($try = 0; $try -le $Retries; $try++) {
            $r = $null
            try { $r = $ping.Send($ComputerName, $TimeoutMs) } catch { continue }
            if ($null -eq $r) { continue }
            if ($r.Status -ne [System.Net.NetworkInformation.IPStatus]::Success) { continue }
            if ($null -eq $r.Options) { continue }
            $ttl = [int]$r.Options.Ttl
            if ($ttl -le 0) { continue }
            $out.Ok = $true
            $out.Ttl = $ttl
            if     ($ttl -ge 200) { $out.Guess = 'network appliance' }
            elseif ($ttl -ge 100) { $out.Guess = 'Windows' }
            elseif ($ttl -ge 40)  { $out.Guess = 'Linux/Unix' }
            break
        }
    } catch { } finally { try { $ping.Dispose() } catch {} }
    return $out
}

function Get-WindowsPortHint {
    # 445/3389/135 answering is close to conclusive for Windows.
    #
    # This exists specifically because the 3CX SBC on Windows has no SSH server,
    # so the banner grab - the tool's normal way of naming an OS - returns nothing
    # for exactly the platform that most needs identifying.
    param([string]$ComputerName,[int]$TimeoutMs = 600)
    $hits = [System.Collections.Generic.List[string]]::new()
    foreach ($p in @(
        [pscustomobject]@{ Port = 445;  Name = 'SMB' },
        [pscustomobject]@{ Port = 3389; Name = 'RDP' },
        [pscustomobject]@{ Port = 135;  Name = 'RPC' }
    )) {
        $t = Test-TcpPort -ComputerName $ComputerName -Port ([int]$p.Port) -TimeoutMs $TimeoutMs
        if ($t.Open) { [void]$hits.Add(('{0} ({1})' -f $p.Port, $p.Name)) }
    }
    return @($hits.ToArray())
}

function Resolve-HostPlatform {
    # Names the platform outright rather than leaving it to be inferred from an OS
    # string. It matters because 3CX supports the SBC on Raspberry Pi, on Debian
    # and on Windows, and the Windows one runs no SSH server - so knowing which it
    # is tells you whether the SSH features apply at all.
    param(
        [string]$Vendor = '',
        [string]$Os = '',
        [string[]]$WindowsPorts = @(),
        [string]$TtlGuess = ''
    )
    $o = [pscustomobject]@{ Platform = 'unknown'; Basis = '' }

    # Strongest first: an SSH banner or a vendor MAC beats a fingerprint.
    if ($Vendor -eq 'Raspberry Pi')  { $o.Platform = 'Raspberry Pi (Linux)'; $o.Basis = 'MAC is a registered Raspberry Pi assignment'; return $o }
    if ($Os -like 'Raspbian*')       { $o.Platform = 'Raspberry Pi (Linux)'; $o.Basis = 'SSH banner';  return $o }
    if ($Os -like 'Debian*')         { $o.Platform = 'Linux';               $o.Basis = 'SSH banner';  return $o }
    if ($Os -eq 'Ubuntu')            { $o.Platform = 'Linux';               $o.Basis = 'SSH banner';  return $o }
    if ($Os -eq 'Windows')           { $o.Platform = 'Windows';             $o.Basis = 'SSH banner';  return $o }
    if ($Os -eq 'RouterOS' -or $Os -like 'Dropbear*' -or $Os -eq 'Cisco') {
        $o.Platform = 'network appliance'; $o.Basis = 'SSH banner'; return $o
    }
    if ($Vendor -eq 'Yealink')       { $o.Platform = 'Yealink phone';       $o.Basis = 'MAC is a Yealink assignment'; return $o }

    if (@($WindowsPorts).Count -gt 0) {
        $o.Platform = 'Windows'
        $o.Basis    = ('Windows service ports answering: ' + ((@($WindowsPorts) -join ', ')))
        return $o
    }
    if ($Os -eq 'OpenSSH (distro not stated)') { $o.Platform = 'Linux/Unix'; $o.Basis = 'OpenSSH banner with no distro'; return $o }
    if ($TtlGuess) {
        $o.Platform = $TtlGuess
        $o.Basis    = 'reply TTL (on-link fingerprint, coarse)'
        return $o
    }
    return $o
}

function Get-SbcPortProfile {
    # The port profile is the cleanest SBC-vs-PBX discriminator there is, and it
    # needs no login at all. Verified against 3CX's own Debian package and their
    # firewall documentation:
    #
    #   SBC : binds 5060 only. It has NO web endpoint whatsoever - the package is
    #         ten files and pulls in neither a web server nor any web assets - and
    #         it DIALS OUT to the PBX on 5090 rather than listening on it.
    #   PBX : 5060 + 5061 (SIP TLS) + 443 and/or 5001 (web console) + 5090
    #         (tunnel, inbound).
    #
    # So "answers SIP as 3CX and has nothing on 443/5001/5061/5090" is a strong
    # SBC call, and any of those being open points at a full PBX instead.
    return @(
        [pscustomobject]@{ Port = 22;   Name = 'SSH';            Role = 'admin' },
        [pscustomobject]@{ Port = 5060; Name = 'SIP/TCP';        Role = 'both'  },
        [pscustomobject]@{ Port = 443;  Name = 'HTTPS console';  Role = 'pbx'   },
        [pscustomobject]@{ Port = 5001; Name = 'HTTPS alt';      Role = 'pbx'   },
        [pscustomobject]@{ Port = 5061; Name = 'SIP/TLS';        Role = 'pbx'   },
        [pscustomobject]@{ Port = 5090; Name = 'tunnel inbound'; Role = 'pbx'   }
    )
}

function Test-SbcCandidate {
    # Gathers the corroborating signals for one LAN host and states how likely it
    # is to be the local 3CX SBC, on what platform, and what else it is doing.
    #
    # Confidence is a stated judgement with its reasons attached, not a boolean.
    # The SIP signature alone cannot separate an SBC from a full PBX - the sweep
    # has always said "3CX (SBC or PBX)" and that honesty is kept - but the port
    # profile CAN, and it is the signal doing most of the work here.
    param(
        [string]$Ip,
        $SipRow    = $null,     # the row Invoke-SipSweep produced, if any
        $ArpRow    = $null,     # the row Get-ArpTable produced, if any
        $Roles     = @(),       # rows from Get-NetworkRoles, to spot a phone acting as gateway
        [string[]]$PhoneIps = @(),
        [int]$TimeoutMs = 700,
        [switch]$SkipPorts
    )
    $out = [pscustomobject]@{
        IP           = $Ip
        MAC          = ''
        Vendor       = ''
        Hostname     = ''
        Platform     = 'unknown'
        PlatformBasis= ''
        SshOpen      = $false
        SshBanner    = ''
        Os           = ''
        Ttl          = 0
        OpenPorts    = ''
        PbxPorts     = ''
        WinPorts     = ''
        SipType      = ''
        SipUserAgent = ''
        SipMatched   = ''
        RoleLabel    = ''
        IsKnownPhone = $false
        IsRouterPhone= $false          # a phone acting as the network's gateway/DHCP - a fault
        Is3cxRouterPhone = $false      # a phone doing an SBC's job for 3CX - a role
        SbcMarker    = $false          # its reply named it 3CXSBC: the 3CX SBC code, conclusively
        TunnelId     = ''
        ForwardsTo   = ''              # the PBX its tunnel leads to, from the reply's To header
        ForwardsMismatch = $false      # set by the caller when that is not the PBX under test
        Confidence   = 'unlikely'
        Detail       = ''
    }
    if (-not $Ip) { return $out }

    if ($ArpRow) {
        $out.MAC    = [string]$ArpRow.MAC
        $out.Vendor = [string]$ArpRow.Vendor
    }
    if ($SipRow) {
        $out.SipType      = [string]$SipRow.Type
        $out.SipUserAgent = [string]$SipRow.UserAgent
        if ($SipRow.PSObject.Properties['Matched'])    { $out.SipMatched = [string]$SipRow.Matched }
        if ($SipRow.PSObject.Properties['SbcMarker'])  { $out.SbcMarker  = [bool]$SipRow.SbcMarker }
        if ($SipRow.PSObject.Properties['TunnelId'])   { $out.TunnelId   = [string]$SipRow.TunnelId }
        if ($SipRow.PSObject.Properties['ForwardsTo']) { $out.ForwardsTo = [string]$SipRow.ForwardsTo }
    }
    $fwdTxt = ''
    if ($out.ForwardsTo) {
        $fwdTxt = (' It forwards to the PBX ' + $out.ForwardsTo)
        if ($out.TunnelId) { $fwdTxt += (' (tunnel ' + $out.TunnelId + ')') }
        $fwdTxt += '.'
    }
    $out.IsKnownPhone = ($PhoneIps -contains $Ip)
    $out.Hostname = Resolve-PtrName -Ip $Ip -TimeoutMs 500

    # What roles does this host fill on the network? Reused from the Network tab
    # rather than recomputed.
    $myRoles = @(@($Roles) | Where-Object { $_ -and [string]$_.IP -eq $Ip })
    if (@($myRoles).Count -gt 0) {
        $out.RoleLabel = ((@($myRoles) | ForEach-Object { [string]$_.Role }) -join ' + ')
    }

    # SSH banner first: it both proves 22 is reachable and names the OS, and it
    # sends nothing, so it never shows up in the device's auth log.
    $b = Get-SshBanner -ComputerName $Ip -Port 22 -TimeoutMs $TimeoutMs
    if ($b.Ok) {
        $out.SshOpen   = $true
        $out.SshBanner = $b.Banner
        $out.Os        = $b.Os
    }

    $portsProbed = $false
    $pbxOpen = [System.Collections.Generic.List[string]]::new()
    $winHints = @()
    if (-not $SkipPorts) {
        $portsProbed = $true
        $open = [System.Collections.Generic.List[string]]::new()
        if ($out.SshOpen) { [void]$open.Add('22 (SSH)') }
        foreach ($p in (Get-SbcPortProfile)) {
            if ([int]$p.Port -eq 22) { continue }      # already established above
            $t = Test-TcpPort -ComputerName $Ip -Port ([int]$p.Port) -TimeoutMs $TimeoutMs
            if (-not $t.Open) { continue }
            [void]$open.Add(('{0} ({1})' -f $p.Port, $p.Name))
            if ($p.Role -eq 'pbx') { [void]$pbxOpen.Add(('{0} ({1})' -f $p.Port, $p.Name)) }
        }
        $out.OpenPorts = (@($open.ToArray()) -join ', ')
        $out.PbxPorts  = (@($pbxOpen.ToArray()) -join ', ')

        # Only when SSH did not name the OS - which is precisely the Windows SBC
        # case, since it runs no SSH server.
        if (-not $out.Os) {
            $winHints = @(Get-WindowsPortHint -ComputerName $Ip -TimeoutMs $TimeoutMs)
            $out.WinPorts = (@($winHints) -join ', ')
        }
    }

    # Cheap, and the only OS signal available on a host with neither SSH nor an
    # open Windows port. Safe here because every candidate came from the ARP table
    # and is therefore on-link.
    $ttl = Get-TtlFingerprint -ComputerName $Ip -TimeoutMs 700
    if ($ttl.Ok) { $out.Ttl = $ttl.Ttl }

    $plat = Resolve-HostPlatform -Vendor $out.Vendor -Os $out.Os -WindowsPorts $winHints -TtlGuess $ttl.Guess
    $out.Platform      = $plat.Platform
    $out.PlatformBasis = $plat.Basis

    # ---- weigh it up -------------------------------------------------------
    $why   = [System.Collections.Generic.List[string]]::new()
    $score = 0

    # A phone acting as the default gateway or DHCP server is its own finding, and
    # a serious one - it is never the SBC, and it explains a lot of SIP weirdness.
    # Called out here as well as on the Network tab because this is the tab someone
    # opens when SIP is misbehaving.
    if ($out.Vendor -eq 'Yealink' -and $out.RoleLabel) {
        $out.IsRouterPhone = $true
        $out.Confidence = ('NOT an SBC - a phone is acting as the ' + $out.RoleLabel)
        $out.Detail = ('This IP is a Yealink handset and it is also the ' + $out.RoleLabel +
                       ' for this network. A phone should never be routing or handing out DHCP: it explains erratic SIP and one-way audio, and it needs fixing before anything else here is worth reading.')
        return $out
    }

    # A Yealink that answers OPTIONS with the PBX's 3CX signature and WITHOUT its own
    # Yealink User-Agent is not answering for itself: every ordinary Yealink replies
    # as Yealink (that is how the sweep classifies phones). Seen on a real site on a
    # reception phone the customer described as the Router Phone - a phone that
    # carries other phones' traffic to the PBX, doing the SBC's job.
    if (($out.IsKnownPhone -or $out.Vendor -eq 'Yealink') -and ($out.SbcMarker -or ($out.SipType -like '3CX*' -and $out.SipUserAgent -notmatch '(?i)yealink'))) {
        $out.Is3cxRouterPhone = $true
        $out.Platform = 'Yealink phone - 3CX Router Phone'
        if ($out.SbcMarker) {
            $out.Confidence = '3CX Router Phone (confirmed - its reply names it 3CXSBC)'
            $d = 'This is a Yealink phone running the 3CX SBC: its SIP reply carried a Record-Route naming 3CXSBC, which is the SBC code itself. It relayed the probe through its tunnel and the PBX answered, so its link to the PBX was up when it was asked.' + $fwdTxt
        } else {
            $out.Confidence = 'likely a 3CX Router Phone (a phone doing the SBC''s job)'
            $m = $out.SipMatched; if (-not $m) { $m = 'the 3CX header signature' }
            $d = ('This is a Yealink phone, but it answered SIP OPTIONS with the PBX''s 3CX signature (matched on: {0}) and no Yealink User-Agent. Ordinary Yealink phones answer as themselves, so this one is passing SIP on to the PBX - what a Router Phone does. Confirm in the 3CX admin console.' -f $m)
            if ($out.SipMatched -eq 'line-seize') { $d += ' The reply carried line-seize, which the PBX generates, so this phone''s own link to the PBX was up when it was asked.' }
        }
        $d += ' If other phones register through it, it is a single point of failure: unplugging or rebooting it takes them all off the PBX. Logging in to the phones (Yealink tab) shows each phone''s SIP server - this IP means that phone goes through it.'
        if ($out.RoleLabel) { $d += (' It is also the ' + $out.RoleLabel + '.') }
        $out.Detail = $d
        return $out
    }

    if ($out.IsKnownPhone) {
        $out.Confidence = 'no - this is a discovered phone'
        $out.Detail     = 'This IP is one of the Yealink phones found on the LAN. Phones answer SIP OPTIONS too, so being a SIP responder does not make it an SBC.'
        if ($out.RoleLabel) { $out.Detail += (' It is also the ' + $out.RoleLabel + ' - worth checking, a phone should not be filling that role.') }
        return $out
    }

    $is3cx = ($out.SipType -like '3CX*')
    if ($is3cx)            { $score += 3; [void]$why.Add('answers SIP OPTIONS with the 3CX header signature') }
    elseif ($out.SipType)  { $score += 1; [void]$why.Add('answers SIP OPTIONS, but not as 3CX') }

    # Conclusive when present: the SBC names itself, and a full PBX answering for
    # itself adds no such Record-Route. It also overrides the port profile below -
    # a Windows box running the SBC can have 443 open for something else entirely.
    if ($out.SbcMarker) {
        $score += 5
        [void]$why.Add('its SIP reply names it 3CXSBC (a Record-Route added by the 3CX SBC code, never by a PBX answering for itself)')
    }

    # The port profile. This is the discriminator, so it carries the most weight.
    if ($portsProbed -and $is3cx -and -not $out.SbcMarker) {
        if (@($pbxOpen).Count -eq 0) {
            $score += 4
            [void]$why.Add('nothing on 443/5001/5061/5090, which matches an SBC and rules out a full PBX')
        } else {
            $score -= 3
            [void]$why.Add(('listening on ' + $out.PbxPorts + ', which a standalone SBC does not - this looks like the full PBX'))
        }
    }

    if ($out.Vendor -eq 'Raspberry Pi') { $score += 3; [void]$why.Add('MAC is a registered Raspberry Pi assignment') }

    if     ($out.Os -like 'Raspbian*')  { $score += 2; [void]$why.Add('SSH banner reports Raspberry Pi OS') }
    elseif ($out.Os -like 'Debian*')    { $score += 2; [void]$why.Add('SSH banner reports Debian, which the SBC package targets (and 64-bit Pi OS also reports)') }
    elseif ($out.Os -eq 'Ubuntu')       { $score += 1; [void]$why.Add('SSH banner reports Ubuntu') }
    elseif ($out.SshOpen)               { $score += 1; [void]$why.Add('SSH is reachable') }

    # Windows is a supported SBC platform, so it must not be penalised - but it is
    # equally the PBX's platform, and it cannot be driven over SSH.
    if ($out.Platform -eq 'Windows') { [void]$why.Add('Windows host - a supported SBC platform, but also the PBX platform') }
    if ($out.Platform -eq 'Linux' -and -not $out.SshOpen -and $out.Ttl -gt 0) {
        [void]$why.Add(('reply TTL ' + $out.Ttl + ' suggests Linux/Unix'))
    }

    # Soft hint only. Verified: there is no 3CX Pi image any more and no hostname
    # convention - whoever flashed the card typed whatever they liked.
    if ($out.Hostname -match '(?i)3cx|sbc|raspberrypi|raspberry') {
        $score += 1; [void]$why.Add(('hostname ' + $out.Hostname + ' is suggestive, though no naming convention is documented'))
    }

    if     ($out.SbcMarker) { $out.Confidence = 'the local 3CX SBC (confirmed - its reply names it 3CXSBC)' }
    elseif ($score -ge 8)   { $out.Confidence = 'very likely the local SBC' }
    elseif ($score -ge 5)   { $out.Confidence = 'likely the local SBC' }
    elseif ($score -ge 2)   { $out.Confidence = 'possible' }
    else                    { $out.Confidence = 'unlikely' }

    # Without the 3CX SIP signature, a numeric score alone produces a noisy
    # "possible" on anything that merely has SSH. A Raspberry Pi is worth
    # surfacing on a 3CX site, but a Pi on its own is just a Pi - and a SIP
    # device that is not 3CX is not an SBC candidate at all. Say which it is.
    if (-not $is3cx) {
        if ($out.Vendor -eq 'Raspberry Pi' -and $out.SshOpen) {
            $out.Confidence = 'possible - a Pi with SSH, but it did not answer SIP as 3CX'
        } elseif ($out.Vendor -eq 'Raspberry Pi') {
            $out.Confidence = 'a Raspberry Pi, but nothing indicates it is the SBC'
        } else {
            $out.Confidence = 'unlikely'
        }
    }

    $d = 'No corroborating signal beyond being on the LAN.'
    if (@($why).Count -gt 0) { $d = 'Signals: ' + ((@($why.ToArray()) -join '; ')) + '.' }

    if ($out.Platform -ne 'unknown') {
        $d += (' Platform: ' + $out.Platform)
        if ($out.PlatformBasis) { $d += (' (' + $out.PlatformBasis + ')') }
        $d += '.'
    } else {
        $d += ' Platform could not be determined: no SSH banner, no Windows service ports and no ICMP reply.'
    }

    if ($out.RoleLabel) { $d += (' This host is also the ' + $out.RoleLabel + '.') }

    # Keep the ambiguity visible where it genuinely remains.
    if ($is3cx -and -not $portsProbed) {
        $d += ' Port profiling was skipped, so an SBC cannot be told from a full PBX here.'
    }
    if ($is3cx -and $out.SipMatched -eq 'line-seize') {
        # The string line-seize appears ZERO times in the 3cxsbc binary, so a
        # reply carrying it was very likely generated by the PBX and relayed
        # through the tunnel - which says the tunnel is up, but describes the PBX.
        $d += ' Note: matched on the line-seize event package, which does not exist in the SBC binary at all - that reply was most likely generated by the PBX and relayed through the tunnel.'
    }
    if ($out.Platform -eq 'Windows') {
        $d += ' 3CX does support the SBC on Windows, but there is no SSH server there by default - so the terminal and the canned commands on this tab do not apply to it. Manage it from the console or RDP.'
    } elseif (-not $out.SshOpen) {
        $d += ' SSH is not reachable on 22, so the terminal and the canned commands will not work against this host.'
    }
    $out.Detail = $d + $fwdTxt
    return $out
}

# ---------------------------------------------------------------------------
# Running ON a 3CX SBC box (Windows)
# ---------------------------------------------------------------------------
# The LAN sweep can never find an SBC on the machine the tool runs on: a host is
# never in its own ARP table. These checks look at this PC directly instead.
#
# Everything here was confirmed on a real Windows SBC (SmartSBC 20.0.100):
#   service  3CXSBC  ("3CX Session Border Controller")
#   process  3cxsbc  - binds UDP 0.0.0.0:5060 for the phones
#   config   %ProgramData%\3CXSBC\3cxsbc.conf  (+ 3cxsbc.conf.local overrides)
#   log      %ProgramData%\3CXSBC\Logs\3cxsbc.log
#   tunnel   an outbound TCP connection from that process to TunnelAddr:TunnelPort
#
# Deliberately NOT checked: a TLS handshake on the tunnel port. Measured against
# two PBXes, including one whose tunnel is known to work, the tunnel refuses a
# plain TLS ClientHello - so such a check would false-alarm on every healthy site.
# ---------------------------------------------------------------------------

function Get-LocalSbcPath {
    $root = Join-Path $env:ProgramData '3CXSBC'
    return [pscustomobject]@{
        Root   = $root
        Config = (Join-Path $root '3cxsbc.conf')
        Local  = (Join-Path $root '3cxsbc.conf.local')
        Log    = (Join-Path $root 'Logs\3cxsbc.log')
        Mon    = (Join-Path $root 'Logs\3cxsbc.log.mon')
    }
}

function ConvertFrom-SbcConfig {
    # Parses the SBC's INI-style config ("Key=Value # comment", [Section] headers).
    #
    # Password and ProvLink are SKIPPED, never held: the first is the tunnel
    # password and the second embeds the auth key, and everything this function
    # returns may end up in the log or the CSV export.
    param([string]$Text)
    $h = @{}
    if (-not $Text) { return $h }
    $section = ''
    foreach ($line in ($Text -split "`r?`n")) {
        $sm = [regex]::Match($line, '^\s*\[([^\]]+)\]')
        if ($sm.Success) { $section = $sm.Groups[1].Value.Trim(); continue }
        $m = [regex]::Match($line, '^\s*([A-Za-z][A-Za-z0-9_]*)\s*=\s*(.*)$')
        if (-not $m.Success) { continue }           # also skips "#Key=" comment lines
        $k = $m.Groups[1].Value
        if (@('Password','ProvLink') -contains $k) { continue }
        $v = $m.Groups[2].Value
        $c = [regex]::Match($v, '\s#')               # inline comment: "5090 # remote TCP port"
        if ($c.Success) { $v = $v.Substring(0, $c.Index) }
        $v = $v.Trim().Trim('"')
        if (-not $h.ContainsKey($k)) { $h[$k] = $v }  # first occurrence wins (first bridge)
        if ($section) { $h[($section.Split('/')[0] + '.' + $k)] = $v }   # e.g. Log.Level
    }
    return $h
}

function ConvertFrom-SbcLog {
    # Summarises the SBC log. Line format, confirmed on a real box:
    #   LEVEL | yyyyMMdd-HHmmss.fff | 3CX | SBC | 0xTID | File.cpp:line | message
    #
    # CRIT is NOT a severity signal here - the SBC logs its normal start/stop
    # lifecycle at CRIT ("Running in console mode"). Only ERR counts as an error.
    param([string[]]$Lines,[datetime]$Now = (Get-Date))
    $o = [pscustomobject]@{
        Version = ''; HostName = ''; RunStarted = $null
        Starts24h = 0; Stops24h = 0; Errors7d = 0; Inactivity7d = 0
        LastError = ''; LastErrorTime = $null; LastTunnel = ''; LastTunnelTime = $null
        LinesParsed = 0
        # Every start and stop, in the log's own (site-local) time. The Security tab
        # matches these against the PBX's tunnel history: an outage that ends the
        # second the service starts did not recover by itself.
        Starts = [System.Collections.Generic.List[datetime]]::new()
        Stops  = [System.Collections.Generic.List[datetime]]::new()
        # Typed events for outage diagnosis: start, stop, giveup, dns, bridge-invalid,
        # refused, timeout. Times are the log's own (site-local).
        Events = [System.Collections.Generic.List[object]]::new()
        DnsFail7d = 0
    }
    $ci = [System.Globalization.CultureInfo]::InvariantCulture
    foreach ($ln in @($Lines)) {
        $m = [regex]::Match([string]$ln, '^\s*(\w+)\s*\|\s*(\d{8}-\d{6}\.\d{3})\s*\|[^|]*\|[^|]*\|[^|]*\|\s*([^|]*?)\s*\|\s*(.*)$')
        if (-not $m.Success) { continue }
        $t = [datetime]::MinValue
        if (-not [datetime]::TryParseExact($m.Groups[2].Value, 'yyyyMMdd-HHmmss.fff', $ci, [System.Globalization.DateTimeStyles]::None, [ref]$t)) { continue }
        $o.LinesParsed++
        $lvl = $m.Groups[1].Value.ToUpper()
        $msg = $m.Groups[4].Value.Trim()
        $age = $Now - $t

        $b = [regex]::Match($msg, 'SmartSBC\s+(\S+)\s+@\s+(\S+)')
        if ($b.Success) {
            $o.Version = $b.Groups[1].Value; $o.HostName = $b.Groups[2].Value; $o.RunStarted = $t
            if ($age.TotalHours -le 24) { $o.Starts24h++ }
            $o.Starts.Add($t)
        }
        if ($msg -match '(?i)exit event has been fired') {
            if ($age.TotalHours -le 24) { $o.Stops24h++ }
            $o.Stops.Add($t)
        }
        if ($lvl -eq 'ERR') {
            if ($age.TotalDays -le 7) { $o.Errors7d++ }
            $o.LastError = $msg; $o.LastErrorTime = $t
        }
        if ($msg -match '(?i)too long inactivity' -and $age.TotalDays -le 7) { $o.Inactivity7d++ }
        # "Invalid bridge's configuration" is logged when the SBC cannot resolve the
        # PBX at start-up - on a real box every one followed "No such host is known" -
        # so it is filed with the DNS failures' neighbours, not read as a bad config.
        $kind = ''
        if ($b.Success)                                         { $kind = 'start' }
        elseif ($msg -match '(?i)global connection timeout')    { $kind = 'giveup' }
        elseif ($msg -match '(?i)^Stopping:')                   { $kind = 'stop' }
        elseif ($msg -match '(?i)getaddrinfo error|DNS SRV|SRV resolution failed|while contacting DNS servers|Failed to connect to [0-9.]+:53\b') { $kind = 'dns' }
        elseif ($msg -match "(?i)Invalid bridge's configuration") { $kind = 'bridge-invalid' }
        elseif ($msg -match '(?i)actively refused')             { $kind = 'refused' }
        elseif ($msg -match '(?i)connection timeout')           { $kind = 'timeout' }
        if ($kind) { $o.Events.Add([pscustomobject]@{ Time = $t; Kind = $kind }) }
        if ($kind -eq 'dns' -and $age.TotalDays -le 7) { $o.DnsFail7d++ }
        if ($msg -match '(?i)tunnel is (established|failed|not connected|disconnect)|failed to resolve dns srv|bridge failure') {
            $o.LastTunnel = $msg; $o.LastTunnelTime = $t
        }
    }
    return $o
}

function ConvertFrom-SbcMonLog {
    # The SBC's supervisor log (3cxsbc.log.mon, next to 3cxsbc.log) records WHY the
    # SBC stopped - the main log only ever says "console control handler". Seen on a
    # real box:
    #   "console control handler" and "service manager request" in the same instant
    #       -> looks like Windows shutting down (both signal at once)
    #   "service manager request" alone -> the service was stopped (a person, a script)
    #   "console control handler" alone -> a console/shutdown signal only
    # Returns one entry per stop, in the log's own (site-local) time.
    param([string[]]$Lines)
    $ci = [System.Globalization.CultureInfo]::InvariantCulture
    $raw = [System.Collections.Generic.List[object]]::new()
    foreach ($ln in @($Lines)) {
        $m = [regex]::Match([string]$ln, '^\s*\w+\s*\|\s*(\d{8}-\d{6}\.\d{3})\s*\|.*\|\s*Stopping:\s*(.+?)\s*$')
        if (-not $m.Success) { continue }
        $t = [datetime]::MinValue
        if (-not [datetime]::TryParseExact($m.Groups[1].Value, 'yyyyMMdd-HHmmss.fff', $ci, [System.Globalization.DateTimeStyles]::None, [ref]$t)) { continue }
        $raw.Add([pscustomobject]@{ Time = $t; Reason = $m.Groups[2].Value })
    }
    $out = [System.Collections.Generic.List[object]]::new()
    $cur = $null
    foreach ($r in @($raw | Sort-Object Time)) {
        if ($cur -and ($r.Time - $cur.Time).TotalSeconds -le 3) { $cur.Reasons += $r.Reason; continue }
        $cur = [pscustomobject]@{ Time = $r.Time; Reasons = @($r.Reason); Kind = '' }
        $out.Add($cur)
    }
    foreach ($e in $out) {
        $con = @($e.Reasons | Where-Object { $_ -match '(?i)console control' }).Count -gt 0
        $scm = @($e.Reasons | Where-Object { $_ -match '(?i)service manager' }).Count -gt 0
        if ($con -and $scm) { $e.Kind = 'os-shutdown' } elseif ($scm) { $e.Kind = 'service-stop' } else { $e.Kind = 'console-stop' }
    }
    return @($out.ToArray())
}

function Get-WindowsRestartEvents {
    # Windows' own record of restarts, from the System log (readable without admin
    # rights): 1074 names the process that asked for the restart and why - on the
    # dev PC, MoUsoCoreWorker.exe "Service pack (Planned)", i.e. Windows Update;
    # 6008 and 41 are unexpected shutdowns (crash, power loss).
    param([datetime]$StartUtc,[datetime]$EndUtc)
    $ev = @()
    try {
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 1074, 6008, 41; StartTime = $StartUtc.ToLocalTime(); EndTime = $EndUtc.ToLocalTime() } -ErrorAction Stop)
    } catch { return @() }     # includes "No events were found"
    return @($ev | ForEach-Object {
        $proc = ''; $why = ''
        if ($_.Id -eq 1074) {
            try { $proc = [string]$_.Properties[0].Value; $why = [string]$_.Properties[2].Value } catch {}
        } elseif ($_.Id -eq 6008) { $why = 'an unexpected shutdown' }
        else { $why = 'a restart without a clean shutdown (crash or power loss)' }
        [pscustomobject]@{ TimeUtc = $_.TimeCreated.ToUniversalTime(); Id = [int]$_.Id; Process = $proc; Reason = $why }
    })
}

function Get-RestartCauseText {
    # Plain words for a 1074 event's process.
    param($W)
    if (-not $W) { return '' }
    $p = [System.IO.Path]::GetFileName(([string]$W.Process -replace '\s*\(.*$', ''))
    if ($W.Id -ne 1074) { return ('Windows logged ' + $W.Reason) }
    if ($p -match '(?i)^(MoUsoCoreWorker|UsoClient|wuauclt|TrustedInstaller)\.exe$') { return ('Windows Update restarted it (' + $p + ', "' + $W.Reason + '")') }
    if ($p -match '(?i)^(winlogon|explorer|shutdown)\.exe$') { return ('someone restarted it from Windows (' + $p + ', "' + $W.Reason + '")') }
    return ('Windows logged a restart requested by ' + $p + ' ("' + $W.Reason + '")')
}

function Get-SbcTunnelState {
    # Classifies the tunnel from the TCP connections the SBC process holds.
    # Every state counts, not just Established: "trying and failing" (SynSent)
    # and "not trying at all" (nothing) point at different causes.
    param($Connections,[int]$TunnelPort = 5090,[string[]]$TunnelIps = @())
    $o = [pscustomobject]@{ State = 'none'; Detail = '' }
    $mine = @(@($Connections) | Where-Object { $_ -and [int]$_.RemotePort -eq $TunnelPort })
    if (@($mine).Count -eq 0) {
        $o.Detail = ('The SBC process holds no TCP connection to port {0} at all - it is neither connected nor mid-attempt.' -f $TunnelPort)
        return $o
    }
    $est = @($mine | Where-Object { [string]$_.State -eq 'Established' })
    if (@($est).Count -gt 0) {
        $o.State = 'up'
        $ra = [string]$est[0].RemoteAddress
        $o.Detail = ('Established to {0}:{1}.' -f $ra, $TunnelPort)
        if (@($TunnelIps).Count -gt 0 -and $TunnelIps -notcontains $ra) {
            $o.Detail += (' Note: that is not an address the configured TunnelAddr resolves to (' + (@($TunnelIps) -join ', ') + ').')
        }
        return $o
    }
    $syn = @($mine | Where-Object { [string]$_.State -eq 'SynSent' })
    if (@($syn).Count -gt 0) {
        $o.State = 'connecting'
        $o.Detail = ('Trying to connect to {0}:{1} (SynSent) but the connection is not completing.' -f $syn[0].RemoteAddress, $TunnelPort)
        return $o
    }
    $o.State = 'other'
    $o.Detail = ('Connections to port {0} exist but none is established: {1}.' -f $TunnelPort, ((@($mine) | ForEach-Object { [string]$_.State }) -join ', '))
    return $o
}

function Get-SbcTunnelCounterEvidence {
    # When the SBC process holds no TCP connection to the tunnel port, what says
    # the tunnel may be up anyway? Found on a real site: no TCP socket in two checks
    # hours apart, while the PBX recorded the tunnel Up and the SBC - which logs
    # every failed attempt, even at ERR level - logged nothing since its start.
    param($R,[datetime]$Now = (Get-Date),[int]$QuietMinutes = 10)
    $ev = [System.Collections.Generic.List[string]]::new()
    $L = $R.Log
    if ($L -and $L.LinesParsed -gt 0 -and $L.RunStarted -and $L.PSObject.Properties['Events']) {
        $age = ($Now - $L.RunStarted).TotalMinutes
        if ($age -ge $QuietMinutes) {
            $fails = @(@($L.Events) | Where-Object { $_.Time -ge $L.RunStarted -and @('dns', 'timeout', 'refused', 'giveup', 'bridge-invalid') -contains $_.Kind }).Count
            if ($fails -eq 0) {
                [void]$ev.Add(('its log shows no connection failure since it started at {0} ({1} ago), and it logs every failed attempt' -f $L.RunStarted.ToString('yyyy-MM-dd HH:mm'), (Format-SecDuration $age)))
            }
        }
    }
    if ($R.PSObject.Properties['SipMatched'] -and $R.SipMatched -eq 'line-seize') {
        [void]$ev.Add('its reply to SIP OPTIONS carried line-seize, which the SBC does not generate - so that reply most likely came from the PBX, through the tunnel')
    }
    if ($R.PSObject.Properties['PbxConns']) {
        $est = @(@($R.PbxConns) | Where-Object { $_.State -eq 'Established' -and $_.RemotePort -eq $R.TunnelPort })
        if (@($est).Count -gt 0) { [void]$ev.Add(('an Established connection to the PBX on port {0} exists, owned by {1}' -f $R.TunnelPort, $est[0].Process)) }
    }
    return @($ev.ToArray())
}

function Resolve-LocalSbcVerdict {
    # Pure: turns a gathered report into Health / Verdict / Detail. Separate from
    # the gathering so it can be tested without an SBC installed.
    param($R,[datetime]$Now = (Get-Date))
    $d = [System.Collections.Generic.List[string]]::new()
    $pbx = $R.TunnelAddr; if (-not $pbx) { $pbx = '(unknown PBX)' }
    $ep = ('{0}:{1}' -f $pbx, $R.TunnelPort)

    if ($R.Status -ne 'Running') {
        $R.Health  = 'fail'
        $R.Verdict = ('THIS PC: 3CX SBC installed but the service is ' + $R.Status)
        [void]$d.Add(('The 3CXSBC service is {0} (start type {1}). Phones behind this SBC have no service until it runs.' -f $R.Status, $R.StartType))
    } else {
        switch ($R.Tunnel) {
            'up' {
                $R.Health = 'ok'
                $R.Verdict = ('THIS PC: 3CX SBC running - tunnel UP to ' + $ep)
            }
            'connecting' {
                $R.Health = 'fail'
                $R.Verdict = ('THIS PC: 3CX SBC running - tunnel NOT connecting to ' + $ep)
            }
            default {
                $R.Health = 'fail'
                $R.Verdict = ('THIS PC: 3CX SBC running - NO tunnel to ' + $ep)
            }
        }
        if ($R.TunnelDetail) { [void]$d.Add($R.TunnelDetail) }
        $counter = @()
        if ($R.Tunnel -eq 'none' -or $R.Tunnel -eq 'other') { $counter = @(Get-SbcTunnelCounterEvidence -R $R -Now $Now) }
        if (@($counter).Count -gt 0) {
            # Evidence points both ways, so say that rather than pick one.
            $R.Health  = 'warn'
            $R.Verdict = ('THIS PC: 3CX SBC running - tunnel NOT CONFIRMED (no TCP connection to ' + $ep + ' seen)')
            [void]$d.Add(('But that is contradicted: ' + (@($counter) -join '; ') + '.'))
            $udpTxt = ''
            if ($R.PSObject.Properties['UdpPorts'] -and @($R.UdpPorts).Count -gt 0) { $udpTxt = (' It holds UDP port(s) ' + (@($R.UdpPorts) -join ', ') + ' besides 5060 and its media range.') }
            [void]$d.Add(('The tunnel also has a UDP channel (the SBC''s own log names it), and Windows cannot show where a UDP socket is talking to.' + $udpTxt + ' So this PC cannot settle it either way: the SBC''s status in the {0} admin console, or a test call from a phone behind it, can.' -f $pbx))
            if ($R.Reachable -eq $true) { [void]$d.Add(('{0} is reachable from this PC.' -f $ep)) }
        } elseif ($R.Tunnel -ne 'up') {
            if ($R.Reachable -eq $true) {
                [void]$d.Add(('{0} IS reachable from this PC, so this is not a network block - check the SBC''s pairing in the {1} admin console, and its log.' -f $ep, $pbx))
            } elseif ($R.Reachable -eq $false) {
                [void]$d.Add(('{0} is NOT reachable from this PC - check the firewall and DNS before the SBC itself.' -f $ep))
            }
            $ri = '30s by default'
            if ($R.PSObject.Properties['ReconnectInterval'] -and $R.ReconnectInterval) { $ri = ([string]$R.ReconnectInterval + 's in this SBC''s config') }
            [void]$d.Add(('One snapshot: the SBC retries every ReconnectInterval ({0}), so re-check if in doubt. The PBX admin console is the authoritative view of the tunnel.' -f $ri))
        }
    }

    if ($R.Udp5060Owner -and $R.Udp5060Owner -ne '3cxsbc') {
        if ($R.Health -eq 'ok') { $R.Health = 'warn' }
        [void]$d.Add(('UDP 5060 is held by {0}, not the SBC - phones sending SIP to this PC will reach that instead.' -f $R.Udp5060Owner))
    } elseif (-not $R.Udp5060Owner -and $R.Status -eq 'Running') {
        if ($R.Health -eq 'ok') { $R.Health = 'warn' }
        [void]$d.Add('Nothing is listening on UDP 5060, so the SBC is not accepting SIP from the phones.')
    } elseif ($R.Udp5060Owner -eq '3cxsbc') {
        [void]$d.Add('Listening on UDP 5060 for the phones.')
    }
    if ($R.SipAnswer) { [void]$d.Add(('Answers SIP OPTIONS locally: ' + $R.SipAnswer + '.')) }

    if (-not $R.ConfigReadable) {
        [void]$d.Add('The SBC config could not be read - run the tool elevated to see which PBX it is paired with.')
    }

    $L = $R.Log
    if ($L -and $L.LinesParsed -gt 0) {
        $lp = [System.Collections.Generic.List[string]]::new()
        if ($L.Version)    { [void]$lp.Add('SmartSBC ' + $L.Version) }
        if ($L.RunStarted) { [void]$lp.Add('current run since ' + $L.RunStarted.ToString('yyyy-MM-dd HH:mm')) }
        [void]$lp.Add(('{0} start(s) in the last 24h' -f $L.Starts24h))
        [void]$lp.Add(('{0} error(s) in 7 days' -f $L.Errors7d))
        if ($L.PSObject.Properties['DnsFail7d'] -and $L.DnsFail7d -gt 0) { [void]$lp.Add(('{0} failed DNS lookup(s) for the PBX in 7 days - this PC''s DNS or the site''s internet, not the SBC itself' -f $L.DnsFail7d)) }
        # NOT reported as tunnel outages: on a real site, correlated to the second
        # against the PBX's own record (event 4102, SBC status Down/Up), neither
        # of these errors coincided with an outage the PBX saw.
        if ($L.Inactivity7d -gt 0) { [void]$lp.Add(('{0} "Too long inactivity" bridge failure(s) in 7 days - not necessarily a tunnel outage; the PBX event log (event 4102) is the record of the tunnel going down' -f $L.Inactivity7d)) }
        [void]$d.Add('Log: ' + (@($lp.ToArray()) -join '; ') + '.')
        if ($L.Starts24h -ge 3) {
            if ($R.Health -eq 'ok') { $R.Health = 'warn' }
            [void]$d.Add(('The SBC has started {0} times in 24 hours - restarts drop every call in progress.' -f $L.Starts24h))
        }
        if ($R.LogLevel -and $R.LogLevel -match '^(ERR|ERROR|CRIT)') {
            [void]$d.Add(('Log level is {0}, which records failures but not successful connections - silence in the log is not evidence the tunnel is up.' -f $R.LogLevel))
        }
    }

    $R.Detail = (@($d.ToArray()) -join ' ')
    return $R
}

function Test-SbcPbxMismatch {
    # Is the tool testing a different PBX from the one this PC's SBC is paired with?
    # Names are compared first; if they differ, resolved addresses are compared, so
    # an IP-versus-name difference for the same host is not flagged.
    param([string]$TestFqdn,[string]$TunnelAddr,[switch]$SkipResolve)
    if (-not $TestFqdn -or -not $TunnelAddr) { return $false }
    if ($TestFqdn.Trim().ToLower() -eq $TunnelAddr.Trim().ToLower()) { return $false }
    if ($SkipResolve) { return $true }
    $a = @(); $b = @()
    try { $a = @([System.Net.Dns]::GetHostAddresses($TestFqdn)   | ForEach-Object { $_.IPAddressToString }) } catch {}
    try { $b = @([System.Net.Dns]::GetHostAddresses($TunnelAddr) | ForEach-Object { $_.IPAddressToString }) } catch {}
    if (@($a).Count -gt 0 -and @($b).Count -gt 0 -and @($a | Where-Object { $b -contains $_ }).Count -gt 0) { return $false }
    return $true
}

function Get-LocalSbcReport {
    # Gathers everything about a 3CX SBC running on THIS machine. Read-only.
    # Returns Present = $false (and does nothing else) on a machine without one.
    param([string]$TestFqdn = '',[switch]$SkipNetwork,[string]$RawLogPath = '',[int]$LogTail = 4000)
    $R = [pscustomobject]@{
        Present = $false; ServiceName = ''; DisplayName = ''; Status = ''; StartType = ''
        ProcessIds = @(); Udp5060Owner = ''; ConfigPath = ''; ConfigReadable = $false
        TunnelAddr = ''; TunnelPort = 5090; PbxSipIP = ''; SecurityMode = ''; LogLevel = ''
        Tunnel = 'unknown'; TunnelDetail = ''; Reachable = $null; Mismatch = $false; TestFqdn = $TestFqdn
        LanIp = ''; SipAnswer = ''; SipMatched = ''; PbxConns = @(); UdpPorts = @(); FirstRtpPort = 0; NumRtpPorts = 0
        Log = $null; Health = 'unknown'; Verdict = ''; Detail = ''
    }

    $svc = Get-Service -Name '3CXSBC' -ErrorAction SilentlyContinue
    if (-not $svc) {
        $svc = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like '*3CX*Session Border*' } | Select-Object -First 1
    }
    if (-not $svc) { return $R }
    $R.Present = $true
    $R.ServiceName = [string]$svc.Name
    $R.DisplayName = [string]$svc.DisplayName
    $R.Status      = [string]$svc.Status
    try { $R.StartType = [string]$svc.StartType } catch { $R.StartType = '?' }

    $procs = @(Get-Process -Name '3cxsbc' -ErrorAction SilentlyContinue)
    $R.ProcessIds = @($procs | ForEach-Object { $_.Id })

    try {
        $u = @(Get-NetUDPEndpoint -LocalPort 5060 -ErrorAction SilentlyContinue)
        if (@($u).Count -gt 0) {
            $p = Get-Process -Id $u[0].OwningProcess -ErrorAction SilentlyContinue
            if ($p) { $R.Udp5060Owner = [string]$p.ProcessName } else { $R.Udp5060Owner = ('pid ' + $u[0].OwningProcess) }
        }
    } catch {}

    $P = Get-LocalSbcPath
    $cfg = @{}
    try {
        if (Test-Path -LiteralPath $P.Config) {
            $cfg = ConvertFrom-SbcConfig -Text (Get-Content -LiteralPath $P.Config -Raw -ErrorAction Stop)
            $R.ConfigPath = $P.Config
            $R.ConfigReadable = $true
        }
        if (Test-Path -LiteralPath $P.Local) {
            $loc = ConvertFrom-SbcConfig -Text (Get-Content -LiteralPath $P.Local -Raw -ErrorAction Stop)
            foreach ($k in $loc.Keys) { $cfg[$k] = $loc[$k] }      # .local overrides the main file
        }
    } catch { $R.ConfigReadable = $false }
    if ($cfg.ContainsKey('TunnelAddr'))   { $R.TunnelAddr   = $cfg['TunnelAddr'] }
    if ($cfg.ContainsKey('TunnelPort') -and $cfg['TunnelPort'] -match '^\d+$') { $R.TunnelPort = [int]$cfg['TunnelPort'] }
    if ($cfg.ContainsKey('PbxSipIP'))     { $R.PbxSipIP     = $cfg['PbxSipIP'] }
    if ($cfg.ContainsKey('SecurityMode')) { $R.SecurityMode = $cfg['SecurityMode'] }
    if ($cfg.ContainsKey('Log.Level'))    { $R.LogLevel     = $cfg['Log.Level'] }
    if ($cfg.ContainsKey('ReconnectInterval') -and $cfg['ReconnectInterval'] -match '^\d+$') { $R | Add-Member -NotePropertyName ReconnectInterval -NotePropertyValue ([int]$cfg['ReconnectInterval']) -Force }
    if ($cfg.ContainsKey('FirstRtpPort') -and $cfg['FirstRtpPort'] -match '^\d+$') { $R.FirstRtpPort = [int]$cfg['FirstRtpPort'] }
    if ($cfg.ContainsKey('NumRtpPorts')  -and $cfg['NumRtpPorts']  -match '^\d+$') { $R.NumRtpPorts  = [int]$cfg['NumRtpPorts'] }

    try {
        if (Test-Path -LiteralPath $P.Log) {
            $R.Log = ConvertFrom-SbcLog -Lines @(Get-Content -LiteralPath $P.Log -Tail $LogTail -ErrorAction Stop)
        }
    } catch {}

    $ips = @()
    if ($R.TunnelAddr -and -not $SkipNetwork) {
        try { $ips = @([System.Net.Dns]::GetHostAddresses($R.TunnelAddr) | ForEach-Object { $_.IPAddressToString }) } catch {}
    }
    $conns = @()
    if (@($R.ProcessIds).Count -gt 0) {
        try { $conns = @(Get-NetTCPConnection -OwningProcess ([uint32[]]$R.ProcessIds) -ErrorAction SilentlyContinue) } catch {}
    }
    $ts = Get-SbcTunnelState -Connections $conns -TunnelPort $R.TunnelPort -TunnelIps $ips
    $R.Tunnel = $ts.State
    $R.TunnelDetail = $ts.Detail

    # Wider evidence, for when the SBC's own TCP sockets show nothing. On the real
    # site that was the reading twice, while the PBX recorded the tunnel Up and the
    # SBC logged no failure at all - so the TCP view alone is not the whole story.
    if (@($ips).Count -gt 0) {
        try {
            $R.PbxConns = @(Get-NetTCPConnection -RemoteAddress ([string[]]$ips) -ErrorAction SilentlyContinue | ForEach-Object {
                $pn = ''; try { $pn = [string](Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } catch {}
                [pscustomobject]@{ RemoteAddress = [string]$_.RemoteAddress; RemotePort = [int]$_.RemotePort; State = [string]$_.State; Process = $pn }
            })
        } catch {}
    }
    if (@($R.ProcessIds).Count -gt 0) {
        # The SBC's UDP sockets other than 5060 and its media range. Its log names a
        # UDP channel to the PBX, and Windows cannot show a UDP socket's far end.
        try {
            $rtpHi = $R.FirstRtpPort + 2 * $R.NumRtpPorts
            $R.UdpPorts = @(Get-NetUDPEndpoint -OwningProcess ([uint32[]]$R.ProcessIds) -ErrorAction SilentlyContinue | ForEach-Object { [int]$_.LocalPort } |
                Where-Object { $_ -ne 5060 -and -not ($R.FirstRtpPort -gt 0 -and $_ -ge $R.FirstRtpPort -and $_ -lt $rtpHi) } | Sort-Object -Unique)
        } catch {}
    }

    if (-not $SkipNetwork) {
        if ($R.TunnelAddr) {
            # TCP only - see the header: a TLS handshake would false-alarm.
            $R.Reachable = [bool](Test-TcpPort -ComputerName $R.TunnelAddr -Port $R.TunnelPort -TimeoutMs 3000).Open
            $R.Mismatch  = Test-SbcPbxMismatch -TestFqdn $TestFqdn -TunnelAddr $R.TunnelAddr
            $R.LanIp     = Get-LocalIpForTarget -TargetHost $R.TunnelAddr
        }
        if (-not $R.LanIp) { $R.LanIp = Get-LocalIpForTarget -TargetHost '8.8.8.8' }
        # Ask the SBC itself, once. Its full reply goes to the raw capture: whether it
        # carries line-seize (a PBX-only header) says whether the SBC answers OPTIONS
        # itself or relays the PBX's reply through the tunnel.
        if ($R.LanIp -and $R.Udp5060Owner -eq '3cxsbc') {
            $sw = @(Invoke-SipSweep -Hosts @($R.LanIp) -Port 5060 -WaitMs 2000)
            if (@($sw).Count -gt 0) {
                $R.SipAnswer = $sw[0].Response
                if ($sw[0].PSObject.Properties['Matched']) { $R.SipMatched = [string]$sw[0].Matched }
                if ($RawLogPath) {
                    $mm = 'none'; if ($sw[0].Matched) { $mm = $sw[0].Matched }
                    Write-PhoneRaw -Path $RawLogPath -Url ('SIP OPTIONS reply from THIS PC''s SBC at {0}   [3CX signature matched on: {1}]' -f $R.LanIp, $mm) -Text ([string]$sw[0].Raw)
                }
            } else {
                $R.SipAnswer = 'no reply'
            }
        }
    } else {
        $R.Mismatch = Test-SbcPbxMismatch -TestFqdn $TestFqdn -TunnelAddr $R.TunnelAddr -SkipResolve
    }

    return (Resolve-LocalSbcVerdict -R $R)
}

function ConvertTo-LocalSbcRow {
    # Shapes the report like a Test-SbcCandidate row so the SIP / SBC grid, the
    # CSV export and the clipboard copy handle it with no special cases.
    param($R)
    $ip = $R.LanIp; if (-not $ip) { $ip = '(this PC)' }
    $sip = ''
    if ($R.SipAnswer) { $sip = $R.SipAnswer }
    return [pscustomobject]@{
        IP = $ip; MAC = ''; Vendor = ''; Hostname = $env:COMPUTERNAME
        Platform = 'Windows (this PC)'; PlatformBasis = 'this machine'
        SshOpen = $false; SshBanner = ''; Os = 'Windows'; Ttl = 0
        OpenPorts = $(if ($R.Udp5060Owner) { 'UDP 5060 (' + $R.Udp5060Owner + ')' } else { '' })
        PbxPorts = ''; WinPorts = ''; SipType = $sip; SipUserAgent = ''; SipMatched = ''
        RoleLabel = ''; IsKnownPhone = $false; IsRouterPhone = $false; Is3cxRouterPhone = $false
        IsLocalSbc = $true; LocalHealth = $R.Health
        Confidence = $R.Verdict; Detail = $R.Detail
    }
}

function Get-SbcCommandSet {
    # Canned commands for a standalone 3CX SBC on Debian / Raspberry Pi.
    #
    # EVERY command here was verified against 3CX's own published package and
    # installer, not assumed. Notably:
    #
    #   * The unit is '3cxsbc' - all lowercase. 'systemctl status 3CX*' is the
    #     PBX idiom and does NOT match it, because unit names are case-sensitive.
    #   * 3CXStopServices / 3CXStartServices are in the 3cxpbx package ONLY, and
    #     that package is amd64-only. They do not exist on any SBC, and they do
    #     not exist on ARM at all - so on a Pi SBC they are 'command not found'.
    #     The SBC equivalent is 'systemctl restart 3cxsbc'.
    #   * The log and the config are owned by the service account (tcxsbc, note
    #     the 't') and mode 750/640, so reading either genuinely needs sudo.
    #   * sudo itself may prompt: Raspberry Pi OS 6.2 (Trixie) turns OFF
    #     passwordless sudo on new installs, and the current 3CX guide points at
    #     Trixie. Read-only probes therefore use 'sudo -n' so they fail instantly
    #     with a clear message rather than hanging on a password prompt no
    #     captured session can answer.
    #
    # Commands must not contain a double quote - Invoke-PlinkCommand rejects
    # those rather than mangling the argument string.
    param([string]$PbxHost = '')

    $set = [System.Collections.Generic.List[object]]::new()

    $set.Add([pscustomobject]@{
        Title = 'Collect everything (one round trip)'
        Note  = 'Service state, version, tunnel peer, sudo availability and host basics in a single call, split on the ---MARKER--- lines. Start here: it answers most questions before you need anything else.'
        Text  = ('echo ---SERVICE---; systemctl is-active 3cxsbc; ' +
                 'echo ---ENABLED---; systemctl is-enabled 3cxsbc; ' +
                 'echo ---VERSION---; dpkg-query -W -f=' + "'" + '${Version}' + "'" + ' 3cxsbc; echo; ' +
                 'echo ---TUNNEL---; ss -tn state established | awk ' + "'" + '$NF ~ /:5090$/ {print $NF}' + "'" + '; ' +
                 'echo ---PRODUCT---; command -v 3CXStopServices >/dev/null && echo PBX-PACKAGE-PRESENT || echo SBC-ONLY; ' +
                 'echo ---SUDO---; sudo -n true 2>&1 || echo PASSWORD-REQUIRED; ' +
                 'echo ---HOST---; uptime; ' +
                 'echo ---OS---; grep PRETTY_NAME /etc/os-release')
        Destructive = $false; ReadOnly = $true; NeedsSudo = $false
    })

    $set.Add([pscustomobject]@{
        Title = 'Service status'
        Note  = 'Active/inactive/failed plus the last few journal lines. Restart=always is set in the unit, so a service that keeps dying will show a climbing restart count rather than staying down.'
        Text  = 'systemctl status 3cxsbc --no-pager; echo ---RESTARTS---; systemctl show 3cxsbc -p NRestarts,ActiveState,SubState,ExecMainStartTimestamp'
        Destructive = $false; ReadOnly = $true; NeedsSudo = $false
    })

    $set.Add([pscustomobject]@{
        Title = 'Tunnel state'
        Note  = 'There is no CLI tunnel-status command, so this checks the two things that do exist: an established outbound TCP session to the PBX on 5090, and what the log last said about the tunnel. The authoritative view is the PBX console.'
        Text  = ('echo ---SOCKET---; ss -tn state established | awk ' + "'" + '$NF ~ /:5090$/ {print $NF}' + "'" + '; ' +
                 'echo ---LOG---; sudo -n grep -aiE ' + "'" + 'secure tunnel is (established|failed)|tunnel is (not connected|disconnect)|failed to resolve dns srv' + "'" + ' /var/log/3cxsbc/3cxsbc.log 2>&1 | tail -20')
        Destructive = $false; ReadOnly = $true; NeedsSudo = $true
    })

    $set.Add([pscustomobject]@{
        Title = 'Config - which PBX is it paired to'
        Note  = 'TunnelAddr is the PBX. Deliberately a targeted grep and not a cat: the config also holds the tunnel Password and a ProvLink that embeds the auth key, and this output goes into the log and the export.'
        Text  = ('sudo -n grep -E ' + "'" + '^(ID|Name|TunnelAddr|TunnelPort|TunnelAddr2|TunnelPort2|PbxSipIP|PbxSipPort|LocalSipAddr|LocalSipPort|SecurityMode)' + "'" + ' /etc/3cxsbc.conf 2>&1; ' +
                 'echo ---LOCAL-OVERRIDES---; sudo -n grep -vE ' + "'" + '^(Password|ProvLink)' + "'" + ' /etc/3cxsbc.conf.local 2>&1')
        Destructive = $false; ReadOnly = $true; NeedsSudo = $true
    })

    $set.Add([pscustomobject]@{
        Title = 'Log tail'
        Note  = 'Both sinks, because which one is populated depends on [Log] Type= in the PBX-provisioned config. An empty file does not mean the SBC has no logs.'
        Text  = ('echo ---FILE---; sudo -n tail -n 120 /var/log/3cxsbc/3cxsbc.log 2>&1; ' +
                 'echo ---JOURNAL---; sudo -n journalctl -u 3cxsbc -n 80 --no-pager 2>&1')
        Destructive = $false; ReadOnly = $true; NeedsSudo = $true
    })

    if ($PbxHost) {
        $set.Add([pscustomobject]@{
            Title = ('Reach the PBX from the SBC (' + $PbxHost + ')')
            Note  = 'Run from the SBC, not from this PC. The SBC also does a DNS SRV lookup for the tunnel, so an SRV failure is its own distinct cause.'
            Text  = ('echo ---DNS---; getent hosts ' + $PbxHost + '; ' +
                     'echo ---SRV---; getent hosts _3cxtunnel._tcp.' + $PbxHost + ' 2>&1 || echo no-srv-lookup-tool; ' +
                     'echo ---TUNNEL-PORT---; timeout 5 bash -c ' + "'" + 'cat < /dev/null > /dev/tcp/' + $PbxHost + '/5090' + "'" + ' && echo 5090-open || echo 5090-unreachable; ' +
                     'echo ---TIME---; date')
            Destructive = $false; ReadOnly = $true; NeedsSudo = $false
        })
    }

    $set.Add([pscustomobject]@{
        Title = 'Restart the SBC service'
        Note  = 'DROPS EVERY CALL IN PROGRESS at this site. The service has Restart=always, so if it is crash-looping a restart will not fix it - read the log first.'
        Text  = 'sudo systemctl restart 3cxsbc; sleep 3; systemctl is-active 3cxsbc'
        Destructive = $true; ReadOnly = $false; NeedsSudo = $true
    })

    $set.Add([pscustomobject]@{
        Title = 'Stop the SBC service'
        Note  = 'DROPS EVERY CALL and leaves the site without its SBC until started again. Phones behind it will lose service.'
        Text  = 'sudo systemctl stop 3cxsbc; systemctl is-active 3cxsbc'
        Destructive = $true; ReadOnly = $false; NeedsSudo = $true
    })

    $set.Add([pscustomobject]@{
        Title = 'Start the SBC service'
        Note  = 'Brings it back after a stop.'
        Text  = 'sudo systemctl start 3cxsbc; sleep 3; systemctl is-active 3cxsbc'
        Destructive = $false; ReadOnly = $false; NeedsSudo = $true
    })

    $set.Add([pscustomobject]@{
        Title = 'Re-provision from the PBX'
        Note  = 'Re-pulls /etc/3cxsbc.conf using the stored ProvLink and OVERWRITES it, then restarts. Use when the SBC config has drifted from the PBX. It does not re-pair to a different PBX - that needs the installer re-run, which is interactive and copy-paste only.'
        Text  = 'sudo 3cxsbc-reprovision; echo ---EXIT=$?---; sudo systemctl restart 3cxsbc; sleep 3; systemctl is-active 3cxsbc'
        Destructive = $true; ReadOnly = $false; NeedsSudo = $true
    })

    return @($set.ToArray())
}

function Resolve-RoleHost {
    # Describes the device filling a network role (gateway / DHCP), flagging it
    # when a Yealink phone is the one doing it.
    param([string]$Role,[string]$Ip,$Arp,[string[]]$OuiList,$PhoneByIp)
    $mac = ''
    if ($Arp.ContainsKey($Ip)) { $mac = $Arp[$Ip] }
    if (-not $mac) {
        try { $n = @(Get-NetNeighbor -IPAddress $Ip -ErrorAction Stop) | Select-Object -First 1; if ($n) { $mac = ($n.LinkLayerAddress -replace '[-:]','').ToUpper() } } catch {}
    }
    $oui = if ($mac.Length -ge 6) { $mac.Substring(0,6) } else { '' }
    $isYealink = [bool]($oui -and ($OuiList -contains $oui))
    $macFmt = if ($mac) { ($mac -replace '(..)(?=.)','$1-') } else { '(unknown)' }
    if ($isYealink) {
        $who = if ($PhoneByIp.ContainsKey($Ip)) { ' (this is one of the discovered phones)' } else { '' }
        $note = 'WARNING: a Yealink phone is acting as the ' + $Role + $who + ' - a router-phone adding a NAT layer can break provisioning'
        $vendor = 'Yealink'
    } else {
        $note = 'normal network equipment (not a phone)'
        $vendor = ''
    }
    [pscustomobject]@{ Role = $Role; IP = $Ip; MAC = $macFmt; Vendor = $vendor; Note = $note; Warn = $isYealink }
}

function Get-NetworkRoles {
    # Identifies who fills the gateway / DHCP-server roles and flags a phone doing it.
    param([string[]]$OuiList,$Phones)
    $out = [System.Collections.Generic.List[object]]::new()
    $arp = @{}
    try {
        foreach ($line in (& arp -a)) {
            if ($line -match '(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})') {
                $arp[$matches[1]] = ($matches[2] -replace '[-:]','').ToUpper()
            }
        }
    } catch {}
    $phoneByIp = @{}
    foreach ($p in @($Phones)) { if ($p -and $p.IP) { $phoneByIp[$p.IP] = $p } }

    $seen = @{}
    try {
        $cfgs = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = True' -ErrorAction Stop
        foreach ($cfg in @($cfgs)) {
            foreach ($gw in @($cfg.DefaultIPGateway)) {
                if ($gw -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { continue }
                if ($seen.ContainsKey('GW|' + $gw)) { continue }
                $seen['GW|' + $gw] = $true
                $out.Add((Resolve-RoleHost -Role 'Default Gateway' -Ip $gw -Arp $arp -OuiList $OuiList -PhoneByIp $phoneByIp))
            }
            $dh = [string]$cfg.DHCPServer
            if ($dh -match '^\d{1,3}(\.\d{1,3}){3}$' -and -not $seen.ContainsKey('DH|' + $dh)) {
                $seen['DH|' + $dh] = $true
                $out.Add((Resolve-RoleHost -Role 'DHCP Server' -Ip $dh -Arp $arp -OuiList $OuiList -PhoneByIp $phoneByIp))
            }
        }
    } catch {}
    return @($out.ToArray())
}

# ===========================================================================
# Media / path quality
# ---------------------------------------------------------------------------
# Everything below measures the UDP path to the PBX. Read this before changing
# any of it:
#
#   Nothing answers on the RTP range (UDP 9000-10999) - 3CX only opens media
#   ports for an established call - so there is NO responder to measure real
#   media against. Every figure here is measured over the SIP signalling path
#   (UDP 5060 to the same PBX) or over STUN, and every result string must say
#   so. The proxy is a good one (same transport, same NAT, same WAN) but it is
#   a proxy, and the tool must never present it as an RTP measurement.
#
#   Loss and jitter measured this way are ROUND-TRIP. One-way figures are
#   derived under a symmetric-path assumption that has to be stated on the row.
# ===========================================================================

function Get-Percentile {
    # Linear-interpolated percentile. $Sorted must already be ascending.
    param([double[]]$Sorted,[double]$Q)
    $n = @($Sorted).Count
    if ($n -eq 0) { return 0.0 }
    if ($n -eq 1) { return [double]$Sorted[0] }
    $r  = ($n - 1) * $Q
    $lo = [int][math]::Floor($r)
    $hi = [int][math]::Ceiling($r)
    if ($lo -eq $hi) { return [double]$Sorted[$lo] }
    return [double]($Sorted[$lo] + ($Sorted[$hi] - $Sorted[$lo]) * ($r - $lo))
}

function Get-StdDev {
    param([double[]]$Values)
    $v = @($Values)
    if ($v.Count -lt 2) { return 0.0 }
    $mean = ($v | Measure-Object -Average).Average
    $ss = 0.0
    foreach ($x in $v) { $ss += ($x - $mean) * ($x - $mean) }
    return [math]::Sqrt($ss / ($v.Count - 1))
}

function Measure-JitterRfc3550 {
    # RFC 3550 s6.4.1 interarrival jitter.
    #
    # For a request/response train the transit difference
    #     D(i,j) = (Rj - Ri) - (Sj - Si)
    # collapses exactly to RTT_j - RTT_i, because we hold our own send stamps.
    # So the only thing separating this from a plain mean-|delta| is the 1/16
    # recency weighting - and we report both, because the RFC 3550 figure is
    # what 3CX and Yealink themselves display and therefore what a technician
    # will be comparing against.
    #
    # Only CONSECUTIVE received probes are paired. If probe 7 was lost, the
    # pair (6,8) spans two send intervals and would inflate D - that single
    # detail is the difference between a jitter figure and a loss artefact.
    #
    # An RTP receiver reports J continuously, so its INSTANTANEOUS value is
    # meaningful. A one-shot diagnostic has no such luxury: the end-of-run value
    # reflects only the last ~16-48 pairs, i.e. whatever the link happened to be
    # doing at the arbitrary moment the run stopped. Measured on a synthetic
    # series with a noisy tail, that reads 52 ms against a run-wide 13.8 ms.
    # So the headline is the MEAN of J across the run, with the max kept as the
    # worst case and the final value kept for comparison against what 3CX or a
    # phone would display.
    param([double[]]$Rtts,[int[]]$Seqs)
    $n = @($Rtts).Count
    $out = [pscustomobject]@{
        JitterMs       = 0.0    # mean of J across the run - the headline
        JitterMaxMs    = 0.0    # worst J seen
        JitterFinalMs  = 0.0    # end-of-run instant (what an RTP receiver reports)
        MeanAbsDeltaMs = 0.0
        PairsUsed      = 0
    }
    if ($n -lt 2) { return $out }

    # J starts at zero and ramps with a 16-pair time constant. Averaging from
    # pair 17 still catches values that are converging and reads ~2% low on a
    # steady series; three time constants brings that under 0.5%.
    $warmup = 48
    $j = 0.0; $sum = 0.0; $pairs = 0
    $jSum = 0.0; $jMax = 0.0; $jCount = 0
    for ($i = 1; $i -lt $n; $i++) {
        if (($Seqs[$i] - $Seqs[$i - 1]) -ne 1) { continue }
        $d = [math]::Abs($Rtts[$i] - $Rtts[$i - 1])
        $j = $j + (($d - $j) / 16.0)
        $sum += $d
        $pairs++
        # Skip the ramp so the mean is not dragged down by J starting at zero.
        if ($pairs -gt $warmup) {
            $jSum += $j
            $jCount++
            if ($j -gt $jMax) { $jMax = $j }
        }
    }
    $out.PairsUsed     = $pairs
    $out.JitterFinalMs = [math]::Round($j, 3)
    if ($pairs -gt 0) { $out.MeanAbsDeltaMs = [math]::Round($sum / $pairs, 3) }
    if ($jCount -gt 0) {
        $out.JitterMs    = [math]::Round($jSum / $jCount, 3)
        $out.JitterMaxMs = [math]::Round($jMax, 3)
    } else {
        # Too few pairs to have cleared the ramp - the instantaneous value is
        # all there is, and the caller's sample-size gate should catch this.
        $out.JitterMs    = [math]::Round($j, 3)
        $out.JitterMaxMs = [math]::Round($j, 3)
    }
    return $out
}

function Test-ProbeThrottled {
    # Distinguishes "the PBX stopped answering us" from packet loss.
    #
    # Real loss is scattered and RECOVERS. A rate-limit or a blacklist is a
    # change-point: replies stop at some index and never resume. Reporting the
    # second as the first would tell a technician their WAN is broken when in
    # fact this tool got itself blocked - so when this fires, the caller must
    # suppress the loss / jitter / MOS figures entirely rather than print them.
    #
    # $Probes is the send-ordered probe array; each element needs .Answered.
    param($Probes)
    $p = @($Probes)
    $n = $p.Count
    $out = [pscustomobject]@{
        Throttled        = $false
        StoppedAtPacket  = 0      # 1-based packet number where replies stopped
        TailRun          = 0
        FirstHalfLossPct = 0.0
        Total            = $n
    }
    if ($n -lt 20) { return $out }

    # Length of the final run of consecutive unanswered sends.
    $tail = 0
    for ($i = $n - 1; $i -ge 0; $i--) {
        if ($p[$i].Answered) { break }
        $tail++
    }
    $out.TailRun = $tail

    $half = [int][math]::Floor($n / 2)
    $lost = 0
    for ($i = 0; $i -lt $half; $i++) { if (-not $p[$i].Answered) { $lost++ } }
    $firstHalfLoss = 0.0
    if ($half -gt 0) { $firstHalfLoss = $lost / [double]$half }
    $out.FirstHalfLossPct = [math]::Round($firstHalfLoss * 100.0, 2)

    # A healthy first half followed by a long dead tail is a block, not a WAN
    # fault. If the first half was ALSO failing, this is genuine loss (or the
    # host never answered at all) and must not be reported as throttling.
    $threshold = [math]::Max(20, [int]($n * 0.10))
    if ($tail -ge $threshold -and $firstHalfLoss -lt 0.02) {
        $out.Throttled       = $true
        $out.StoppedAtPacket = $n - $tail + 1
    }
    return $out
}

function Enter-HighResTimer {
    # Windows' default timer resolution is ~15.6 ms, and Socket.Poll's TIMEOUT
    # expiry rides that quantum exactly as Sleep does - measured here, Poll(1ms)
    # really costs 15.4 ms. (Poll's wake-on-DATA is prompt, ~0.2 ms; it is only
    # the timeout that is coarse. Easy to conflate, and getting it wrong puts
    # 15 ms of the tool's own scheduler noise straight into the reported jitter.)
    #
    # timeBeginPeriod(1) brings that to ~1.4 ms, which is what lets the send
    # pacer wait instead of spinning the whole inter-packet gap. It is
    # process-scoped, and Exit-HighResTimer gives it back.
    #
    # Returns $true if the resolution was raised. Callers must degrade
    # gracefully when it was not - the instrument pacing figure the train
    # reports is what tells the reader how much to trust its jitter number.
    if (-not ('CxChecker.NativeTimer' -as [type])) {
        try {
            Add-Type -Namespace 'CxChecker' -Name 'NativeTimer' -ErrorAction Stop -MemberDefinition @'
[DllImport("winmm.dll", EntryPoint="timeBeginPeriod")] public static extern uint Begin(uint period);
[DllImport("winmm.dll", EntryPoint="timeEndPeriod")]   public static extern uint End(uint period);
'@
        } catch { return $false }
    }
    try { return ([CxChecker.NativeTimer]::Begin(1) -eq 0) } catch { return $false }
}

function Exit-HighResTimer {
    param([bool]$WasRaised)
    if (-not $WasRaised) { return }
    try { [void][CxChecker.NativeTimer]::End(1) } catch {}
}

function Invoke-SipOptionsTrain {
    # A paced train of SIP OPTIONS at the PBX over UDP, matched by branch, to
    # measure what a single OPTIONS exchange cannot: sustained loss, the RTT
    # distribution, jitter, reordering and duplicates.
    #
    # RATE SAFETY. This is the only part of the tool that sends the PBX a
    # sustained stream, and if it trips 3CX anti-hacking or Fail2ban the whole
    # site loses SIP during business hours. That asymmetry - a diagnostic
    # breaking the thing it is diagnosing - drives the caps below. They are
    # enforced here rather than in the UI so no caller can bypass them.
    #
    # PACING. Measured on Windows PowerShell 5.1: Thread::Sleep(1) actually
    # costs ~15.5 ms and a Sleep-paced send loop has 6-8 ms of send-gap sd at
    # every target interval - larger than the jitter of a healthy site, so the
    # tool would end up reporting its own scheduler as the customer's network.
    # The Poll+SpinWait hybrid below measures ~0.03 ms sd. Poll is used rather
    # than Sleep for the coarse wait because it also wakes on inbound data
    # (~0.24 ms), which keeps the receive timestamps honest.
    param(
        [string]$ComputerName,
        [int]$Port       = 5060,
        [int]$IntervalMs = 50,      # 20 pps
        [int]$DurationMs = 20000,
        [string]$Label   = 'idle',
        [int]$TailMs     = 2000,    # drain window for stragglers after the last send
        [int]$PrerollCount = 5,     # discarded warm-up probes (see below)
        [switch]$NoWarmup,          # internal: set on the warm-up pass itself
        $Shared          = $null    # optional synchronized hashtable: .Cancel / .Status
    )

    # JIT the WHOLE measurement loop before the real one starts. PowerShell
    # compiles each branch on first execution, and measured, that cost lands on
    # the first several probes of a cold run: ~2.5-3 ms of instrument pacing sd
    # and up to 66 ms of schedule error, versus 0.002 ms once warm. At a healthy
    # site that is larger than the jitter being measured, so without this the
    # tool would mostly be reporting its own start-up.
    #
    # The warm-up runs against the loopback discard port, so it costs the PBX
    # nothing - and a closed local port returns ICMP unreachable, which exercises
    # the ConnectionReset path too.
    if (-not $NoWarmup) {
        try {
            [void](Invoke-SipOptionsTrain -ComputerName '127.0.0.1' -Port 9 -IntervalMs 20 -DurationMs 1000 -TailMs 50 -PrerollCount 0 -Label 'warmup' -NoWarmup)
        } catch {}
    }

    # ---- hard caps ----------------------------------------------------------
    # Enforced here rather than in the UI so no caller can bypass them.
    if ($IntervalMs -lt 20) { $IntervalMs = 20 }        # never faster than 50 pps
    if ($DurationMs -lt 1000) { $DurationMs = 1000 }
    if ($PrerollCount -lt 0)  { $PrerollCount = 0 }
    if ($PrerollCount -gt 10) { $PrerollCount = 10 }
    $count = [int][math]::Floor($DurationMs / $IntervalMs)
    if ($count -lt 1) { $count = 1 }
    # 600 packets total to the PBX in one run, pre-roll included.
    $maxCount = 600 - $PrerollCount
    if ($count -gt $maxCount) { $count = $maxCount }

    $out = [pscustomobject]@{
        Label                 = $Label
        Target                = $ComputerName
        Port                  = $Port
        IntervalMs            = $IntervalMs
        Ok                    = $false
        Error                 = ''
        Cancelled             = $false
        Sent                  = 0
        PrerollSent           = 0
        Received              = 0
        LossPct               = 0.0
        LossResolutionPct     = 0.0
        RttMinMs              = 0.0
        RttP50Ms              = 0.0
        RttP95Ms              = 0.0
        RttMaxMs              = 0.0
        JitterMs              = 0.0
        JitterMaxMs           = 0.0
        JitterFinalMs         = 0.0
        MeanAbsDeltaMs        = 0.0
        JitterPairs           = 0
        Duplicates            = 0
        Reordered             = 0
        IcmpUnreachable       = 0
        NonOkReplies          = 0
        StatusLine            = ''
        RetryAfter            = ''
        ViaHost               = ''
        Received_             = ''      # received= param the PBX echoed
        Rport                 = 0       # rport= param the PBX echoed
        LocalIp               = ''
        LocalPort             = 0
        InstrumentPacingSdMs  = 0.0
        InstrumentPacingMaxErrMs = 0.0
        HighResTimer          = $false
        Throttle              = $null
        Probes                = @()
    }

    $udp = New-Object System.Net.Sockets.UdpClient
    try {
        $udp.Connect($ComputerName, $Port)
        $lep   = [System.Net.IPEndPoint]$udp.Client.LocalEndPoint
        $lip   = $lep.Address.ToString()
        $lport = $lep.Port
        $out.LocalIp = $lip; $out.LocalPort = $lport
    } catch {
        $out.Error = $_.Exception.Message
        try { $udp.Close() } catch {}
        return $out
    }

    $pending  = @{}
    $probes   = [System.Collections.Generic.List[object]]::new()
    $sendGaps = [System.Collections.Generic.List[double]]::new()

    $sent = 0; $answeredCount = 0; $dupes = 0; $reordered = 0; $icmp = 0
    $maxSeqSeen = -1; $nextSend = 0.0; $lastSendMs = -1.0
    $drainUntil = -1.0; $nextStatusMs = 1000.0

    $hiRes = Enter-HighResTimer
    $out.HighResTimer = $hiRes

    # Build the first probe BEFORE the clock starts, so first-call JIT and GUID
    # generation cannot land inside the measured schedule. Each subsequent probe
    # is built immediately after the previous send, keeping ~0.4 ms of string
    # work off the critical path between "due" and "on the wire".
    $nxIds   = New-SipProbeIds -LocalIp $lip
    $nxBytes = [System.Text.Encoding]::ASCII.GetBytes((New-SipOptionsMessage -TargetHost $ComputerName -LocalIp $lip -LocalPort $lport -Branch $nxIds.Branch -CallId $nxIds.CallId -Tag $nxIds.Tag -CSeq 1))

    # Warm every code path the loop will use. Without this, first-call JIT lands
    # on the first few probes and they run up to 26 ms late before recovering -
    # which showed up as ~4 ms of instrument pacing sd that had nothing to do
    # with the network and would have been reported as if it did.
    $warmText = 'SIP/2.0 200 OK' + [char]13 + [char]10 + 'Via: SIP/2.0/UDP 0.0.0.0:1;branch=z9hG4bKwarmup;rport=1;received=0.0.0.0' + [char]13 + [char]10 + [char]13 + [char]10
    for ($w = 0; $w -lt 3; $w++) {
        $wm = [regex]::Match($warmText, '(?im)^Via:\s*SIP/2\.0/UDP\s+([^;\s]+)\s*;(.*)$')
        [void][regex]::Match($wm.Groups[2].Value, '(?i)branch=([^;\s]+)')
        [void][regex]::Match($wm.Groups[2].Value, '(?i)received=([^;\s]+)')
        [void][regex]::Match($wm.Groups[2].Value, '(?i)rport=(\d+)')
        [void][regex]::Match(($warmText.Split([char]10))[0].Trim(), '^SIP/2\.0\s+(\d{3})')
        [void](New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0))
        [void]$udp.Available
        try { [void]$udp.Client.Poll(0, [System.Net.Sockets.SelectMode]::SelectRead) } catch {}
        [System.Threading.Thread]::SpinWait(100)
        [void](New-SipProbeIds -LocalIp $lip)
    }

    # Pre-roll. The synthetic warm-up above cannot cover the real send path -
    # the first Send() on a connected socket, the first pscustomobject literal,
    # the first List/hashtable insert - and measured, those make probes 0-6 land
    # up to 66 ms late on a FIRST run in a process while a third run is clean
    # (sd 0.002 ms). Left alone that transient alone was worth ~9 ms of
    # instrument sd, i.e. the tool inventing jitter that was not on the wire.
    # So send a few for real and throw the results away. They still reach the
    # PBX, so they are counted against the packet budget.
    for ($w = 0; $w -lt $PrerollCount; $w++) {
        $pIds = New-SipProbeIds -LocalIp $lip
        $pBuf = [System.Text.Encoding]::ASCII.GetBytes((New-SipOptionsMessage -TargetHost $ComputerName -LocalIp $lip -LocalPort $lport -Branch $pIds.Branch -CallId $pIds.CallId -Tag $pIds.Tag -CSeq 0))
        try { [void]$udp.Send($pBuf, $pBuf.Length) } catch {}
        Start-Sleep -Milliseconds 40
        while ($true) {
            try {
                if ($udp.Available -le 0) { break }
                $pEp = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                [void]$udp.Receive([ref]$pEp)
            } catch { break }
        }
    }
    $out.PrerollSent = $PrerollCount

    # A scheduler preemption mid-train shows up as one late packet; nudging the
    # priority makes that rarer. Restored in the finally.
    $prio0 = $null
    try {
        $prio0 = [System.Threading.Thread]::CurrentThread.Priority
        [System.Threading.Thread]::CurrentThread.Priority = [System.Threading.ThreadPriority]::AboveNormal
    } catch { $prio0 = $null }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        while ($true) {

            # ---- send if due (before draining: sending is the time-critical
            #      half, and parsing an inbound reply first would push the next
            #      send late by however long the parse took) ------------------
            if ($sent -lt $count -and ($sw.ElapsedTicks / 10000.0) -ge $nextSend) {
                $sendMs = $sw.ElapsedTicks / 10000.0
                $sendOk = $true
                try { [void]$udp.Send($nxBytes, $nxBytes.Length) }
                catch [System.Net.Sockets.SocketException] {
                    if ($_.Exception.SocketErrorCode -eq [System.Net.Sockets.SocketError]::ConnectionReset) { $icmp++ }
                    $sendOk = $false
                } catch { $sendOk = $false }

                $rec = [pscustomobject]@{
                    Seq = $sent; Branch = $nxIds.Branch; SendMs = $sendMs; RecvMs = -1.0
                    RttMs = -1.0; Answered = $false; SendOk = $sendOk
                    StatusLine = ''; StatusCode = 0
                }
                $pending[$nxIds.Branch] = $rec
                [void]$probes.Add($rec)
                if ($lastSendMs -ge 0) { [void]$sendGaps.Add($sendMs - $lastSendMs) }
                $lastSendMs = $sendMs
                $sent++
                $nextSend = [double]$sent * $IntervalMs   # absolute schedule - no drift accumulation

                if ($sent -lt $count) {
                    $nxIds   = New-SipProbeIds -LocalIp $lip
                    $nxBytes = [System.Text.Encoding]::ASCII.GetBytes((New-SipOptionsMessage -TargetHost $ComputerName -LocalIp $lip -LocalPort $lport -Branch $nxIds.Branch -CallId $nxIds.CallId -Tag $nxIds.Tag -CSeq ($sent + 1)))
                }
            }

            # ---- drain every datagram currently queued -----------------------
            while ($true) {
                $avail = 0
                try { $avail = $udp.Available } catch { break }
                if ($avail -le 0) { break }
                $data = $null
                try {
                    $rep  = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                    $data = $udp.Receive([ref]$rep)
                } catch [System.Net.Sockets.SocketException] {
                    # Available reports 1 when an ICMP error is pending and NO
                    # datagram exists - Receive() then throws. ConnectionReset
                    # here is an ICMP port-unreachable from the PBX: real
                    # information, not a fault, and consuming it clears the
                    # pending error so the train can continue.
                    if ($_.Exception.SocketErrorCode -eq [System.Net.Sockets.SocketError]::ConnectionReset) { $icmp++ }
                    break
                } catch { break }
                if ($null -eq $data -or $data.Length -eq 0) { break }

                $rxMs = $sw.ElapsedTicks / 10000.0
                $text = [System.Text.Encoding]::ASCII.GetString($data)

                # Hot path is branch-match only. The top Via comes back as the
                # SERVER received it, so it is both the transaction key and the
                # SIP ALG evidence - but the ALG detail is identical on every
                # reply, so it is captured once rather than re-parsed 400 times.
                $vm = [regex]::Match($text, '(?im)^Via:\s*SIP/2\.0/UDP\s+([^;\s]+)\s*;(.*)$')
                if (-not $vm.Success) { continue }
                $bm = [regex]::Match($vm.Groups[2].Value, '(?i)branch=([^;\s]+)')
                if (-not $bm.Success) { continue }
                $br = $bm.Groups[1].Value
                if (-not $pending.ContainsKey($br)) { continue }

                $rec = $pending[$br]
                if ($rec.Answered) { $dupes++; continue }
                $rec.Answered   = $true
                $rec.RecvMs     = $rxMs
                $rec.RttMs      = $rxMs - $rec.SendMs
                $rec.StatusLine = ($text.Split([char]10))[0].Trim()
                $sm = [regex]::Match($rec.StatusLine, '^SIP/2\.0\s+(\d{3})')
                if ($sm.Success) { $rec.StatusCode = [int]$sm.Groups[1].Value }

                if (-not $out.ViaHost) {
                    $out.ViaHost = $vm.Groups[1].Value
                    $rm = [regex]::Match($vm.Groups[2].Value, '(?i)received=([^;\s]+)')
                    if ($rm.Success) { $out.Received_ = $rm.Groups[1].Value }
                    $pm = [regex]::Match($vm.Groups[2].Value, '(?i)rport=(\d+)')
                    if ($pm.Success) { $out.Rport = [int]$pm.Groups[1].Value }
                    $out.StatusLine = $rec.StatusLine
                }
                # A 503 (especially with Retry-After) is a throttle signal in its
                # own right, so scan for it on any non-200 rather than only once.
                if ($rec.StatusCode -ne 200 -and -not $out.RetryAfter) {
                    $ra = [regex]::Match($text, '(?im)^Retry-After:\s*(.+?)\s*$')
                    if ($ra.Success) { $out.RetryAfter = $ra.Groups[1].Value.Trim() }
                }

                if ($rec.Seq -lt $maxSeqSeen) { $reordered++ } else { $maxSeqSeen = $rec.Seq }
                $answeredCount++
            }

            # ---- cancellation -----------------------------------------------
            if ($Shared -and $Shared.Cancel) { $out.Cancelled = $true; break }

            # ---- termination -------------------------------------------------
            if ($sent -ge $count) {
                if ($drainUntil -lt 0) { $drainUntil = ($sw.ElapsedTicks / 10000.0) + $TailMs }
                if ($answeredCount -ge $sent) { break }
                if (($sw.ElapsedTicks / 10000.0) -ge $drainUntil) { break }
            }

            # ---- status ------------------------------------------------------
            if ($Shared -and ($sw.ElapsedTicks / 10000.0) -ge $nextStatusMs) {
                $Shared.Status = ('UDP path test ({0}): {1}/{2} probes, {3} replies...' -f $Label, $sent, $count, $answeredCount)
                $nextStatusMs += 1000.0
            }

            # ---- pace --------------------------------------------------------
            # Poll for the bulk of the wait (it also wakes the instant a reply
            # arrives, which keeps receive timestamps honest), then spin the last
            # few ms. The Poll budget leaves a margin for its own overshoot: with
            # the 1 ms timer resolution above that is ~0.5 ms, without it ~16 ms,
            # which is why the fallback margin below is the larger one.
            $margin = 4.0
            if (-not $hiRes) { $margin = 20.0 }
            $target = $nextSend
            if ($sent -ge $count) { $target = $drainUntil }
            $rem = $target - ($sw.ElapsedTicks / 10000.0)
            if ($rem -gt $margin) {
                $budget = [math]::Min($rem - $margin, 10.0)
                try { [void]$udp.Client.Poll([int]($budget * 1000), [System.Net.Sockets.SelectMode]::SelectRead) } catch {}
            } elseif ($rem -gt 0) {
                [System.Threading.Thread]::SpinWait(100)
            }
        }
    } catch {
        $out.Error = $_.Exception.Message
    } finally {
        $sw.Stop()
        try { $udp.Close() } catch {}
        if ($null -ne $prio0) { try { [System.Threading.Thread]::CurrentThread.Priority = $prio0 } catch {} }
        Exit-HighResTimer -WasRaised $hiRes
    }

    # ---- statistics ---------------------------------------------------------
    $all      = @($probes.ToArray())
    $sentOk   = @($all | Where-Object { $_.SendOk })
    $answered = @($all | Where-Object { $_.Answered })
    $out.Probes   = $all
    $out.Sent     = $sentOk.Count
    $out.Received = $answered.Count
    $out.Duplicates      = $dupes
    $out.Reordered       = $reordered
    $out.IcmpUnreachable = $icmp
    $out.NonOkReplies    = @($answered | Where-Object { $_.StatusCode -ne 200 }).Count

    if ($sentOk.Count -gt 0) {
        $out.LossPct           = [math]::Round(100.0 * ($sentOk.Count - $answered.Count) / $sentOk.Count, 3)
        $out.LossResolutionPct = [math]::Round(100.0 / $sentOk.Count, 3)
    }

    if ($answered.Count -gt 0) {
        $rtts   = @($answered | ForEach-Object { [double]$_.RttMs })
        $sorted = @($rtts | Sort-Object)
        $out.RttMinMs = [math]::Round($sorted[0], 2)
        $out.RttP50Ms = [math]::Round((Get-Percentile -Sorted $sorted -Q 0.50), 2)
        $out.RttP95Ms = [math]::Round((Get-Percentile -Sorted $sorted -Q 0.95), 2)
        $out.RttMaxMs = [math]::Round($sorted[$sorted.Count - 1], 2)
        $jit = Measure-JitterRfc3550 -Rtts $rtts -Seqs @($answered | ForEach-Object { [int]$_.Seq })
        $out.JitterMs       = $jit.JitterMs
        $out.JitterMaxMs    = $jit.JitterMaxMs
        $out.JitterFinalMs  = $jit.JitterFinalMs
        $out.MeanAbsDeltaMs = $jit.MeanAbsDeltaMs
        $out.JitterPairs    = $jit.PairsUsed
        $out.Ok             = $true
    }

    # The tool's own send-pacing noise. Reported alongside the network figure so
    # a jitter number below this floor can be shown as "<X ms" instead of being
    # quoted as if it were a measurement. Never subtract one from the other.
    $out.InstrumentPacingSdMs = [math]::Round((Get-StdDev -Values @($sendGaps.ToArray())), 3)
    $maxErr = 0.0
    foreach ($r in $all) {
        $e = [math]::Abs($r.SendMs - ([double]$r.Seq * $IntervalMs))
        if ($e -gt $maxErr) { $maxErr = $e }
    }
    $out.InstrumentPacingMaxErrMs = [math]::Round($maxErr, 2)

    $out.Throttle = Test-ProbeThrottled -Probes $all
    return $out
}

function Get-EmodelMos {
    # ITU-T G.107 (simplified) with G.113 Appendix I impairment constants.
    #
    # WHAT THIS IS NOT: a call quality measurement. It is derived from SIP
    # OPTIONS request/response timing over UDP 5060, not from RTP media, and it
    # assumes a symmetric path (one-way delay = RTT/2), symmetric loss, random
    # (non-bursty) loss, and a jitter buffer of 2x measured jitter. The PBX's
    # OPTIONS responder also adds application-layer latency a media relay would
    # not. Every caller must print that caveat next to the number.
    #
    # G.711 only. G.722 is wideband; the narrowband E-model is not defined for
    # it and would understate it, so this refuses rather than guesses.
    param(
        [double]$RttP50Ms,
        [double]$JitterMs,
        [double]$LossPctRoundTrip,
        [string]$Codec = 'G.711',
        [bool]$Plc = $true,
        [int]$SampleCount = 0
    )
    $out = [pscustomobject]@{
        Ok = $false; Reason = ''; Mos = 0.0; R = 0.0
        OneWayDelayMs = 0.0; OneWayLossPct = 0.0; Codec = $Codec; Plc = $Plc
    }

    # Smallest observable loss is 1/N. Below ~100 probes the loss term is too
    # coarse for the impairment maths to mean anything.
    if ($SampleCount -lt 100) {
        $out.Reason = ('insufficient samples for a MOS estimate ({0} replies; needs 100)' -f $SampleCount)
        return $out
    }
    if ($Codec -ne 'G.711') {
        $out.Reason = ('MOS not computed for {0} - the narrowband E-model does not apply' -f $Codec)
        return $out
    }

    # One-way delay: half the round trip, plus a jitter buffer sized at 2x
    # measured jitter, plus 30 ms for 20 ms packetisation and serialisation.
    $ta = ($RttP50Ms / 2.0) + (2.0 * $JitterMs) + 30.0

    # Measured loss is ROUND TRIP. Under a symmetric assumption the one-way rate
    # is about half; feeding the round-trip figure straight in would roughly
    # double the impairment and understate MOS by a visible margin.
    $ppl = $LossPctRoundTrip / 2.0
    if ($ppl -lt 0) { $ppl = 0.0 }

    $id = 0.024 * $ta
    if ($ta -gt 177.3) { $id += 0.11 * ($ta - 177.3) }

    $ie  = 0.0                                  # G.711 has no compression impairment
    $bpl = 4.3
    if ($Plc) { $bpl = 25.1 }                   # packet loss concealment
    $burstR = 1.0                               # random loss - burstiness is not
                                                # reliably measurable from ~400 samples
    $ieEff = $ie
    if ($ppl -gt 0) { $ieEff = $ie + (95.0 - $ie) * $ppl / (($ppl / $burstR) + $bpl) }

    $r = 93.2 - $id - $ieEff
    if     ($r -lt 0)   { $mos = 1.0 }
    elseif ($r -gt 100) { $mos = 4.5 }
    else { $mos = 1.0 + (0.035 * $r) + ($r * ($r - 60.0) * (100.0 - $r) * 0.000007) }
    if ($mos -lt 1.0) { $mos = 1.0 }
    if ($mos -gt 4.5) { $mos = 4.5 }

    $out.Ok            = $true
    $out.Mos           = [math]::Round($mos, 2)
    $out.R             = [math]::Round($r, 1)
    $out.OneWayDelayMs = [math]::Round($ta, 1)
    $out.OneWayLossPct = [math]::Round($ppl, 3)
    return $out
}

# ---------------------------------------------------------------------------
# STUN (RFC 5389)
# ---------------------------------------------------------------------------
# For a site whose phones are direct remote STUN endpoints, how this NAT maps
# ports is the single most decisive thing about whether calls work. Written by
# hand because .NET Framework 4.x has no STUN client and no BinaryPrimitives -
# [System.Buffers.Binary.BinaryPrimitives] does not resolve and System.Memory
# cannot be loaded, so every field is assembled with explicit byte shifts.
# ---------------------------------------------------------------------------

function New-StunBindingRequest {
    # 20-byte header: type 0x0001, length 0, magic cookie, 96-bit transaction id.
    param([ref]$TxIdOut)
    $b = New-Object byte[] 20
    $b[0] = 0x00; $b[1] = 0x01          # Binding Request
    $b[2] = 0x00; $b[3] = 0x00          # message length: no attributes
    $b[4] = 0x21; $b[5] = 0x12; $b[6] = 0xA4; $b[7] = 0x42   # magic cookie
    $t = New-Object byte[] 12
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    try { $rng.GetBytes($t) } finally { try { $rng.Dispose() } catch {} }
    [System.Array]::Copy($t, 0, $b, 8, 12)
    $TxIdOut.Value = $t
    return ,$b
}

function Read-StunResponse {
    # Parses a Binding Success Response for the mapped address.
    #
    # Every read is bounds-checked and the 4-byte attribute padding is honoured.
    # Both matter: a server that returns SOFTWARE or RESPONSE-ORIGIN before
    # XOR-MAPPED-ADDRESS will desync a parser that ignores padding, and a
    # malformed or hostile response would otherwise throw inside the worker
    # runspace and take the whole scan down with it.
    param([byte[]]$Resp,[byte[]]$TxId)
    $o = [pscustomobject]@{ Ok = $false; Ip = ''; Port = 0; Source = ''; Err = '' }
    if ($null -eq $Resp -or $Resp.Length -lt 20) { $o.Err = 'short response'; return $o }
    if (-not ($Resp[0] -eq 0x01 -and $Resp[1] -eq 0x01)) { $o.Err = 'not a Binding Success Response'; return $o }
    if (-not ($Resp[4] -eq 0x21 -and $Resp[5] -eq 0x12 -and $Resp[6] -eq 0xA4 -and $Resp[7] -eq 0x42)) { $o.Err = 'bad magic cookie'; return $o }
    for ($k = 0; $k -lt 12; $k++) { if ($Resp[8 + $k] -ne $TxId[$k]) { $o.Err = 'transaction id mismatch'; return $o } }

    $mlen = ((([int]$Resp[2]) -shl 8) -bor ([int]$Resp[3]))
    $end  = 20 + $mlen
    if ($end -gt $Resp.Length) { $end = $Resp.Length }

    $i = 20
    while (($i + 4) -le $end) {
        $at = ((([int]$Resp[$i])     -shl 8) -bor ([int]$Resp[$i + 1]))
        $al = ((([int]$Resp[$i + 2]) -shl 8) -bor ([int]$Resp[$i + 3]))
        $v  = $i + 4
        if (($v + $al) -gt $end) { break }
        $pad = (4 - ($al % 4)) % 4

        if ($at -eq 0x0020 -and $al -ge 8 -and $Resp[$v + 1] -eq 0x01) {
            # XOR-MAPPED-ADDRESS, IPv4. Port is XORed with the top 16 bits of the
            # cookie; the address is XORed with the whole cookie (bytes 4..7) -
            # NOT with the transaction id, which is the usual place to go wrong.
            $o.Port = (((([int]$Resp[$v + 2]) -shl 8) -bor ([int]$Resp[$v + 3])) -bxor 0x2112)
            $q = New-Object byte[] 4
            for ($k = 0; $k -lt 4; $k++) { $q[$k] = [byte]((([int]$Resp[$v + 4 + $k]) -bxor ([int]$Resp[4 + $k])) -band 0xFF) }
            $o.Ip     = ([string]$q[0] + '.' + [string]$q[1] + '.' + [string]$q[2] + '.' + [string]$q[3])
            $o.Source = 'XOR-MAPPED-ADDRESS'
            $o.Ok     = $true
            break
        }
        elseif ($at -eq 0x0001 -and $al -ge 8 -and $Resp[$v + 1] -eq 0x01 -and -not $o.Ok) {
            # Legacy MAPPED-ADDRESS: keep looking, XOR-MAPPED-ADDRESS wins.
            $o.Port   = ((([int]$Resp[$v + 2]) -shl 8) -bor ([int]$Resp[$v + 3]))
            $o.Ip     = ([string]$Resp[$v + 4] + '.' + [string]$Resp[$v + 5] + '.' + [string]$Resp[$v + 6] + '.' + [string]$Resp[$v + 7])
            $o.Source = 'MAPPED-ADDRESS'
            $o.Ok     = $true
        }
        $i = $v + $al + $pad
    }
    if (-not $o.Ok -and -not $o.Err) { $o.Err = 'no mapped address attribute' }
    return $o
}

function Invoke-StunQuery {
    # One Binding Request on a CALLER-SUPPLIED socket. The socket is the whole
    # point: NAT mapping behaviour can only be compared across servers if the
    # source port stays the same, so this never binds or closes one itself.
    param(
        $Socket,                      # System.Net.Sockets.UdpClient, already bound
        [string]$Server,
        [int]$Port = 3478,
        [int]$TimeoutMs = 1200,
        [int]$Retries = 2             # a single lost STUN reply must not read as "symmetric"
    )
    $res = [pscustomobject]@{ Ok = $false; Server = $Server; ServerIp = ''; Ip = ''; Port = 0; Source = ''; Err = ''; RttMs = 0.0 }
    try {
        $addrs = [System.Net.Dns]::GetHostAddresses($Server) | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork }
        if (-not $addrs -or @($addrs).Count -eq 0) { $res.Err = 'DNS failed'; return $res }
        $res.ServerIp = (@($addrs)[0]).IPAddressToString
    } catch { $res.Err = 'DNS failed: ' + $_.Exception.Message; return $res }

    $ep = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Parse($res.ServerIp)), $Port
    for ($attempt = 0; $attempt -le $Retries; $attempt++) {
        $txid = $null
        $req  = New-StunBindingRequest -TxIdOut ([ref]$txid)
        $sw   = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            [void]$Socket.Send($req, $req.Length, $ep)
        } catch { $res.Err = $_.Exception.Message; continue }

        $Socket.Client.ReceiveTimeout = $TimeoutMs
        $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
        while ([DateTime]::UtcNow -lt $deadline) {
            try {
                $from = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Any), 0
                $data = $Socket.Receive([ref]$from)
                $p = Read-StunResponse -Resp $data -TxId $txid
                if ($p.Ok) {
                    $sw.Stop()
                    $res.Ok = $true; $res.Ip = $p.Ip; $res.Port = $p.Port; $res.Source = $p.Source
                    $res.RttMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 1)
                    return $res
                }
                # Not ours (stale reply from an earlier attempt, or another
                # protocol on this socket) - keep waiting out the timeout.
            } catch [System.Net.Sockets.SocketException] {
                if ($_.Exception.SocketErrorCode -eq [System.Net.Sockets.SocketError]::ConnectionReset) { continue }
                break
            } catch { break }
        }
        $sw.Stop()
        if (-not $res.Err) { $res.Err = 'no reply' }
    }
    return $res
}

function Get-StunServerList {
    # Ordered candidates, all verified answering from this machine. Deliberately
    # spread across operators and ports, because a site that blocks UDP 3478 or
    # blocks Google must still be classifiable.
    #
    # Notable: stun.3cx.com does NOT answer STUN (resolves, never replies), so
    # it is not here - the obvious choice for a 3CX tool is the wrong one.
    # stun.nextcloud.com answers on 443, which survives firewalls that drop
    # 3478. stun.ekiga.net returns legacy MAPPED-ADDRESS rather than
    # XOR-MAPPED-ADDRESS, so it also exercises the parser's fallback path.
    #
    # stun.counterpath.com is omitted: it resolves to the same IP as
    # stun.ekiga.net, and two names on one host cannot test mapping behaviour.
    return @(
        [pscustomobject]@{ Host = 'stun.l.google.com';        Port = 19302 },
        [pscustomobject]@{ Host = 'stun.sipgate.net';         Port = 3478  },
        [pscustomobject]@{ Host = 'stun.voip.blackberry.com'; Port = 3478  },
        [pscustomobject]@{ Host = 'stun.linphone.org';        Port = 3478  },
        [pscustomobject]@{ Host = 'stun.nextcloud.com';       Port = 443   },
        [pscustomobject]@{ Host = 'stun.ekiga.net';           Port = 3478  }
    )
}

function Get-NatMappingBehaviour {
    # Queries STUN servers from ONE socket and compares the public mapping.
    #
    # Walks the candidate list until two servers with DIFFERENT IPs have
    # answered, rather than hardcoding a pair - measured in the field, popular
    # STUN hosts go away (stun.cloudflare.com has no A record today) and others
    # share an IP, and either would silently invalidate the comparison.
    #
    # Reports MAPPING behaviour only. Filtering behaviour needs RFC 5780
    # CHANGE-REQUEST/OTHER-ADDRESS, which most modern servers no longer
    # implement, so the RFC 3489 labels (Full Cone, Restricted Cone, Port
    # Restricted) are deliberately never printed. Claiming those without running
    # the filtering test would be a confident wrong answer.
    param(
        $Servers        = $null,
        [int]$TimeoutMs = 1200,
        [int]$MaxProbe  = 4,        # give up after this many candidates
        $Socket         = $null     # caller may supply a socket to keep the binding alive
    )
    if ($null -eq $Servers) { $Servers = Get-StunServerList }

    $out = [pscustomobject]@{
        Ok = $false; Behaviour = 'unknown'; Detail = ''; Conclusive = $false
        LocalPort = 0; PublicIp = ''; PortPreserving = $false; MultiWan = $false
        MappedPortA = 0; MappedPortB = 0; ServerA = ''; ServerB = ''
        ServersTried = 0; Results = @()
    }

    $udp = $Socket
    $ownSocket = $false
    try {
        if ($null -eq $udp) {
            $udp = New-Object System.Net.Sockets.UdpClient
            $udp.Client.Bind((New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Any), 0))
            $ownSocket = $true
        }
        $out.LocalPort = ([System.Net.IPEndPoint]$udp.Client.LocalEndPoint).Port

        $good = [System.Collections.Generic.List[object]]::new()
        $seenServerIps = @{}
        $tried = 0
        foreach ($s in @($Servers)) {
            if ($tried -ge $MaxProbe) { break }
            if ($good.Count -ge 2) { break }
            $tried++
            $r = Invoke-StunQuery -Socket $udp -Server $s.Host -Port $s.Port -TimeoutMs $TimeoutMs -Retries 1
            [void]($out.Results += $r)
            if (-not $r.Ok) { continue }
            # Two names on one host do not test two destinations.
            if ($seenServerIps.ContainsKey($r.ServerIp)) { continue }
            $seenServerIps[$r.ServerIp] = $true
            [void]$good.Add($r)
        }
        $out.ServersTried = $tried

        if ($good.Count -eq 0) {
            $out.Behaviour = 'no STUN reply'
            $out.Detail    = ('No STUN server answered after {0} attempts. Outbound UDP to 3478/19302/443 appears to be blocked - which would also stop the phones learning their public address.' -f $tried)
            return $out
        }

        $out.Ok       = $true
        $a            = $good[0]
        $out.PublicIp = $a.Ip
        $out.ServerA  = ('{0} ({1})' -f $a.Server, $a.ServerIp)
        $out.MappedPortA = $a.Port

        if ($good.Count -lt 2) {
            $out.PortPreserving = ($a.Port -eq $out.LocalPort)
            $out.Behaviour = 'inconclusive'
            $out.Detail    = ('Only one STUN server answered ({0}), so the mapping could not be compared across destinations. Public mapping seen: {1}:{2}.' -f $a.Server, $a.Ip, $a.Port)
            return $out
        }

        $b = $good[1]
        $out.ServerB     = ('{0} ({1})' -f $b.Server, $b.ServerIp)
        $out.MappedPortB = $b.Port
        $out.PortPreserving = ($a.Port -eq $out.LocalPort -and $b.Port -eq $out.LocalPort)
        $out.Conclusive     = $true

        if ($a.Ip -ne $b.Ip) {
            # Its own serious finding: 3CX IP allow-lists assume one egress IP.
            $out.MultiWan  = $true
            $out.Behaviour = 'multiple egress IPs'
            $out.Detail    = ('Two STUN servers saw different public IPs ({0} and {1}). The site egresses over more than one WAN. That breaks 3CX IP allow-lists and drops calls whenever the path flips.' -f $a.Ip, $b.Ip)
        }
        elseif ($a.Port -eq $b.Port) {
            $out.Behaviour = 'endpoint-independent'
            $out.Detail    = ('Same public mapping {0}:{1} seen by two independent STUN servers. This NAT is predictable, which is what direct STUN phones need.' -f $a.Ip, $a.Port)
        }
        else {
            $out.Behaviour = 'address-dependent'
            $out.Detail    = ('The public port changed with the destination ({0} vs {1}). This NAT is symmetric-like: STUN cannot predict the media port, so direct STUN phones will get one-way or no audio. Move the phones onto the 3CX Tunnel/SBC.' -f $a.Port, $b.Port)
        }
    } catch {
        $out.Detail = $_.Exception.Message
    } finally {
        if ($ownSocket) { try { $udp.Close() } catch {} }
    }
    return $out
}

function Get-LocalIpForTarget {
    # The source IP the stack would actually use to reach $TargetHost. Taken
    # from a throwaway connected UDP socket rather than from Get-NetIPAddress,
    # because that is what makes multi-homed and VPN machines behave.
    param([string]$TargetHost,[int]$Port = 9)
    $ip = ''
    $s = $null
    try {
        $s = New-Object System.Net.Sockets.Socket ([System.Net.Sockets.AddressFamily]::InterNetwork), ([System.Net.Sockets.SocketType]::Dgram), ([System.Net.Sockets.ProtocolType]::Udp)
        $s.Connect($TargetHost, $Port)
        $ip = ([System.Net.IPEndPoint]$s.LocalEndPoint).Address.ToString()
    } catch { $ip = '' } finally { if ($s) { try { $s.Close() } catch {} } }
    return $ip
}

function Test-SipAlg {
    # Looks for a router rewriting SIP on the way out, using three signals from
    # a single OPTIONS exchange plus a STUN query on the SAME socket.
    #
    #  1. Via host rewritten. RFC 3261 8.2.6.2 - the server copies Via values
    #     into the response, so the echoed Via is the Via AS THE SERVER GOT IT.
    #     If it holds the public IP instead of ours, something rewrote it.
    #
    #  2. rport= vs the STUN mapped port from the same local socket. Equal means
    #     the mapping is endpoint-independent ON THE REAL SIP PATH, not merely
    #     on the STUN path. And rport=5060 when we did not send from 5060 is the
    #     classic ALG signature - it catches ALGs that leave Via alone.
    #
    #  3. received= vs the public IP, which would expose UDP and HTTPS leaving
    #     by different WANs. NOTE: measured against 3CX, received= is NOT sent
    #     even though RFC 3581 asks for it, so this signal is usually absent and
    #     must never be read as "the IPs match".
    #
    # The Contact header is deliberately NOT compared: the server never echoes
    # Contact, so any ALG that rewrites only Contact is simply invisible here.
    param(
        [string]$ComputerName,
        [int]$Port = 5060,
        [string]$PublicIp = '',
        $StunServers = $null,
        [int]$TimeoutMs = 3000
    )
    $out = [pscustomobject]@{
        Ok = $false; AlgDetected = $false; Verdict = 'not tested'; Detail = ''
        LocalIp = ''; LocalPort = 0
        ViaHost = ''; ViaRewritten = $false
        Received = ''; ReceivedPresent = $false; Rport = 0
        StunOk = $false; StunMappedIp = ''; StunMappedPort = 0
        SipPathMappingMatches = $null      # $true / $false / $null when unknown
        MultiWan = $false; Signals = @()
    }
    if ($null -eq $StunServers) { $StunServers = Get-StunServerList }

    $lip = Get-LocalIpForTarget -TargetHost $ComputerName -Port $Port
    if (-not $lip) { $out.Detail = 'Could not determine the local source address for the PBX.'; return $out }
    $out.LocalIp = $lip

    $udp = New-Object System.Net.Sockets.UdpClient
    try {
        # Bind to the interface that reaches the PBX, but stay UNCONNECTED so the
        # one socket can talk to both the STUN server and the PBX - that shared
        # binding is the whole point of signal 2.
        $udp.Client.Bind((New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Parse($lip)), 0))
        $lport = ([System.Net.IPEndPoint]$udp.Client.LocalEndPoint).Port
        $out.LocalPort = $lport

        foreach ($s in @($StunServers)) {
            $sr = Invoke-StunQuery -Socket $udp -Server $s.Host -Port $s.Port -TimeoutMs 1200 -Retries 1
            if ($sr.Ok) {
                $out.StunOk = $true; $out.StunMappedIp = $sr.Ip; $out.StunMappedPort = $sr.Port
                break
            }
        }

        $ids = New-SipProbeIds -LocalIp $lip
        $msg = New-SipOptionsMessage -TargetHost $ComputerName -LocalIp $lip -LocalPort $lport -Branch $ids.Branch -CallId $ids.CallId -Tag $ids.Tag
        $buf = [System.Text.Encoding]::ASCII.GetBytes($msg)
        [void]$udp.Send($buf, $buf.Length, $ComputerName, $Port)

        $udp.Client.ReceiveTimeout = $TimeoutMs
        $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
        $text = ''
        while ([DateTime]::UtcNow -lt $deadline) {
            try {
                $from = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Any), 0
                $data = $udp.Receive([ref]$from)
                $t = [System.Text.Encoding]::ASCII.GetString($data)
                if ($t -match ('(?i)' + [regex]::Escape($ids.Branch))) { $text = $t; break }
            } catch [System.Net.Sockets.SocketException] {
                if ($_.Exception.SocketErrorCode -eq [System.Net.Sockets.SocketError]::ConnectionReset) { continue }
                break
            } catch { break }
        }

        if (-not $text) {
            $out.Verdict = 'no reply'
            $out.Detail  = 'The PBX did not answer OPTIONS on this socket, so SIP ALG could not be tested. A router mangling SIP badly enough is itself one cause of that.'
            return $out
        }
        $out.Ok = $true

        $vm = [regex]::Match($text, '(?im)^Via:\s*SIP/2\.0/UDP\s+([^;\s]+)\s*;(.*)$')
        if ($vm.Success) {
            $out.ViaHost = $vm.Groups[1].Value
            $rm = [regex]::Match($vm.Groups[2].Value, '(?i)received=([^;\s]+)')
            if ($rm.Success) { $out.Received = $rm.Groups[1].Value; $out.ReceivedPresent = $true }
            $pm = [regex]::Match($vm.Groups[2].Value, '(?i)rport=(\d+)')
            if ($pm.Success) { $out.Rport = [int]$pm.Groups[1].Value }
        }

        $sig = [System.Collections.Generic.List[string]]::new()

        # --- signal 1: Via rewritten -----------------------------------------
        $viaIp = ($out.ViaHost -split ':')[0]
        if ($viaIp -and $viaIp -ne $lip) {
            $out.ViaRewritten = $true
            $out.AlgDetected  = $true
            [void]$sig.Add(('Via host came back as {0} but we sent {1} - a device on the path rewrote the SIP headers.' -f $out.ViaHost, $lip))
        }

        # --- signal 2: rport vs STUN mapped port ------------------------------
        if ($out.Rport -gt 0) {
            if ($out.Rport -eq 5060 -and $lport -ne 5060) {
                $out.AlgDetected = $true
                [void]$sig.Add(('The PBX saw our source port as 5060 although we sent from {0}. Rewriting the source port to 5060 is the classic SIP ALG signature.' -f $lport))
            }
            if ($out.StunOk) {
                if ($out.Rport -eq $out.StunMappedPort) {
                    $out.SipPathMappingMatches = $true
                    [void]$sig.Add(('The PBX and the STUN server saw the same public port ({0}), so the NAT mapping is endpoint-independent on the real SIP path.' -f $out.Rport))
                } else {
                    $out.SipPathMappingMatches = $false
                    [void]$sig.Add(('The PBX saw public port {0} but the STUN server saw {1} from the same local socket - the NAT maps by destination, so STUN cannot predict the media port.' -f $out.Rport, $out.StunMappedPort))
                }
            }
        }

        # --- signal 3: received= vs public IP ---------------------------------
        if ($out.ReceivedPresent -and $PublicIp -and $out.Received -ne $PublicIp) {
            $out.MultiWan = $true
            [void]$sig.Add(('The PBX saw us arrive from {0} but HTTPS egresses as {1} - UDP and TCP leave by different WANs, which breaks 3CX IP allow-lists.' -f $out.Received, $PublicIp))
        }

        $out.Signals = @($sig.ToArray())

        if ($out.AlgDetected) {
            $out.Verdict = 'SIP ALG detected'
            $out.Detail  = (@($sig.ToArray()) -join ' ') + ' Disable SIP ALG on the router.'
        } else {
            $out.Verdict = 'not observed on OPTIONS'
            $extra = 'Does not rule out an ALG that only rewrites REGISTER or INVITE, and an ALG that rewrites only Contact is invisible to any OPTIONS-based test. If phones misbehave despite this result, disable SIP ALG on the router anyway.'
            if (-not $out.ReceivedPresent) {
                $extra += ' (3CX does not send received=, so the separate multi-WAN cross-check was not available.)'
            }
            $out.Detail = (@($sig.ToArray()) -join ' ') + ' ' + $extra
        }
    } catch {
        $out.Detail = $_.Exception.Message
    } finally { try { $udp.Close() } catch {} }
    return $out
}

function Wait-Cancellable {
    # Idle wait that stays responsive: checks for cancellation and pushes a
    # countdown so a multi-minute stage does not look like a hang.
    param([int]$Seconds,$Shared = $null,[string]$Message = 'Waiting')
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $Seconds) {
        if ($Shared -and $Shared.Cancel) { $sw.Stop(); return $false }
        if ($Shared) {
            $left = [int][math]::Ceiling($Seconds - $sw.Elapsed.TotalSeconds)
            $Shared.Status = ('{0} - {1}s remaining...' -f $Message, $left)
        }
        Start-Sleep -Milliseconds 250
    }
    $sw.Stop()
    return $true
}

function Test-NatBindingTimeout {
    # How long the router keeps a UDP mapping alive with no traffic on it.
    #
    # Measured by watching whether the PUBLIC PORT changes, not by whether a
    # reply comes back. The obvious version of this test - idle, then re-send
    # SIP OPTIONS and see if the PBX answers - cannot work: our own request
    # re-creates the binding before anything can be observed, so it reports
    # "survived" essentially always. Each STUN probe here also refreshes the
    # binding, so one ladder measures every rung.
    #
    # Structurally blind on a port-preserving NAT: a re-created binding would be
    # handed the same port, so a surviving binding and an expired one look
    # identical. That case reports inconclusive rather than guessing.
    param(
        [int[]]$LadderSeconds = @(30,60,120),
        $StunServers = $null,
        [int]$TimeoutMs = 1200,
        $Shared = $null
    )
    if ($null -eq $StunServers) { $StunServers = Get-StunServerList }
    $out = [pscustomobject]@{
        Ok = $false; Conclusive = $false; Cancelled = $false
        SurvivedSeconds = 0; ExpiredAtSeconds = 0
        Server = ''; LocalPort = 0; InitialPort = 0
        Rungs = @(); Detail = ''
    }

    $udp = New-Object System.Net.Sockets.UdpClient
    try {
        $udp.Client.Bind((New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Any), 0))
        $out.LocalPort = ([System.Net.IPEndPoint]$udp.Client.LocalEndPoint).Port

        # One server for the whole ladder - comparing ports across destinations
        # would confound mapping behaviour with binding lifetime.
        $chosen = $null
        foreach ($s in @($StunServers)) {
            $r = Invoke-StunQuery -Socket $udp -Server $s.Host -Port $s.Port -TimeoutMs $TimeoutMs -Retries 2
            if ($r.Ok) { $chosen = $s; $out.Server = $s.Host; $out.InitialPort = $r.Port; break }
        }
        if ($null -eq $chosen) {
            $out.Detail = 'No STUN server answered, so the NAT binding lifetime could not be measured.'
            return $out
        }
        $out.Ok = $true

        if ($out.InitialPort -eq $out.LocalPort) {
            $out.Detail = ('Inconclusive: this NAT preserves the source port (public {0} = local {0}), so a re-created binding would be given the same port and expiry is undetectable by this method. Leave the phones on a 30s keep-alive, which is short enough for any common NAT.' -f $out.LocalPort)
            return $out
        }

        $rungs = [System.Collections.Generic.List[object]]::new()
        $prev = $out.InitialPort
        foreach ($sec in @($LadderSeconds)) {
            if (-not (Wait-Cancellable -Seconds $sec -Shared $Shared -Message ('NAT binding test: idling {0}s' -f $sec))) {
                $out.Cancelled = $true; break
            }
            $r = Invoke-StunQuery -Socket $udp -Server $chosen.Host -Port $chosen.Port -TimeoutMs $TimeoutMs -Retries 2
            $survived = ($r.Ok -and $r.Port -eq $prev)
            [void]$rungs.Add([pscustomobject]@{ Seconds = $sec; Port = $r.Port; Survived = $survived; Ok = $r.Ok })
            if (-not $r.Ok) {
                $out.Detail = ('STUN stopped answering after the {0}s idle, so the ladder could not be completed.' -f $sec)
                break
            }
            if (-not $survived) {
                $out.ExpiredAtSeconds = $sec
                $out.Conclusive = $true
                break
            }
            $out.SurvivedSeconds = $sec
            $out.Conclusive = $true
            $prev = $r.Port
        }
        $out.Rungs = @($rungs.ToArray())

        if ($out.Conclusive -and -not $out.Detail) {
            if ($out.ExpiredAtSeconds -gt 0) {
                $out.Detail = ('The public port changed after {0}s of idle, so the NAT binding expires within {0}s.' -f $out.ExpiredAtSeconds)
            } else {
                $out.Detail = ('The public port was unchanged after {0}s of idle, so the binding survives at least that long.' -f $out.SurvivedSeconds)
            }
        }
    } catch {
        $out.Detail = $_.Exception.Message
    } finally { try { $udp.Close() } catch {} }
    return $out
}

function Get-NatBindingVerdict {
    # Turns a binding lifetime into advice, against the 30s keep-alive that both
    # Yealink and the 3CX SBC use by default.
    param($Binding,[int]$PhoneKeepAliveSeconds = 30)
    $o = [pscustomobject]@{ Status = 'info'; Text = ''; Detail = '' }
    if ($null -eq $Binding -or -not $Binding.Ok) {
        $o.Text = 'not measured'; $o.Detail = 'NAT binding lifetime was not measured.'; return $o
    }
    if (-not $Binding.Conclusive) {
        $o.Text = 'inconclusive'; $o.Detail = $Binding.Detail; return $o
    }
    if ($Binding.ExpiredAtSeconds -gt 0) {
        $s = $Binding.ExpiredAtSeconds
        if ($s -le $PhoneKeepAliveSeconds) {
            $o.Status = 'fail'
            $o.Text   = ('expires within {0}s' -f $s)
            $o.Detail = ('The NAT drops idle UDP bindings within {0}s, which is at or below the {1}s phone keep-alive. Expect one-way audio and missed inbound calls. Shorten the phone keep-alive below {0}s, or move the phones onto the 3CX Tunnel/SBC.' -f $s, $PhoneKeepAliveSeconds)
        } else {
            $o.Status = 'warn'
            $o.Text   = ('expires within {0}s' -f $s)
            $o.Detail = ('The NAT drops idle UDP bindings within {0}s. The {1}s phone keep-alive is inside that, so it holds - but do not raise it.' -f $s, $PhoneKeepAliveSeconds)
        }
        return $o
    }
    $s = $Binding.SurvivedSeconds
    $o.Status = 'ok'
    $o.Text   = ('survives at least {0}s' -f $s)
    $o.Detail = ('The NAT kept the idle UDP binding for at least {0}s, comfortably longer than the {1}s phone keep-alive.' -f $s, $PhoneKeepAliveSeconds)
    return $o
}

function Get-LocalInterfaceMtu {
    # MTU of the interface that actually carries traffic to $ForTarget.
    #
    # Deliberately NOT "the interface with a default gateway": on this dev
    # machine that picks ZeroTier and reports 2800, which would then be compared
    # against a real path MTU and reported as a constraint that does not exist.
    # Resolving the source address for the specific target is VPN-proof.
    param([string]$ForTarget = '')
    $mtu = 0
    try {
        $lip = ''
        if ($ForTarget) { $lip = Get-LocalIpForTarget -TargetHost $ForTarget }
        if ($lip) {
            $addr = Get-NetIPAddress -IPAddress $lip -AddressFamily IPv4 -ErrorAction Stop | Select-Object -First 1
            if ($addr) {
                $ifx = Get-NetIPInterface -InterfaceIndex $addr.InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop | Select-Object -First 1
                if ($ifx) { return [int]$ifx.NlMtu }
            }
        }
        $cfg = Get-NetIPConfiguration -ErrorAction Stop | Where-Object { $_.IPv4DefaultGateway -and $_.IPv4Address } | Select-Object -First 1
        if ($cfg) {
            $ifx = Get-NetIPInterface -InterfaceIndex $cfg.InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop | Select-Object -First 1
            if ($ifx) { $mtu = [int]$ifx.NlMtu }
        }
    } catch { $mtu = 0 }
    return $mtu
}

function Get-PathMtu {
    # Path MTU by ICMP with the Don't Fragment bit set, binary searched.
    #
    # This is NOT about RTP: a G.711 20 ms packet is ~214 bytes on the wire and
    # could not care less about MTU. It is here because a DF-blackhole path -
    # MTU below ~1400 with ICMP fragmentation-needed filtered - breaks TLS
    # handshakes part-way through, which is the real cause behind "provisioning
    # hangs at 0%" and "the phone reboots forever".
    param(
        [string]$ComputerName,
        [int]$TimeoutMs  = 1500,
        [int]$BudgetMs   = 20000,
        [int]$LocalMtu   = 0
    )
    $out = [pscustomobject]@{
        Ok = $false; PathMtu = 0; LocalMtu = $LocalMtu
        Constrained = $false; Detail = ''; Probes = 0
    }
    if ($out.LocalMtu -le 0) { $out.LocalMtu = Get-LocalInterfaceMtu -ForTarget $ComputerName }

    $ping = New-Object System.Net.NetworkInformation.Ping
    $opts = New-Object System.Net.NetworkInformation.PingOptions
    $opts.DontFragment = $true
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    # Helper: $true = fits, $false = too big, $null = no answer.
    $probe = {
        param([int]$payload)
        $buf = New-Object byte[] $payload
        for ($try = 0; $try -lt 3; $try++) {
            try {
                $r = $ping.Send($ComputerName, $TimeoutMs, $buf, $opts)
                if ($r.Status -eq [System.Net.NetworkInformation.IPStatus]::Success)      { return $true }
                if ($r.Status -eq [System.Net.NetworkInformation.IPStatus]::PacketTooBig) { return $false }
                # TimedOut and friends: retry - loss must not be read as "too big".
            } catch { }
        }
        return $null
    }

    try {
        # Gate: if plain ICMP does not come back, the whole search is a waste of
        # eleven timeouts and would report a fabricated MTU.
        $out.Probes++
        $base = & $probe 32
        if ($base -ne $true) {
            $out.Detail = 'ICMP echo is filtered or unanswered on this path, so path MTU is not measurable from here.'
            return $out
        }

        $lo = 32          # known to fit
        $hi = 1473        # known-or-assumed too big (1472 + 28 = 1500)
        $out.Probes++
        $top = & $probe 1472
        if ($top -eq $true) {
            $out.Ok = $true
            $out.PathMtu = 1500
        } else {
            if ($null -eq $top) {
                $out.Detail = 'ICMP answered at 32 bytes but not at 1472, and not with a too-big response - the path is filtering large echoes, so path MTU is not measurable.'
                return $out
            }
            while (($hi - $lo) -gt 1) {
                if ($sw.Elapsed.TotalMilliseconds -gt $BudgetMs) {
                    $out.Detail = 'Path MTU search ran out of time.'
                    return $out
                }
                $mid = [int](($lo + $hi) / 2)
                $out.Probes++
                $r = & $probe $mid
                if ($r -eq $true)       { $lo = $mid }
                elseif ($r -eq $false)  { $hi = $mid }
                else {
                    $out.Detail = ('Path MTU search stalled: no answer at {0} bytes.' -f $mid)
                    return $out
                }
            }
            $out.Ok = $true
            $out.PathMtu = $lo + 28      # IPv4 header 20 + ICMP header 8
        }

        if ($out.LocalMtu -gt 0 -and $out.PathMtu -lt $out.LocalMtu) {
            $out.Constrained = $true
            $out.Detail = ('Path MTU is {0}, below this machine''s interface MTU of {1} - something on the path is constraining it. If ICMP fragmentation-needed is also filtered, TLS handshakes to the PBX can stall part-way, which looks like provisioning hanging or phones rebooting in a loop.' -f $out.PathMtu, $out.LocalMtu)
        } elseif ($out.LocalMtu -gt 0) {
            $out.Detail = ('Path MTU is {0}, matching this machine''s interface MTU - no constraint on the path.' -f $out.PathMtu)
        } else {
            $out.Detail = ('Path MTU is {0}.' -f $out.PathMtu)
        }
    } catch {
        $out.Detail = $_.Exception.Message
    } finally {
        $sw.Stop()
        try { $ping.Dispose() } catch {}
    }
    return $out
}

function Test-UdpPortUnreachable {
    # POSITIVE-ONLY reachability probe for the RTP media range.
    #
    # On a connected UdpClient, an ICMP type 3 code 3 surfaces as a
    # SocketException with SocketError.ConnectionReset - so a reset proves a
    # datagram reached the PBX AND an ICMP reply came back, i.e. the path is
    # open. Silence proves nothing at all: it is the EXPECTED result when 3CX
    # has the port bound, and it is also what happens when ICMP is filtered or
    # rate-limited. The control port outside the range is what makes the result
    # interpretable.
    #
    # Constraints this design works around:
    #  - Linux rate-limits ICMP unreachables to about one per second per
    #    destination, hence the >=1.2s spacing.
    #  - Only one pending error is queued per socket, hence one socket per port.
    #  - The range is never swept: 2000 ports from one source is a port scan,
    #    would trip Fail2ban and any IDS at the site, and at this spacing would
    #    take about 40 minutes anyway.
    param(
        [string]$ComputerName,
        [int[]]$Ports      = @(9000, 9500, 10999),
        [int]$ControlPort  = 11000,
        [int]$SpacingMs    = 1200,
        [int]$WaitMs       = 900,
        $Shared            = $null
    )
    $out = [pscustomobject]@{
        Ok = $false; Conclusive = $false; Verdict = ''; Detail = ''
        ControlReset = $false; InRangeReset = 0; InRangeSilent = 0; Results = @()
    }

    $probeOne = {
        param([int]$p)
        $res = [pscustomobject]@{ Port = $p; Reset = $false; Err = '' }
        $u = New-Object System.Net.Sockets.UdpClient
        try {
            $u.Connect($ComputerName, $p)
            $b = New-Object byte[] 24      # inert payload; nothing parses this
            [void]$u.Send($b, $b.Length)
            $u.Client.ReceiveTimeout = $WaitMs
            try {
                $ep = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Any), 0
                [void]$u.Receive([ref]$ep)      # a real reply would be a surprise
            } catch [System.Net.Sockets.SocketException] {
                if ($_.Exception.SocketErrorCode -eq [System.Net.Sockets.SocketError]::ConnectionReset) { $res.Reset = $true }
                else { $res.Err = $_.Exception.SocketErrorCode.ToString() }
            }
        } catch { $res.Err = $_.Exception.Message } finally { try { $u.Close() } catch {} }
        return $res
    }

    try {
        $results = [System.Collections.Generic.List[object]]::new()

        if ($Shared) { $Shared.Status = ('RTP range probe: control port {0}...' -f $ControlPort) }
        $ctl = & $probeOne $ControlPort
        $ctl | Add-Member -NotePropertyName Role -NotePropertyValue 'control' -Force
        [void]$results.Add($ctl)
        $out.ControlReset = $ctl.Reset

        foreach ($p in @($Ports)) {
            if ($Shared -and $Shared.Cancel) { break }
            Start-Sleep -Milliseconds $SpacingMs
            if ($Shared) { $Shared.Status = ('RTP range probe: UDP {0}...' -f $p) }
            $r = & $probeOne $p
            $r | Add-Member -NotePropertyName Role -NotePropertyValue 'in-range' -Force
            [void]$results.Add($r)
            if ($r.Reset) { $out.InRangeReset++ } else { $out.InRangeSilent++ }
        }
        $out.Results = @($results.ToArray())
        $out.Ok = $true

        # Interpretation. An ICMP port-unreachable from ANY probed port is the
        # positive result: it proves a UDP datagram reached the PBX in the media
        # range and an ICMP reply got back, so the path is open.
        #
        # An unbound RTP port is NOT a fault and must never be reported as one.
        # 3CX allocates media ports per call, so on an idle PBX the whole range
        # is legitimately closed - measured against a live PBX, 9000/9500/10999
        # all returned unreachable while the site was working perfectly well.
        if ($out.InRangeReset -gt 0) {
            $out.Conclusive = $true
            $out.Verdict = 'path open'
            $out.Detail  = ('UDP datagrams reached the PBX in the media range and ICMP replies came back ({0} of {1} probed ports responded), so nothing between here and the PBX is dropping UDP to 9000-10999. The ports themselves are not bound, which is normal - 3CX allocates RTP ports per call. This does not prove media will flow during a call.' -f $out.InRangeReset, @($Ports).Count)
        } elseif ($out.ControlReset) {
            $out.Conclusive = $true
            $out.Verdict = 'media ports silent, ICMP works'
            $out.Detail  = ('ICMP comes back from this host (control port {0} answered) but every probed media port stayed silent. That is consistent with 3CX holding the range bound, and equally consistent with the media range being firewalled - this test cannot separate the two. Verify UDP 9000-10999 at the firewall.' -f $ControlPort)
        } else {
            $out.Verdict = 'inconclusive'
            $out.Detail  = 'Nothing returned an ICMP port-unreachable, so ICMP is filtered or rate-limited somewhere on this path. This test can say nothing about the RTP range - verify UDP 9000-10999 at the firewall.'
        }
    } catch {
        $out.Detail = $_.Exception.Message
    }
    return $out
}

# ---------------------------------------------------------------------------
# Site health
# ---------------------------------------------------------------------------
# Worst-of-MEASURED subscores, as a colour rather than a number.
#
# Weakest link, not a weighted average: an excellent MOS must not be allowed to
# average away a symmetric NAT, because the NAT is what will actually break
# every call. And no 0-100 score - aggregating one real measurement, two
# heuristics and a model estimate into "73" is false precision. "Not measured"
# is a first-class state that never drags the result down but is always listed,
# so the reader can tell a healthy site from an untested one.
# ---------------------------------------------------------------------------

function New-HealthSubscore {
    param(
        [string]$Name,
        [ValidateSet('green','amber','red','notmeasured')][string]$Level,
        [string]$Summary,
        [string]$Remedy = ''
    )
    [pscustomobject]@{ Name = $Name; Level = $Level; Summary = $Summary; Remedy = $Remedy }
}

function Get-ConnectivitySubscore {
    param($OpenMap,[bool]$SipUdpOk)
    $prov   = ([bool]$OpenMap[443] -or [bool]$OpenMap[5001])
    $tls    = [bool]$OpenMap[5061]
    $sipAny = ($SipUdpOk -or $tls -or [bool]$OpenMap[5060])

    if (-not $prov) {
        return New-HealthSubscore -Name 'Connectivity' -Level 'red' `
            -Summary 'Provisioning unreachable - neither 443 nor 5001 answered.' `
            -Remedy 'Phones cannot fetch their configuration. Check DNS, the site firewall and that the PBX is running.'
    }
    if (-not $sipAny) {
        return New-HealthSubscore -Name 'Connectivity' -Level 'red' `
            -Summary 'No SIP path - neither UDP 5060 nor TLS 5061 is usable.' `
            -Remedy 'Phones cannot register. Check the firewall for outbound SIP, and check for SIP ALG.'
    }
    if (-not $SipUdpOk -and $tls) {
        return New-HealthSubscore -Name 'Connectivity' -Level 'amber' `
            -Summary 'Provisioning is up and TLS 5061 is open, but UDP 5060 did not answer.' `
            -Remedy 'Fine if the phones are configured for SIP over TLS. If any phone uses UDP SIP it will fail - check for SIP ALG or a UDP block.'
    }
    return New-HealthSubscore -Name 'Connectivity' -Level 'green' `
        -Summary 'Provisioning reachable and a SIP path answers.'
}

function Get-PathQualitySubscore {
    param($Train,$Mos)
    if ($null -eq $Train -or -not $Train.Ok) {
        return New-HealthSubscore -Name 'UDP path quality' -Level 'notmeasured' `
            -Summary 'The UDP path test did not run or got no replies.'
    }
    if ($Train.Throttle -and $Train.Throttle.Throttled) {
        # Not red: we do not know the path is bad, we know we were blocked.
        return New-HealthSubscore -Name 'UDP path quality' -Level 'notmeasured' `
            -Summary ('Replies stopped at packet {0} of {1} and never resumed - the PBX rate-limited or blacklisted this source, so the figures are invalid.' -f $Train.Throttle.StoppedAtPacket, $Train.Throttle.Total) `
            -Remedy 'Check 3CX Console > Security > Blacklisted IPs for this site''s public IP, then re-run with the gentle rate.'
    }

    $loss = [double]$Train.LossPct
    $jit  = [double]$Train.JitterMs
    $p95  = [double]$Train.RttP95Ms
    $mosTxt = ''
    if ($Mos -and $Mos.Ok) { $mosTxt = (' Estimated MOS {0}.' -f $Mos.Mos) }

    $summary = ('loss {0}%, jitter {1} ms, RTT p95 {2} ms.{3}' -f $loss, $jit, $p95, $mosTxt)

    if ($loss -lt 0.5 -and $jit -lt 10 -and $p95 -lt 100) {
        return New-HealthSubscore -Name 'UDP path quality' -Level 'green' -Summary $summary
    }
    if ($loss -lt 2 -and $jit -lt 30 -and $p95 -lt 200) {
        return New-HealthSubscore -Name 'UDP path quality' -Level 'amber' -Summary $summary `
            -Remedy 'Callers will notice this under load. Check for contention on the uplink, enable QoS for voice, and confirm no Wi-Fi hop carries the phones.'
    }
    return New-HealthSubscore -Name 'UDP path quality' -Level 'red' -Summary $summary `
        -Remedy 'This path will drop and break up calls. Investigate the WAN link, contention and QoS before blaming the PBX.'
}

function Get-NatSubscore {
    param($Mapping,$Alg,$Binding,[bool]$LocalSbcFound = $false,[int]$PhoneKeepAliveSeconds = 30)
    $notes  = [System.Collections.Generic.List[string]]::new()
    $level  = 'green'
    $remedy = ''

    # --- mapping -----------------------------------------------------------
    if ($null -eq $Mapping -or -not $Mapping.Ok) {
        return New-HealthSubscore -Name 'NAT suitability' -Level 'notmeasured' `
            -Summary 'NAT mapping behaviour was not measured - no STUN server answered.' `
            -Remedy 'Outbound UDP to STUN appears blocked, which would also stop the phones learning their public address. Check the firewall.'
    }
    if ($Mapping.MultiWan) {
        $level = 'red'
        [void]$notes.Add('the site egresses over more than one WAN IP')
        $remedy = 'Pin voice traffic to a single WAN, or the 3CX IP allow-list and the media path will disagree. '
    } elseif ($Mapping.Behaviour -eq 'address-dependent') {
        $level = 'red'
        [void]$notes.Add('the NAT maps by destination (symmetric-like)')
        $remedy = 'Direct STUN phones cannot work reliably behind this NAT - move them onto the 3CX Tunnel/SBC. '
    } elseif ($Mapping.Behaviour -eq 'endpoint-independent') {
        [void]$notes.Add('endpoint-independent NAT mapping')
    } else {
        [void]$notes.Add(('NAT mapping {0}' -f $Mapping.Behaviour))
    }

    # --- SIP ALG -----------------------------------------------------------
    if ($Alg -and $Alg.AlgDetected) {
        [void]$notes.Add('SIP ALG is rewriting SIP')
        if ($LocalSbcFound) {
            if ($level -eq 'green') { $level = 'amber' }
        } else {
            $level = 'red'
        }
        $remedy += 'Disable SIP ALG / SIP transformations on the router. '
    } elseif ($Alg -and $Alg.Ok) {
        [void]$notes.Add('no SIP ALG seen on OPTIONS')
    }

    # --- binding lifetime ---------------------------------------------------
    if ($Binding -and $Binding.Ok -and $Binding.Conclusive) {
        if ($Binding.ExpiredAtSeconds -gt 0) {
            $s = $Binding.ExpiredAtSeconds
            [void]$notes.Add(('NAT UDP bindings expire within {0}s' -f $s))
            if ($s -le $PhoneKeepAliveSeconds) {
                $level = 'red'
                $remedy += ('The {0}s binding lifetime is at or below the {1}s phone keep-alive - shorten the keep-alive or use the SBC. ' -f $s, $PhoneKeepAliveSeconds)
            } elseif ($s -lt 60) {
                if ($level -eq 'green') { $level = 'amber' }
                $remedy += 'Keep the phone keep-alive at 30s and do not raise it. '
            }
        } else {
            [void]$notes.Add(('NAT bindings survive at least {0}s' -f $Binding.SurvivedSeconds))
        }
    }

    return New-HealthSubscore -Name 'NAT suitability' -Level $level `
        -Summary ((@($notes.ToArray()) -join '; ') + '.') -Remedy $remedy.Trim()
}

function Get-SiteHealth {
    # Overall = the worst MEASURED subscore. Untested checks are listed but
    # never lower the result, so "green with 2 not measured" stays honest.
    param($Subscores)
    $all = @($Subscores | Where-Object { $_ })
    $rank = @{ 'red' = 0; 'amber' = 1; 'green' = 2 }
    $measured = @($all | Where-Object { $_.Level -ne 'notmeasured' })
    $unmeasured = @($all | Where-Object { $_.Level -eq 'notmeasured' })

    $out = [pscustomobject]@{
        Overall = 'notmeasured'; Headline = ''; Subscores = $all
        NotMeasured = @($unmeasured | ForEach-Object { $_.Name })
        Actions = @()
    }
    if ($measured.Count -eq 0) {
        $out.Headline = 'Nothing could be measured - see the rows above.'
        return $out
    }

    $worst = 'green'
    foreach ($s in $measured) { if ($rank[$s.Level] -lt $rank[$worst]) { $worst = $s.Level } }
    $out.Overall = $worst

    $label = @{ 'green' = 'GOOD'; 'amber' = 'MARGINAL'; 'red' = 'PROBLEM' }
    $txt = ('Site health: {0}' -f $label[$worst])
    $drivers = @($measured | Where-Object { $_.Level -eq $worst } | ForEach-Object { $_.Name })
    if ($worst -ne 'green') { $txt += (' - driven by: {0}' -f ($drivers -join ', ')) }
    if ($unmeasured.Count -gt 0) {
        $txt += (' ({0} check{1} not measurable: {2})' -f $unmeasured.Count, $(if ($unmeasured.Count -eq 1) { '' } else { 's' }), (($unmeasured | ForEach-Object { $_.Name }) -join ', '))
    }
    $out.Headline = $txt + '.'
    $out.Actions  = @($all | Where-Object { $_.Remedy } | ForEach-Object { $_.Remedy })
    return $out
}

# ---------------------------------------------------------------------------
# Security - read-only
# ---------------------------------------------------------------------------
# Three sources, each reporting only what it can actually see:
#   * the PBX's own event log export (CSV): tunnel history, attacks, blacklisting
#   * the PBX's IP blacklist page, pasted in: the allow list against the site's
#     real public IP
#   * this PC: what listens, what Windows Firewall lets in, and who can read the
#     SBC's config (it holds the tunnel password)
#
# What none of them can see is the router's port forwards. Testing the site's own
# public IP from inside the LAN depends on the router's hairpin NAT, so it would
# report the router's behaviour rather than the internet's view. Not attempted.
#
# Nothing here writes anything, and no raw event text reaches a report: a 3CX
# event can carry a whole INVITE, including digest responses and SRTP keys.
# ---------------------------------------------------------------------------

function New-SecFinding {
    param([string]$Severity,[string]$Area,[string]$Finding,[string]$Action = '')
    return [pscustomobject]@{ Severity = $Severity; Area = $Area; Finding = $Finding; Action = $Action }
}

function Get-SecSeverityRank {
    param([string]$Severity)
    switch ($Severity) { 'high' { return 0 } 'review' { return 1 } 'info' { return 2 } 'ok' { return 3 } }
    return 4
}

function Format-SecDuration {
    param([double]$Minutes)
    $sec = [int][math]::Round($Minutes * 60)
    if ($sec -lt 60)   { return ('{0}s' -f $sec) }
    if ($sec -lt 3600) { return ('{0}m{1:00}s' -f [int][math]::Floor($sec / 60), ($sec % 60)) }
    $m = [int][math]::Round($sec / 60.0)
    return ('{0}h{1:00}m' -f [int][math]::Floor($m / 60), ($m % 60))
}

# ---- IP arithmetic (IPv4 only - 3CX's blacklist page is IPv4) ----

function ConvertTo-IpUInt32 {
    param([string]$Ip)
    $a = $null
    if (-not [System.Net.IPAddress]::TryParse(([string]$Ip).Trim(), [ref]$a)) { return $null }
    if ($a.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $null }
    $b = $a.GetAddressBytes()
    return ([uint32]$b[0] * 16777216 + [uint32]$b[1] * 65536 + [uint32]$b[2] * 256 + [uint32]$b[3])
}

function Test-PrivateAddress {
    # RFC 1918, CGNAT, link-local, loopback - and the IPv6 equivalents.
    param([string]$Ip)
    $s = ([string]$Ip).Trim()
    if ($s -match '^(::1$|fe80:|fc|fd)') { return $true }
    $n = ConvertTo-IpUInt32 $s
    if ($null -eq $n) { return $false }
    foreach ($r in @(@('10.0.0.0', 8), @('172.16.0.0', 12), @('192.168.0.0', 16), @('100.64.0.0', 10), @('169.254.0.0', 16), @('127.0.0.0', 8))) {
        $base = [double](ConvertTo-IpUInt32 $r[0])
        $size = [math]::Pow(2, 32 - $r[1])
        if ($n -ge $base -and $n -lt ($base + $size)) { return $true }
    }
    return $false
}

# ---- 3CX event log export ----

function ConvertFrom-3cxEventTime {
    # The export writes "2026-09-06 21:37:39Z" - UTC. Returns a UTC DateTime, or $null.
    param([string]$Text)
    $ci = [System.Globalization.CultureInfo]::InvariantCulture
    $st = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    $t = [datetime]::MinValue
    foreach ($f in @("yyyy-MM-dd HH:mm:ss'Z'", 'yyyy-MM-dd HH:mm:ss', "yyyy-MM-dd'T'HH:mm:ss'Z'", "yyyy-MM-dd'T'HH:mm:ss.fff'Z'", 'yyyy/MM/dd HH:mm:ss')) {
        if ([datetime]::TryParseExact(([string]$Text).Trim(), $f, $ci, $st, [ref]$t)) { return $t }
    }
    return $null
}

function Import-3cxEventLog {
    # Reads the CSV the 3CX admin console exports from its event log. Refuses a file
    # that is not one, rather than analysing the wrong thing.
    param([string]$Path)
    $rows = @(Import-Csv -LiteralPath $Path -ErrorAction Stop)
    if (@($rows).Count -eq 0) { throw 'The file has no rows.' }
    $cols = @($rows[0].PSObject.Properties | ForEach-Object { ([string]$_.Name).Trim([char]0xFEFF, ' ') })
    foreach ($need in @('Event ID', 'Date & Time', 'Details')) {
        if ($cols -notcontains $need) {
            throw ('This does not look like a 3CX event log export: expected the columns "Event ID", "Date & Time" and "Details", found: ' + ($cols -join ', '))
        }
    }
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $rows) {
        $id = 0
        [void][int]::TryParse(([string]$r.'Event ID').Trim(), [ref]$id)
        $ts = ([string]$r.'Date & Time').Trim()
        $lvl = ''
        foreach ($p in $r.PSObject.Properties) { if (([string]$p.Name).Trim([char]0xFEFF, ' ') -eq 'Level') { $lvl = [string]$p.Value } }
        $out.Add([pscustomobject]@{
            Level   = $lvl
            Id      = $id
            TimeUtc = (ConvertFrom-3cxEventTime $ts)
            Zoned   = ($ts -match 'Z$')
            Details = [string]$r.Details
            Source  = [string]$r.Source
        })
    }
    return @($out.ToArray())
}

function Get-SbcTunnelHistory {
    # Event 4102 is the PBX's own record of each SBC going Down and coming back Up -
    # the authoritative tunnel history. It says WHEN, not why. When the SBC is on
    # this PC its own logs and Windows' restart events say why, and on a real site
    # they matched the PBX to the second:
    #   -SbcEvents    typed events from the SBC log   { TimeUtc; Kind }
    #   -SbcStops     stops from the supervisor log   { TimeUtc; Kind }
    #   -WinRestarts  Windows 1074/6008/41            { TimeUtc; Id; Process; Reason }
    # Each outage gets a CauseKind: reboot, service, stopped, dns, connect, or ''
    # (no record either way - never guessed).
    #
    # Times are shown in -TimeZone (default: this PC's zone, which is site time
    # when the tool runs on site).
    param(
        $Events,
        [System.TimeZoneInfo]$TimeZone = [System.TimeZoneInfo]::Local,
        $SbcEvents = @(),
        $SbcStops = @(),
        $WinRestarts = @(),
        [string[]]$LocalIps = @(),
        [int]$ClusterMinutes = 15
    )
    $rx = "Trunk SBC '(?<name>[^']+)' \((?<pub>[^/)]*)/(?<lan>[^)]*)\) has changed status to (?<st>\w+)"
    $ev = @(@($Events) | Where-Object { $_.Id -eq 4102 -and $_.TimeUtc } | Sort-Object TimeUtc)
    $timed = @(@($Events) | Where-Object { $_.TimeUtc } | Sort-Object TimeUtc)
    $endUtc = $null
    if (@($timed).Count -gt 0) { $endUtc = $timed[-1].TimeUtc }

    $bySbc = [ordered]@{}
    foreach ($e in $ev) {
        $m = [regex]::Match([string]$e.Details, $rx)
        if (-not $m.Success) { continue }
        $n = $m.Groups['name'].Value
        if (-not $bySbc.Contains($n)) {
            $bySbc[$n] = [pscustomobject]@{
                Name = $n; PublicIp = $m.Groups['pub'].Value.Trim(); LanIp = $m.Groups['lan'].Value.Trim()
                IsThisPc = $false; Events = [System.Collections.Generic.List[object]]::new()
                Outages = [System.Collections.Generic.List[object]]::new()
                TotalMinutes = 0.0; LastState = ''; LastChangeUtc = $null; Recurring = @()
            }
        }
        $bySbc[$n].Events.Add([pscustomobject]@{ TimeUtc = $e.TimeUtc; State = $m.Groups['st'].Value })
    }

    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($k in $bySbc.Keys) {
        $s = $bySbc[$k]
        if (@($LocalIps) -contains $s.LanIp) { $s.IsThisPc = $true }
        $downAt = $null; $first = $true
        foreach ($x in $s.Events) {
            if ($x.State -eq 'Down') {
                if ($null -eq $downAt) { $downAt = $x.TimeUtc }
            } elseif ($x.State -eq 'Up') {
                if ($null -ne $downAt) {
                    $s.Outages.Add([pscustomobject]@{ DownUtc = $downAt; UpUtc = $x.TimeUtc; Minutes = ($x.TimeUtc - $downAt).TotalMinutes; StillDown = $false; StartUnknown = $false; CauseKind = ''; Cause = '' })
                    $downAt = $null
                } elseif ($first) {
                    # Up with no Down before it: the outage began before the export did.
                    $s.Outages.Add([pscustomobject]@{ DownUtc = $null; UpUtc = $x.TimeUtc; Minutes = 0.0; StillDown = $false; StartUnknown = $true; CauseKind = ''; Cause = '' })
                }
            }
            $first = $false
            $s.LastState = $x.State; $s.LastChangeUtc = $x.TimeUtc
        }
        if ($null -ne $downAt) {
            $mins = 0.0
            if ($endUtc) { $mins = ($endUtc - $downAt).TotalMinutes }
            $s.Outages.Add([pscustomobject]@{ DownUtc = $downAt; UpUtc = $null; Minutes = $mins; StillDown = $true; StartUnknown = $false; CauseKind = ''; Cause = '' })
        }
        # Why - only for the SBC on this PC, whose logs these are.
        if ($s.IsThisPc) {
            $ci2 = [System.Globalization.CultureInfo]::InvariantCulture
            $hm = { param($u) ([System.TimeZoneInfo]::ConvertTimeFromUtc($u, $TimeZone)).ToString('HH:mm:ss', $ci2) }
            foreach ($o in $s.Outages) {
                if (-not $o.DownUtc) { continue }
                $to = $endUtc; if ($o.UpUtc) { $to = $o.UpUtc.AddSeconds(30) }
                $from = $o.DownUtc.AddSeconds(-180)
                $stop = @(@($SbcStops) | Where-Object { $_.TimeUtc -ge $from -and $_.TimeUtc -le $o.DownUtc.AddSeconds(60) } | Sort-Object TimeUtc) | Select-Object -First 1
                $win  = @(@($WinRestarts) | Where-Object { $_.TimeUtc -ge $o.DownUtc.AddMinutes(-10) -and $_.TimeUtc -le $to } | Sort-Object { if ($_.Id -eq 1074) { 0 } else { 1 } }, TimeUtc) | Select-Object -First 1
                $inWin = @(@($SbcEvents) | Where-Object { $_.TimeUtc -ge $from -and $_.TimeUtc -le $to })
                $dns   = @($inWin | Where-Object { $_.Kind -eq 'dns' }).Count
                $conn  = @($inWin | Where-Object { $_.Kind -eq 'timeout' -or $_.Kind -eq 'refused' }).Count
                $nst   = @($inWin | Where-Object { $_.Kind -eq 'start' }).Count
                $wtxt = Get-RestartCauseText $win
                if ($stop -and $stop.Kind -eq 'os-shutdown' -or (-not $stop -and $win)) {
                    $o.CauseKind = 'reboot'
                    $o.Cause = 'this PC restarted'
                    if ($stop) { $o.Cause = ('the SBC stopped at {0} as Windows shut down - this PC restarting' -f (& $hm $stop.TimeUtc)) }
                    if ($wtxt) { $o.Cause += ('; ' + $wtxt) }
                } elseif ($stop -and $stop.Kind -eq 'service-stop') {
                    $o.CauseKind = 'service'
                    $o.Cause = ('the 3CXSBC service was stopped at {0} (a person, a script or an installer)' -f (& $hm $stop.TimeUtc))
                } elseif ($stop) {
                    $o.CauseKind = 'stopped'
                    $o.Cause = ('the SBC was stopped at {0} by a console/shutdown signal' -f (& $hm $stop.TimeUtc))
                } elseif ($dns -ge 3) {
                    $o.CauseKind = 'dns'
                    # The SBC's log shows THIS PC failing to look the PBX up. It cannot
                    # show whether the whole site was offline or only this PC's DNS was:
                    # on the real site every phone used a different path (a Router Phone).
                    $o.Cause = ('DNS: this PC could not look up the PBX ({0} failed lookups)' -f $dns)
                    if ($nst -gt 1) { $o.Cause += ('; the SBC restarted {0} times while retrying and reconnected on its own when lookups worked again' -f $nst) }
                } elseif ($conn -gt 0) {
                    $o.CauseKind = 'connect'
                    $o.Cause = ('the SBC kept trying but could not connect ({0} timeouts/refusals) - network or PBX side' -f $conn)
                }
            }
        }
        $tot = 0.0
        foreach ($o in $s.Outages) { $tot += $o.Minutes }
        $s.TotalMinutes = $tot

        # Same time of day on different days points at something scheduled - but only
        # among outages with the same cause. On the real site a reboot at 07:36 and a
        # DNS failure at 07:40 thirteen days apart would otherwise pose as a pattern.
        $starts = @($s.Outages | Where-Object { $_.DownUtc } | ForEach-Object {
            $l = [System.TimeZoneInfo]::ConvertTimeFromUtc($_.DownUtc, $TimeZone)
            [pscustomobject]@{ Local = $l; Mod = $l.Hour * 60 + $l.Minute; Kind = [string]$_.CauseKind }
        } | Sort-Object Kind, Mod)
        $groups = [System.Collections.Generic.List[object]]::new()
        $cur = $null
        foreach ($st in $starts) {
            if ($cur -and $st.Kind -eq $cur[0].Kind -and ($st.Mod - $cur[0].Mod) -le $ClusterMinutes) { $cur.Add($st) }
            else { $cur = [System.Collections.Generic.List[object]]::new(); $cur.Add($st); $groups.Add($cur) }
        }
        $rec = [System.Collections.Generic.List[string]]::new()
        $ci = [System.Globalization.CultureInfo]::InvariantCulture
        foreach ($g in $groups) {
            $days = @($g | ForEach-Object { $_.Local.Date } | Sort-Object -Unique)
            if (@($days).Count -lt 2) { continue }
            $lo = $g[0].Local.ToString('HH:mm', $ci); $hi = $g[$g.Count - 1].Local.ToString('HH:mm', $ci)
            $span = $lo; if ($hi -ne $lo) { $span = ($lo + '-' + $hi) }
            $dl = (@($g | Sort-Object Local | ForEach-Object { $_.Local.ToString('ddd d MMM', $ci) }) -join ', ')
            $what = switch ($g[0].Kind) { 'reboot' { 'restarts of this PC' } 'service' { 'service stops' } 'dns' { 'DNS failures on this PC' } 'connect' { 'connection failures' } default { 'outages' } }
            [void]$rec.Add(('{0} {1} at {2} ({3})' -f $g.Count, $what, $span, $dl))
        }
        $s.Recurring = @($rec.ToArray())
        $out.Add($s)
    }
    return @($out.ToArray())
}

function Get-3cxAttackSummary {
    # Summarises what the PBX turned away. Extracts fields only - never the raw
    # INVITE text, which can carry digest responses and SRTP keys.
    param($Events, [int]$Top = 5)
    $o = [pscustomobject]@{
        Scans = 0; ScanSources = 0; ScanDays = 0; ScanPeakPerDay = 0; ScanUserAgents = 0
        TopSources = @(); TopPrefixes = @(); TopPrefixShare = 0; TopTargets = @()
        Blacklists = @(); WanBlocks = @(); NoRoute = @(); TrunkFailures = 0; TrunkSample = ''
        OtherIds = @()
    }
    $known = @(30051, 12290, 12291, 30052, 12294, 4102)

    # 30051 - unsolicited INVITEs: scanners and toll-fraud probes.
    $inv = @(@($Events) | Where-Object { $_.Id -eq 30051 })
    $o.Scans = @($inv).Count
    if ($o.Scans -gt 0) {
        $src = @{}; $ua = @{}; $day = @{}; $tgt = @{}
        foreach ($e in $inv) {
            $d = [string]$e.Details
            $ip = ''
            $m = [regex]::Match($d, 'received=([0-9]{1,3}(?:\.[0-9]{1,3}){3})')
            if ($m.Success) { $ip = $m.Groups[1].Value }
            else {
                $m = [regex]::Match($d, '(?m)^Via:\s*SIP/2\.0/\w+\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})')
                if ($m.Success) { $ip = $m.Groups[1].Value }
            }
            if ($ip) { $src[$ip] = 1 + [int]$src[$ip] }
            $m = [regex]::Match($d, '(?m)^User-Agent:\s*(.+?)\s*$')
            if ($m.Success) { $ua[$m.Groups[1].Value] = 1 }
            if ($e.TimeUtc) { $dk = $e.TimeUtc.ToString('yyyy-MM-dd'); $day[$dk] = 1 + [int]$day[$dk] }
            $m = [regex]::Match($d, '(?m)^INVITE sip:([^@;>\s]+)@')
            if ($m.Success) {
                $num = $m.Groups[1].Value
                $digits = ($num -replace '[^0-9]', '')
                # Group dialling-prefix variants of one number (+44..., 0044..., 01144...)
                # by their last ten digits.
                $key = $num
                if ($digits.Length -ge 10) { $key = $digits.Substring($digits.Length - 10) }
                if (-not $tgt.ContainsKey($key)) { $tgt[$key] = @{ Count = 0; Forms = @{} } }
                $tgt[$key].Count++
                $tgt[$key].Forms[$num] = 1 + [int]$tgt[$key].Forms[$num]
            }
        }
        $o.ScanSources = $src.Count
        $o.ScanUserAgents = $ua.Count
        $o.ScanDays = $day.Count
        if ($day.Count -gt 0) { $o.ScanPeakPerDay = [int](@($day.Values) | Measure-Object -Maximum).Maximum }
        $o.TopSources = @($src.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First $Top | ForEach-Object { [pscustomobject]@{ Ip = $_.Key; Count = [int]$_.Value } })
        $pre = @{}
        foreach ($kv in $src.GetEnumerator()) {
            $p24 = (($kv.Key -split '\.')[0..2] -join '.') + '.0/24'
            $pre[$p24] = [int]$pre[$p24] + [int]$kv.Value
        }
        $o.TopPrefixes = @($pre.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First $Top | ForEach-Object { [pscustomobject]@{ Prefix = $_.Key; Count = [int]$_.Value } })
        $sum = 0
        foreach ($t in @($o.TopPrefixes | Select-Object -First 2)) { $sum += $t.Count }
        $o.TopPrefixShare = [int][math]::Round(100.0 * $sum / $o.Scans)
        $o.TopTargets = @($tgt.GetEnumerator() | Sort-Object { $_.Value.Count } -Descending | Select-Object -First $Top | ForEach-Object {
            $forms = $_.Value.Forms
            $main = @($forms.GetEnumerator() | Sort-Object Value -Descending)[0].Key
            [pscustomobject]@{ Number = $main; Count = [int]$_.Value.Count; Variants = [int]$forms.Count }
        })
    }

    # 12290 - blacklisted for brute force.
    $bl = [System.Collections.Generic.List[object]]::new()
    foreach ($e in @(@($Events) | Where-Object { $_.Id -eq 12290 })) {
        $m = [regex]::Match([string]$e.Details, 'The IP (?<ip>[0-9A-Fa-f.:]+) has been blacklisted for (?<sec>\d+) sec')
        if (-not $m.Success) { continue }
        $bl.Add([pscustomobject]@{ Ip = $m.Groups['ip'].Value; Seconds = [int]$m.Groups['sec'].Value; Source = ([string]$e.Source).Trim(); TimeUtc = $e.TimeUtc })
    }
    $o.Blacklists = @($bl.ToArray())

    # 12291 - rejected by "Block WAN requests". The username an attempt presented
    # is the useful part: it names the extension being attacked.
    $wb = [System.Collections.Generic.List[object]]::new()
    foreach ($e in @(@($Events) | Where-Object { $_.Id -eq 12291 })) {
        $d = [string]$e.Details
        $m = [regex]::Match($d, 'SIP request \((?<m>\w+)\) from (?<ip>[0-9A-Fa-f.:]+) was rejected\. Reason: (?<why>.+?)\.(\s|$)')
        if (-not $m.Success) { continue }
        $num = ''; $user = ''; $uaTxt = ''
        $n = [regex]::Match($d, '(?m)^[A-Z]+ sip:([^@;>\s]+)@'); if ($n.Success) { $num = $n.Groups[1].Value }
        $u = [regex]::Match($d, '(?mi)^(?:Proxy-)?Authorization:[^\r\n]*?username="([^"]+)"'); if ($u.Success) { $user = $u.Groups[1].Value }
        $a = [regex]::Match($d, '(?m)^User-Agent:\s*(.+?)\s*$'); if ($a.Success) { $uaTxt = $a.Groups[1].Value }
        $wb.Add([pscustomobject]@{ Ip = $m.Groups['ip'].Value; Method = $m.Groups['m'].Value; Reason = $m.Groups['why'].Value.Trim(); Number = $num; User = $user; UserAgent = $uaTxt; TimeUtc = $e.TimeUtc })
    }
    $o.WanBlocks = @($wb.ToArray())

    # 30052 - no outbound rule. Not security: usually a misdial.
    $nr = @{}
    foreach ($e in @(@($Events) | Where-Object { $_.Id -eq 30052 })) {
        $m = [regex]::Match([string]$e.Details, 'that (?<who>.+?) dialed')
        $who = '?'; if ($m.Success) { $who = $m.Groups['who'].Value }
        $nr[$who] = 1 + [int]$nr[$who]
    }
    $o.NoRoute = @($nr.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { [pscustomobject]@{ Who = $_.Key; Count = [int]$_.Value } })

    # 12294 - trunk call/registration failed.
    $tf = @(@($Events) | Where-Object { $_.Id -eq 12294 })
    $o.TrunkFailures = @($tf).Count
    if (@($tf).Count -gt 0) {
        $m = [regex]::Match([string]$tf[-1].Details, 'replied:\s*(.+)$')
        if ($m.Success) { $o.TrunkSample = $m.Groups[1].Value.Trim() }
    }

    $o.OtherIds = @(@($Events) | Where-Object { $known -notcontains $_.Id } | Group-Object Id | Sort-Object Count -Descending | ForEach-Object { [pscustomobject]@{ Id = $_.Name; Count = $_.Count } })
    return $o
}

function Get-3cxEventAnalysis {
    # Turns an imported event log into findings plus a plain-text report.
    param(
        $Events,
        [System.TimeZoneInfo]$TimeZone = [System.TimeZoneInfo]::Local,
        $SbcEvents = @(),
        $SbcStops = @(),
        $WinRestarts = @(),
        [string[]]$LocalIps = @()
    )
    $F = [System.Collections.Generic.List[object]]::new()
    $rep = New-Object System.Text.StringBuilder
    $ci = [System.Globalization.CultureInfo]::InvariantCulture
    $fmtT = { param($u) if (-not $u) { return '?' } ([System.TimeZoneInfo]::ConvertTimeFromUtc($u, $TimeZone)).ToString('ddd d MMM HH:mm:ss', $ci) }

    $timed = @(@($Events) | Where-Object { $_.TimeUtc } | Sort-Object TimeUtc)
    $unzoned = @(@($Events) | Where-Object { -not $_.Zoned }).Count
    $firstUtc = $null; $lastUtc = $null
    if (@($timed).Count -gt 0) { $firstUtc = $timed[0].TimeUtc; $lastUtc = $timed[-1].TimeUtc }
    $levels = (@(@($Events) | Group-Object Level | ForEach-Object { ('{0} {1}' -f $_.Count, $_.Name) }) -join ', ')
    $win = ('{0} events ({1}), {2} to {3}' -f @($Events).Count, $levels, (& $fmtT $firstUtc), (& $fmtT $lastUtc))
    $F.Add((New-SecFinding 'info' 'Event log' ('Imported ' + $win + '. Times are shown in ' + $TimeZone.Id + '.') ''))
    if ($unzoned -gt 0) {
        $F.Add((New-SecFinding 'info' 'Event log' ('{0} event time(s) had no "Z" (UTC) marker and were read as UTC anyway - check the times against the 3CX console.' -f $unzoned) ''))
    }
    [void]$rep.AppendLine('=== 3CX event log: ' + $win + ' ===')
    [void]$rep.AppendLine('Times in ' + $TimeZone.Id + ' - site time when this PC is on site.')
    [void]$rep.AppendLine('')

    # ---- Tunnel history ----
    $hist = @(Get-SbcTunnelHistory -Events $Events -TimeZone $TimeZone -SbcEvents $SbcEvents -SbcStops $SbcStops -WinRestarts $WinRestarts -LocalIps $LocalIps)
    [void]$rep.AppendLine('--- SBC tunnel history (event 4102: the PBX''s own record) ---')
    if (@($hist).Count -eq 0) {
        [void]$rep.AppendLine('No SBC status changes in this export: either no SBC is paired, or its tunnel never changed state.')
        $F.Add((New-SecFinding 'info' 'SBC tunnel' 'No SBC status changes (event 4102) in this export - either no SBC is paired, or its tunnel never dropped in this period.' ''))
    }
    foreach ($s in $hist) {
        $who = ('SBC ''{0}'' ({1} / LAN {2}{3})' -f $s.Name, $s.PublicIp, $s.LanIp, $(if ($s.IsThisPc) { ' = this PC' } else { '' }))
        [void]$rep.AppendLine($who)
        if ($s.Outages.Count -eq 0) {
            [void]$rep.AppendLine('  no outages')
            $F.Add((New-SecFinding 'ok' 'SBC tunnel' ($who + ': no tunnel drops recorded in this period.') ''))
            [void]$rep.AppendLine('')
            continue
        }
        [void]$rep.AppendLine(('  {0,-24} {1,-24} {2,-10} {3}' -f 'Down', 'Up', 'Lasted', 'Note'))
        foreach ($o in $s.Outages) {
            $note = ''
            if ($o.StillDown)      { $note = 'STILL DOWN at end of export' }
            if ($o.StartUnknown)   { $note = 'went down before the export starts' }
            if ($o.Cause)          { $note = (($note + ' ' + $o.Cause).Trim()) }
            $dur = Format-SecDuration $o.Minutes
            if ($o.StillDown) { $dur = ('>' + $dur) }
            if ($o.StartUnknown) { $dur = '?' }
            $dn = '(before export)'; if ($o.DownUtc) { $dn = (& $fmtT $o.DownUtc) }
            $up = '-'; if ($o.UpUtc) { $up = (& $fmtT $o.UpUtc) }
            [void]$rep.AppendLine(('  {0,-24} {1,-24} {2,-10} {3}' -f $dn, $up, $dur, $note))
        }
        foreach ($r in $s.Recurring) { [void]$rep.AppendLine('  Pattern: ' + $r) }
        [void]$rep.AppendLine('')

        $longest = @($s.Outages | Sort-Object Minutes -Descending)[0]
        $sev = 'review'
        $txt = ('{0}: {1} tunnel outage(s), {2} in total; longest {3} from {4}.' -f $who, $s.Outages.Count, (Format-SecDuration $s.TotalMinutes), (Format-SecDuration $longest.Minutes), (& $fmtT $longest.DownUtc))
        $act = 'While the tunnel is down, every phone behind the SBC is off the PBX.'
        $open = @($s.Outages | Where-Object { $_.StillDown })
        if (@($open).Count -gt 0) {
            $sev = 'high'
            $txt = ('{0}: tunnel was DOWN at the end of the export (since {1}). {2} outage(s) in the period.' -f $who, (& $fmtT $open[0].DownUtc), $s.Outages.Count)
            $act = 'Check the SBC now (SIP / SBC tab). Re-export the event log to see whether it came back.'
        }
        $F.Add((New-SecFinding $sev 'SBC tunnel' $txt $act))
        $lst = { param($set) (@($set | ForEach-Object { ('{0} ({1})' -f (& $fmtT $_.DownUtc), (Format-SecDuration $_.Minutes)) }) -join ', ') }
        $rb = @($s.Outages | Where-Object { $_.CauseKind -eq 'reboot' })
        if (@($rb).Count -gt 0) {
            $wu = @($rb | Where-Object { $_.Cause -match 'Windows Update' }).Count -gt 0
            $act = 'Every restart of this PC takes the phones off the PBX until the SBC is back. Schedule restarts outside business hours'
            if ($wu) { $act += ' - Windows Update''s active hours / maintenance window decide when it restarts' }
            $act += ', or give the SBC a device that is not restarted for updates. Windows'' System log (event 1074) names who or what restarted it.'
            $F.Add((New-SecFinding 'review' 'SBC tunnel' ('{0} of the {1} outage(s) were this PC restarting: {2}.' -f @($rb).Count, $s.Outages.Count, (& $lst $rb)) $act))
        }
        $sv = @($s.Outages | Where-Object { $_.CauseKind -eq 'service' -or $_.CauseKind -eq 'stopped' })
        if (@($sv).Count -gt 0) {
            $F.Add((New-SecFinding 'info' 'SBC tunnel' ('{0} outage(s) were the SBC being stopped, not a network fault: {1}.' -f @($sv).Count, (& $lst $sv)) 'Planned work is fine - just note that every stop drops the phones.'))
        }
        foreach ($o in @($s.Outages | Where-Object { $_.CauseKind -eq 'dns' })) {
            $F.Add((New-SecFinding 'review' 'SBC tunnel' ('{0}, for {1}: {2}.' -f (& $fmtT $o.DownUtc), (Format-SecDuration $o.Minutes), $o.Cause) 'Not an SBC fault: this PC''s DNS failed, or the site''s internet did - its log cannot tell which. Check this PC''s DNS servers and the router/ISP for that time. If phones on another path stayed registered through it, it was this PC.'))
        }
        $cn = @($s.Outages | Where-Object { $_.CauseKind -eq 'connect' })
        if (@($cn).Count -gt 0) {
            $F.Add((New-SecFinding 'review' 'SBC tunnel' ('{0} outage(s) with the SBC running but unable to connect: {1}.' -f @($cn).Count, (& $lst $cn)) 'Network path or PBX side: check the router and the PBX''s own status at those times.'))
        }
        $unk = @($s.Outages | Where-Object { -not $_.CauseKind -and $_.DownUtc })
        if ($s.IsThisPc -and @($unk).Count -gt 0 -and @($SbcEvents).Count -gt 0) {
            $F.Add((New-SecFinding 'info' 'SBC tunnel' ('{0} outage(s) have no matching entry in the SBC''s own logs: {1}.' -f @($unk).Count, (& $lst $unk)) 'Something between the SBC and the PBX - look at the router and the PBX at those times.'))
        }
        if (-not $s.IsThisPc) {
            $F.Add((New-SecFinding 'info' 'SBC tunnel' ('The cause of each outage cannot be told from here: the SBC ({0}) is not this PC.' -f $s.LanIp) 'Run this import on the SBC machine itself: its own logs and Windows'' restart events then say why each outage happened.'))
        }
        if (@($s.Recurring).Count -gt 0) {
            $F.Add((New-SecFinding 'review' 'SBC tunnel' ('Same time of day, same cause: ' + (@($s.Recurring) -join '; ') + '.') 'A fixed time points at something scheduled: Windows Update, backups, an antivirus scan, a router reboot or an ISP lease renewal.'))
        }
    }

    # ---- Attacks ----
    $a = Get-3cxAttackSummary -Events $Events
    [void]$rep.AppendLine('--- What the PBX turned away ---')
    if ($a.Scans -gt 0) {
        $tt = (@($a.TopTargets | Select-Object -First 3 | ForEach-Object { ('{0} ({1} tries, {2} prefix forms)' -f $_.Number, $_.Count, $_.Variants) }) -join '; ')
        $tp = (@($a.TopPrefixes | Select-Object -First 2 | ForEach-Object { $_.Prefix }) -join ' and ')
        [void]$rep.AppendLine(('Unsolicited calls (30051): {0} from {1} addresses over {2} days, peak {3} in a day, {4} different User-Agents (scanners fake them).' -f $a.Scans, $a.ScanSources, $a.ScanDays, $a.ScanPeakPerDay, $a.ScanUserAgents))
        [void]$rep.AppendLine('  Numbers they tried to reach: ' + $tt)
        [void]$rep.AppendLine('  Busiest sources: ' + (@($a.TopSources | ForEach-Object { ('{0} x{1}' -f $_.Ip, $_.Count) }) -join ', '))
        [void]$rep.AppendLine('  Busiest /24 ranges: ' + (@($a.TopPrefixes | ForEach-Object { ('{0} x{1}' -f $_.Prefix, $_.Count) }) -join ', '))
        $F.Add((New-SecFinding 'info' 'Attacks' ('{0} unsolicited calls from {1} addresses were rejected (peak {2} in a day). This is normal background scanning for a PBX on the internet, and the PBX turned every one away. They were trying to reach {3}.' -f $a.Scans, $a.ScanSources, $a.ScanPeakPerDay, (@($a.TopTargets | Select-Object -First 2 | ForEach-Object { $_.Number }) -join ' and ')) ('These are toll-fraud probes: keep outbound rules limited to the destinations the business actually calls. ' + $tp + (' account for {0}% of them - blocking those ranges in the 3CX IP blacklist cuts that share of the noise.' -f $a.TopPrefixShare))))
    } else {
        [void]$rep.AppendLine('No unsolicited calls (30051) in this export.')
    }

    foreach ($w in $a.WanBlocks) {
        [void]$rep.AppendLine(('Rejected (12291): {0}  {1} {2} {3} user={4} ({5}) - {6}' -f (& $fmtT $w.TimeUtc), $w.Ip, $w.Method, $w.Number, $w.User, $w.UserAgent, $w.Reason))
    }
    # One finding per attacker and login, however many numbers it tried.
    foreach ($grp in @($a.WanBlocks | Group-Object { $_.Ip + '|' + $_.User })) {
        $g = @($grp.Group | Sort-Object TimeUtc)
        $w = $g[0]
        $nums = (@($g | ForEach-Object { $_.Number } | Where-Object { $_ } | Select-Object -Unique) -join ', ')
        $tries = ''; if (@($g).Count -gt 1) { $tries = (' ({0} attempts)' -f @($g).Count) }
        $lastT = $g[-1].TimeUtc
        $later = @($a.Blacklists | Where-Object { $_.Ip -eq $w.Ip -and $_.TimeUtc -and $lastT -and $_.TimeUtc -ge $lastT } | Sort-Object TimeUtc)
        $who = ''
        if ($w.User) { $who = (' presenting extension ' + $w.User + '''s login') }
        $txt = ('{0}: {1} tried to call {2}{3}{4} from outside the LAN ({5}); "{6}" stopped it.' -f (& $fmtT $w.TimeUtc), $w.Ip, $nums, $who, $tries, $w.UserAgent, $w.Reason)
        $act = 'Keep "Block WAN requests" on for every extension that does not need to work off-site.'
        $sev = 'info'
        if ($w.User) {
            $sev = 'review'
            $act = ('The log cannot say whether the password was right. Make sure extension {0} has a strong SIP password, and keep "Block WAN requests" on for every extension that does not need to work off-site.' -f $w.User)
            if (@($later).Count -gt 0) {
                $act += (' 3CX blacklisted this address {0} min later for failed logins, which suggests it was guessing.' -f [int][math]::Round(($later[0].TimeUtc - $lastT).TotalMinutes))
            }
        }
        $F.Add((New-SecFinding $sev 'Attacks' $txt $act))
    }

    if (@($a.Blacklists).Count -gt 0) {
        $sip = @($a.Blacklists | Where-Object { $_.Source -like 'SIP*' })
        $web = @($a.Blacklists | Where-Object { $_.Source -notlike 'SIP*' })
        foreach ($b in $a.Blacklists) { [void]$rep.AppendLine(('Blacklisted (12290): {0}  {1} for {2} s  [{3}]' -f (& $fmtT $b.TimeUtc), $b.Ip, $b.Seconds, $b.Source)) }
        $txt = ('{0} address(es) blacklisted for SIP password guessing, {1} for web-client password guessing.' -f @($sip).Count, @($web).Count)
        $act = ''
        if (@($web).Count -gt 0) {
            $webSec = (@($web | ForEach-Object { $_.Seconds } | Sort-Object -Unique) -join '/')
            $act = ('The web-client lockout lasted only {0} s. If the web client does not need to be reachable from everywhere, restrict who can reach it.' -f $webSec)
            if (@($sip).Count -gt 0) {
                $act = ('The web-client lockout lasted only {0} s, against {1} s for SIP. If the web client does not need to be reachable from everywhere, restrict who can reach it.' -f $webSec, (@($sip | ForEach-Object { $_.Seconds } | Sort-Object -Unique) -join '/'))
            }
        }
        $F.Add((New-SecFinding 'info' 'Attacks' $txt $act))
    }

    [void]$rep.AppendLine('')
    [void]$rep.AppendLine('--- Not security, but in the export ---')
    if (@($a.NoRoute).Count -gt 0) {
        $nrTot = 0; foreach ($n in $a.NoRoute) { $nrTot += $n.Count }
        $by = (@($a.NoRoute | ForEach-Object { ('{0} x{1}' -f $_.Who, $_.Count) }) -join ', ')
        [void]$rep.AppendLine(('No outbound rule (30052): {0} - {1}' -f $nrTot, $by))
        $F.Add((New-SecFinding 'info' 'Calls' ('{0} calls matched no outbound rule ({1}) - usually misdials, occasionally a missing rule.' -f $nrTot, $by) ''))
    }
    if ($a.TrunkFailures -gt 0) {
        [void]$rep.AppendLine(('Trunk call/registration failures (12294): {0}; latest reply: {1}' -f $a.TrunkFailures, $a.TrunkSample))
        $F.Add((New-SecFinding 'info' 'Calls' ('{0} trunk call/registration failures (latest carrier reply: {1}).' -f $a.TrunkFailures, $a.TrunkSample) ''))
    }
    if (@($a.OtherIds).Count -gt 0) {
        $oth = (@($a.OtherIds | ForEach-Object { ('{0} x{1}' -f $_.Id, $_.Count) }) -join ', ')
        [void]$rep.AppendLine('Other event IDs, not interpreted: ' + $oth)
        $F.Add((New-SecFinding 'info' 'Event log' ('Also in the export, not interpreted by this tool: event ' + $oth + '.') ''))
    }

    return [pscustomobject]@{
        FirstUtc = $firstUtc; LastUtc = $lastUtc; Count = @($Events).Count
        History = $hist; Attacks = $a; Findings = @($F.ToArray()); Report = $rep.ToString()
    }
}

# ---- 3CX IP blacklist page, pasted ----

function ConvertFrom-3cxBlacklistText {
    # Parses rows copied from the 3CX IP blacklist page. Tab-separated with a header
    # row when copied from the grid; falls back to pattern matching per line.
    param([string]$Text)
    $out = [System.Collections.Generic.List[object]]::new()
    $ipRx = '(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])'
    $dateRx = '\d{1,2}/\d{1,2}/\d{4}(?:\s+\d{1,2}:\d{2}(?:\s*[AP]M)?)?'
    $lines = @(([string]$Text) -split "`r?`n")
    $map = $null
    foreach ($ln in $lines) {
        if ($ln -match "`t" -and $ln -match 'IP Address' -and $ln -match 'Action') {
            $map = @{}
            $cells = $ln -split "`t"
            for ($i = 0; $i -lt $cells.Count; $i++) { $h = $cells[$i].Trim(); if ($h -and -not $map.ContainsKey($h)) { $map[$h] = $i } }
            break
        }
    }
    $ci = [System.Globalization.CultureInfo]::InvariantCulture
    foreach ($ln in $lines) {
        if ($ln -notmatch $ipRx) { continue }
        if ($ln -match 'IP Address' -and $ln -match 'Action') { continue }
        $ip = ''; $mask = ''; $action = ''; $exp = ''; $range = ''; $desc = ''
        $cells = $ln -split "`t"
        if ($map -and $cells.Count -ge 4 -and $map.ContainsKey('IP Address')) {
            $get = { param($k) if ($map.ContainsKey($k) -and $map[$k] -lt $cells.Count) { return $cells[$map[$k]].Trim() } return '' }
            $ip = & $get 'IP Address'; $mask = & $get 'Subnet Mask'; $action = & $get 'Action'
            $exp = & $get 'Expiration Date'; $range = & $get 'IP Address Range'; $desc = & $get 'Description'
        } else {
            $ips = @([regex]::Matches($ln, $ipRx) | ForEach-Object { $_.Value })
            $ip = $ips[0]
            if (@($ips).Count -gt 1 -and $ips[1] -match '^255\.') { $mask = $ips[1] }
            $m = [regex]::Match($ln, '\b(Allow|Deny|Block)\b'); if ($m.Success) { $action = $m.Value }
            $m = [regex]::Match($ln, $dateRx); if ($m.Success) { $exp = $m.Value }
            $rest = [regex]::Replace($ln, $ipRx, ' ')
            $rest = [regex]::Replace($rest, '\b(Allow|Deny|Block)\b', ' ')
            $rest = [regex]::Replace($rest, $dateRx, ' ')
            $desc = ([regex]::Replace($rest, '(^[\s-]+|[\s-]+$)', '') -replace '\s{2,}', ' ').Trim()
        }
        if ($ip -notmatch "^$ipRx$") { continue }
        $start = [double](ConvertTo-IpUInt32 $ip); $count = 1.0
        if ($mask -match "^$ipRx$") {
            $mn = [double](ConvertTo-IpUInt32 $mask)
            $bits = 0
            for ($i = 31; $i -ge 0; $i--) {
                $bit = [math]::Pow(2, $i)
                if ([math]::Floor($mn / $bit) % 2 -eq 1) { $bits++ } else { break }
            }
            $count = [math]::Pow(2, 32 - $bits)
            $start = $start - ($start % $count)
        }
        $rm = [regex]::Match($range, "^\s*(?<a>$ipRx)\s*-\s*(?<b>$ipRx)\s*$")
        if ($rm.Success) {
            $start = [double](ConvertTo-IpUInt32 $rm.Groups['a'].Value)
            $count = [double](ConvertTo-IpUInt32 $rm.Groups['b'].Value) - $start + 1
        }
        $expAt = $null; $t = [datetime]::MinValue
        foreach ($f in @('M/d/yyyy h:mm tt', 'M/d/yyyy H:mm', 'M/d/yyyy')) {
            if ([datetime]::TryParseExact($exp, $f, $ci, [System.Globalization.DateTimeStyles]::None, [ref]$t)) { $expAt = $t; break }
        }
        $out.Add([pscustomobject]@{
            Ip = $ip; Mask = $mask; Action = $action; Expires = $exp; ExpiresAt = $expAt
            Description = $desc; Start = $start; Count = $count
        })
    }
    return @($out.ToArray())
}

function Test-BlacklistEntryCovers {
    param($Entry,[string]$Ip)
    $n = ConvertTo-IpUInt32 $Ip
    if ($null -eq $n) { return $false }
    return ([double]$n -ge [double]$Entry.Start -and [double]$n -lt ([double]$Entry.Start + [double]$Entry.Count))
}

function Get-3cxBlacklistFindings {
    # Checks the allow list against the site's real public IP(s). -SiteIps are
    # objects with Ip and Source, from the tool's own measurement and from the
    # PBX's SBC events - so the site IP is never guessed.
    param($Entries, $SiteIps = @(), $Attacks = $null, [datetime]$Now = (Get-Date))
    $F = [System.Collections.Generic.List[object]]::new()
    $entries = @($Entries)
    if (@($entries).Count -eq 0) {
        $F.Add((New-SecFinding 'info' 'IP blacklist' 'No IPv4 rows were found in the pasted text.' 'Copy the rows from the 3CX IP blacklist page (with the header row) and paste again.'))
        return @($F.ToArray())
    }
    $site = @(@($SiteIps) | Where-Object { $_ -and $_.Ip } | Group-Object Ip | ForEach-Object { [pscustomobject]@{ Ip = $_.Name; Source = ((@($_.Group | ForEach-Object { $_.Source }) | Sort-Object -Unique) -join ' and ') } })
    $allow = @($entries | Where-Object { $_.Action -eq 'Allow' })
    $deny  = @($entries | Where-Object { $_.Action -ne 'Allow' })
    $siteTxt = (@($site | ForEach-Object { $_.Ip }) -join ', ')

    foreach ($s in $site) {
        $blocked = @($deny | Where-Object { Test-BlacklistEntryCovers $_ $s.Ip })
        if (@($blocked).Count -gt 0) {
            $F.Add((New-SecFinding 'high' 'IP blacklist' ('This site''s own public IP {0} ({1}) is BLACKLISTED: "{2}".' -f $s.Ip, $s.Source, $blocked[0].Description) 'Phones on this site cannot reach the PBX from this IP. Find the device with the wrong password first (or it will be blocked again), then remove the entry.'))
        }
        $cov = @($allow | Where-Object { Test-BlacklistEntryCovers $_ $s.Ip })
        if (@($cov).Count -gt 0) {
            $F.Add((New-SecFinding 'ok' 'IP blacklist' ('This site''s public IP {0} ({1}) is on the allow list ("{2}").' -f $s.Ip, $s.Source, $cov[0].Description) ''))
        } else {
            $F.Add((New-SecFinding 'review' 'IP blacklist' ('This site''s public IP {0} ({1}) is NOT on the allow list.' -f $s.Ip, $s.Source) 'With phones registering directly (STUN), one phone with a wrong password can get the whole office''s IP blacklisted - SIP blocks last 24 hours by default. Allow-listing the site prevents that; only do it for a static IP. Through an SBC the phones reach the PBX over the tunnel instead, and how 3CX counts failed logins there has not been verified by this tool.'))
        }
    }

    foreach ($e in $allow) {
        $isSite = $false
        foreach ($s in $site) { if (Test-BlacklistEntryCovers $e $s.Ip) { $isSite = $true } }
        if ($e.Count -gt 256) {
            $F.Add((New-SecFinding 'review' 'IP blacklist' ('Allow entry {0}/{1} ("{2}") exempts {3} addresses from brute-force blocking.' -f $e.Ip, $e.Mask, $e.Description, $e.Count) 'Narrow it to the addresses that actually need it.'))
        }
        if ($isSite -or @($site).Count -eq 0) { continue }
        $act = 'An allow-listed address is exempt from 3CX''s brute-force blacklisting, so an address nobody uses any more - an old ISP address since given to someone else, or wherever the PBX was set up from - is a standing exemption for a stranger. Confirm who uses it today; if nobody does, remove it.'
        if ($e.Description -match '(?i)PBX Express') { $act = ('Added automatically when the PBX was set up with PBX Express - typically the address it was set up from. ' + $act) }
        $F.Add((New-SecFinding 'review' 'IP blacklist' ('Allow entry {0} ("{1}", expires {2}) is not this site''s current public IP ({3}).' -f $e.Ip, $e.Description, $e.Expires, $siteTxt) $act))
    }
    if (@($site).Count -eq 0 -and @($allow).Count -gt 0) {
        $F.Add((New-SecFinding 'info' 'IP blacklist' ('{0} allow entr(ies) could not be checked against this site: its public IP is not known yet.' -f @($allow).Count) 'Run Check 3CX (it measures the public IP) or import the PBX event log (it records the SBC''s public IP), then look again.'))
    }

    if (@($deny).Count -gt 0) {
        $active = @($deny | Where-Object { -not $_.ExpiresAt -or $_.ExpiresAt -gt $Now })
        $det = (@($deny | ForEach-Object { $x = $_.Ip; if ($_.Description -match 'User-Agent:\s*(.+)$') { $x += (' (' + $Matches[1].Trim() + ')') }; $x }) -join ', ')
        $txt = ('{0} blocked address(es) listed, {1} still in force by their expiry dates: {2}.' -f @($deny).Count, @($active).Count, $det)
        $act = ''
        if ($Attacks) {
            $seen = @($deny | Where-Object { $ip = $_.Ip; @($Attacks.WanBlocks | Where-Object { $_.Ip -eq $ip }).Count -gt 0 })
            if (@($seen).Count -gt 0) { $act = ('{0} also appear(s) in the event log trying to call out with an extension''s login - see the Attacks rows.' -f (@($seen | ForEach-Object { $_.Ip }) -join ', ')) }
        }
        $F.Add((New-SecFinding 'info' 'IP blacklist' $txt $act))
    }
    return @($F.ToArray())
}

# ---- This PC ----

function Get-SecurityPortCatalog {
    # The 3CX and SIP ports this check looks at. Only these, plus anything a 3CX
    # process holds (the SBC's media range), are reported: general Windows hygiene
    # (RDP, SMB, clear-text services) says nothing about the 3CX setup, and on a
    # PC that is not the SBC it described the technician's laptop.
    $c = @{}
    foreach ($x in @(
        @('TCP', 5060, 'SIP'),
        @('UDP', 5060, 'SIP'),
        @('TCP', 5061, 'SIP over TLS'),
        @('TCP', 5090, '3CX tunnel'),
        @('UDP', 5090, '3CX tunnel'),
        @('TCP', 5001, '3CX web (HTTPS)')
    )) { $c[('{0}/{1}' -f $x[0], $x[1])] = [pscustomobject]@{ Name = $x[2]; Kind = 'sip' } }
    return $c
}

function Get-FirewallSnapshot {
    # One bulk read of every enabled inbound rule and its filters, joined in memory.
    # Piping rule by rule (Get-NetFirewallRule | Get-NetFirewallPortFilter) takes
    # minutes on a server with a thousand rules; these -All reads take well under
    # a second each.
    $o = [pscustomobject]@{ Profiles = @(); ActiveProfiles = @(); Rules = @(); Unreadable = 0; ThirdParty = @(); Error = '' }
    try {
        $o.Profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{ Name = [string]$_.Name; Enabled = ([string]$_.Enabled -eq 'True'); DefaultInbound = [string]$_.DefaultInboundAction }
        })
    } catch { $o.Error = ('Firewall profiles unreadable: ' + $_.Exception.Message) }
    try {
        $o.ActiveProfiles = @(Get-NetConnectionProfile -ErrorAction Stop | ForEach-Object {
            $n = [string]$_.NetworkCategory
            if ($n -eq 'DomainAuthenticated') { 'Domain' } else { $n }
        } | Sort-Object -Unique)
    } catch {}
    try {
        $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Enabled True -ErrorAction Stop)
        $pf = @{}; foreach ($x in @(Get-NetFirewallPortFilter -All -PolicyStore ActiveStore -ErrorAction SilentlyContinue)) { $pf[[string]$x.InstanceID] = $x }
        $af = @{}; foreach ($x in @(Get-NetFirewallAddressFilter -All -PolicyStore ActiveStore -ErrorAction SilentlyContinue)) { $af[[string]$x.InstanceID] = $x }
        $ap = @{}; foreach ($x in @(Get-NetFirewallApplicationFilter -All -PolicyStore ActiveStore -ErrorAction SilentlyContinue)) { $ap[[string]$x.InstanceID] = $x }
        $sf = @{}; foreach ($x in @(Get-NetFirewallServiceFilter -All -PolicyStore ActiveStore -ErrorAction SilentlyContinue)) { $sf[[string]$x.InstanceID] = $x }
        # Without admin rights the bulk reads come back partial ("Access is denied"
        # for part of the store - 187 of 481 rules on the dev PC). A missing filter
        # must never be read as "Any", so fetch the gaps rule by rule, and leave out
        # - and count - any rule that is still unreadable.
        foreach ($kind in @('Port', 'Address', 'Application', 'Service')) {
            $tbl = $pf
            if ($kind -eq 'Address')     { $tbl = $af }
            if ($kind -eq 'Application') { $tbl = $ap }
            if ($kind -eq 'Service')     { $tbl = $sf }
            $gap = @($rules | Where-Object { -not $tbl.ContainsKey([string]$_.Name) })
            if (@($gap).Count -eq 0) { continue }
            $got = @()
            switch ($kind) {
                'Port'        { $got = @($gap | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue) }
                'Address'     { $got = @($gap | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue) }
                'Application' { $got = @($gap | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue) }
                'Service'     { $got = @($gap | Get-NetFirewallServiceFilter -ErrorAction SilentlyContinue) }
            }
            foreach ($x in $got) { $tbl[[string]$x.InstanceID] = $x }
        }
        $unread = 0
        $o.Rules = @(foreach ($r in $rules) {
            $id = [string]$r.Name
            $p = $pf[$id]; $a = $af[$id]; $g = $ap[$id]; $s = $sf[$id]
            if (-not $p -or -not $a -or -not $g) { $unread++; continue }
            # A rule with an Owner belongs to a Store app's container, and one with a
            # Package applies only to that app - neither lets in a desktop service.
            if ([string]$r.Owner) { continue }
            if ($g.PSObject.Properties['Package'] -and [string]$g.Package -and [string]$g.Package -ne 'Any') { continue }
            [pscustomobject]@{
                Name          = $id
                DisplayName   = [string]$r.DisplayName
                Action        = [string]$r.Action
                Profiles      = [string]$r.Profile
                Protocol      = $(if ($p) { [string]$p.Protocol } else { 'Any' })
                LocalPorts    = $(if ($p) { @($p.LocalPort | ForEach-Object { [string]$_ }) } else { @('Any') })
                RemoteAddress = $(if ($a) { @($a.RemoteAddress | ForEach-Object { [string]$_ }) } else { @('Any') })
                Program       = $(if ($g) { [string]$g.Program } else { 'Any' })
                Service       = $(if ($s) { [string]$s.Service } else { 'Any' })
            }
        })
        $o.Unreadable = $unread
    } catch { $o.Error = ('Firewall rules unreadable: ' + $_.Exception.Message) }
    # Workstations only: servers have no Security Center.
    try {
        $o.ThirdParty = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName FirewallProduct -ErrorAction Stop |
            ForEach-Object { [string]$_.displayName } | Where-Object { $_ -and $_ -notmatch '(?i)windows (defender )?firewall' })
    } catch {}
    return $o
}

function Test-FirewallRuleMatch {
    # Does this rule apply to a listener? Returns 'yes', 'no', or 'maybe' (the rule
    # names a program, this session could not see the listener's full path, and
    # only the file name could be compared).
    param($Rule,[string]$Protocol,[int]$Port,[string]$ProgramPath = '',[string]$ProcessName = '',[string[]]$Services = @(),[string[]]$ActiveProfiles = @())
    $rp = [string]$Rule.Profiles
    if ($rp -and $rp -ne 'Any' -and @($ActiveProfiles).Count -gt 0) {
        $hit = $false
        foreach ($a in $ActiveProfiles) { if ($rp -match [regex]::Escape($a)) { $hit = $true } }
        if (-not $hit) { return 'no' }
    }
    $pr = [string]$Rule.Protocol
    if ($pr -and $pr -ne 'Any') {
        $num = @{ TCP = '6'; UDP = '17' }
        if (-not ($pr -eq $Protocol -or $pr -eq $num[$Protocol])) { return 'no' }
    }
    $lp = @($Rule.LocalPorts)
    if (-not (@($lp).Count -eq 0 -or $lp -contains 'Any')) {
        $ok = $false
        foreach ($p in $lp) {
            if ($p -match '^\d+$' -and [int]$p -eq $Port) { $ok = $true; break }
            if ($p -match '^(\d+)-(\d+)$' -and $Port -ge [int]$Matches[1] -and $Port -le [int]$Matches[2]) { $ok = $true; break }
            if ($p -eq 'RPCEPMap' -and $Port -eq 135) { $ok = $true; break }
            if ($p -eq 'RPC' -and $Port -ge 49152) { $ok = $true; break }
        }
        if (-not $ok) { return 'no' }
    }
    $res = 'yes'
    $prog = [string]$Rule.Program
    if ($prog -and $prog -ne 'Any') {
        $exp = [Environment]::ExpandEnvironmentVariables($prog)
        if ($ProgramPath) {
            if ($exp -ne $ProgramPath) { return 'no' }      # -ne is case-insensitive
        } elseif ($ProcessName) {
            # No path without admin rights - but the file name still rules most out.
            if ([System.IO.Path]::GetFileNameWithoutExtension($exp) -ne $ProcessName) { return 'no' }
            $res = 'maybe'
        } else {
            $res = 'maybe'
        }
    }
    $svc = [string]$Rule.Service
    if ($svc -and $svc -ne 'Any') {
        if ($svc -eq '*') { if (@($Services).Count -eq 0) { return 'no' } }
        elseif (@($Services) -notcontains $svc) { return 'no' }
        elseif ($res -eq 'maybe') { $res = 'yes' }           # named service matched: that pins the program too
    }
    return $res
}

function Get-ListenerExposure {
    # What Windows Firewall does with inbound traffic for one listener, on the
    # network profile(s) this PC is actually on. Windows Firewall only - the
    # router decides what the internet can reach.
    param([string]$Protocol,[int]$Port,[string]$ProgramPath = '',[string]$ProcessName = '',[string[]]$Services = @(),$Snapshot)
    $o = [pscustomobject]@{ State = 'unknown'; Scope = ''; Rules = @(); Uncertain = $false }
    if (-not $Snapshot) { return $o }
    $act = @($Snapshot.ActiveProfiles)
    $profs = @($Snapshot.Profiles | Where-Object { @($act).Count -eq 0 -or $act -contains $_.Name })
    if (@($profs | Where-Object { -not $_.Enabled }).Count -gt 0) {
        $o.State = 'firewall off'; $o.Scope = 'Any'; return $o
    }
    if (@($profs | Where-Object { $_.DefaultInbound -eq 'Allow' }).Count -gt 0) {
        $o.State = 'allowed'; $o.Scope = 'Any'; $o.Rules = @('(default inbound action is Allow)'); return $o
    }
    $allow = [System.Collections.Generic.List[object]]::new()
    foreach ($r in @($Snapshot.Rules)) {
        $m = Test-FirewallRuleMatch -Rule $r -Protocol $Protocol -Port $Port -ProgramPath $ProgramPath -ProcessName $ProcessName -Services $Services -ActiveProfiles $act
        if ($m -eq 'no') { continue }
        if ($r.Action -eq 'Block') {
            if ($m -eq 'yes') { $o.State = 'blocked'; $o.Scope = ''; $o.Rules = @($r.DisplayName); return $o }
            continue
        }
        if ($r.Action -eq 'Allow') {
            $allow.Add($r)
            if ($m -eq 'maybe') { $o.Uncertain = $true }
        }
    }
    if ($allow.Count -eq 0) { $o.State = 'no allow rule'; return $o }
    $o.State = 'allowed'
    # Rules naming this port first: they say most about why it is open.
    $o.Rules = @($allow | Sort-Object { if (@($_.LocalPorts) -contains 'Any') { 1 } else { 0 } } | ForEach-Object { $_.DisplayName } | Select-Object -Unique)
    $addrs = @($allow | ForEach-Object { $_.RemoteAddress } | ForEach-Object { $_ })
    if ($addrs -contains 'Any' -or $addrs -contains 'Internet') { $o.Scope = 'Any'; return $o }
    $lanWords = @('LocalSubnet', 'LocalSubnet4', 'LocalSubnet6', 'Intranet', 'IntranetRemoteAccess', 'DNS', 'DHCP', 'WINS', 'DefaultGateway', 'PlayToDevice')
    $public = $false
    foreach ($a in $addrs) {
        if ($lanWords -contains $a) { continue }
        $first = (($a -split '-')[0] -split '/')[0]
        if (-not (Test-PrivateAddress $first)) { $public = $true }
    }
    if ($public) { $o.Scope = 'includes public addresses' } else { $o.Scope = 'LAN only' }
    return $o
}

function Get-BroadReadPrincipals {
    # Which broad groups can read a file. Checked by SID, so it works whatever the
    # Windows display language.
    param([string]$Path)
    $broad = [ordered]@{
        'S-1-1-0' = 'Everyone'; 'S-1-5-11' = 'Authenticated Users'; 'S-1-5-32-545' = 'Users'
        'S-1-5-4' = 'INTERACTIVE'; 'S-1-5-14' = 'Remote interactive logon'; 'S-1-5-32-555' = 'Remote Desktop Users'
        'S-1-5-32-546' = 'Guests'; 'S-1-5-7' = 'ANONYMOUS LOGON'
    }
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $allowed = [System.Collections.Generic.List[string]]::new()
    $denied  = [System.Collections.Generic.List[string]]::new()
    foreach ($r in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        $sid = [string]$r.IdentityReference.Value
        if (-not $broad.Contains($sid)) { continue }
        $v = [int64]$r.FileSystemRights
        # ReadData, or the generic READ / ALL bits that raw ACEs can carry.
        $reads = (($v -band 0x1) -ne 0) -or (($v -band 0x80000000) -ne 0) -or (($v -band 0x10000000) -ne 0)
        if (-not $reads) { continue }
        if ([string]$r.AccessControlType -eq 'Deny') { [void]$denied.Add($broad[$sid]) } else { [void]$allowed.Add($broad[$sid]) }
    }
    return @($allowed | Where-Object { $denied -notcontains $_ } | Sort-Object -Unique)
}

function Find-SbcConfigCopies {
    # Every 3cxsbc.conf* in the usual places: the SBC's own folder (backups sit
    # there too), all of ProgramData, the temp folders and users' desktops,
    # downloads and documents. A real site had a copy - tunnel password and all -
    # in a support tool's temp folder under ProgramData.
    param([string]$SbcRoot = '')
    $found = @{}
    $add = { param($items) foreach ($f in @($items)) { if ($f -and -not $f.PSIsContainer) { $found[$f.FullName.ToLower()] = $f.FullName } } }
    $sd = $env:SystemDrive
    & $add (Get-ChildItem -LiteralPath $env:ProgramData -Recurse -Force -File -Filter '3cxsbc.conf*' -ErrorAction SilentlyContinue)
    foreach ($d in @((Join-Path $env:SystemRoot 'Temp'), (Join-Path $sd 'Temp'), (Join-Path $sd 'tmp'), $env:TEMP)) {
        if ($d -and (Test-Path -LiteralPath $d)) { & $add (Get-ChildItem -LiteralPath $d -Recurse -Depth 4 -Force -File -Filter '3cxsbc.conf*' -ErrorAction SilentlyContinue) }
    }
    & $add (Get-ChildItem -LiteralPath ($sd + '\') -Force -File -Filter '3cxsbc.conf*' -ErrorAction SilentlyContinue)
    foreach ($u in @(Get-ChildItem -LiteralPath (Join-Path $sd 'Users') -Directory -Force -ErrorAction SilentlyContinue)) {
        foreach ($sub in @('Desktop', 'Downloads', 'Documents')) {
            $p = Join-Path $u.FullName $sub
            if (Test-Path -LiteralPath $p) { & $add (Get-ChildItem -LiteralPath $p -Recurse -Depth 3 -Force -File -Filter '3cxsbc.conf*' -ErrorAction SilentlyContinue) }
        }
    }
    $rootL = ''
    if ($SbcRoot) { $rootL = ($SbcRoot.TrimEnd('\') + '\').ToLower() }
    return @($found.Values | Sort-Object | ForEach-Object {
        [pscustomobject]@{ Path = $_; InSbcFolder = [bool]($rootL -and $_.ToLower().StartsWith($rootL)) }
    })
}

function Get-LocalSecurityPosture {
    # Gathers what this PC exposes that matters to 3CX: the SBC, if it runs here,
    # and the SIP / 3CX ports. Read-only; each part fails soft on its own.
    param([switch]$SkipFileSearch)
    $P = [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME; Elevated = $false; OsCaption = ''; IsServer = $false
        DesktopSessions = 0; RdpEnabled = $null
        Firewall = $null; Listeners = @()
        SbcPresent = $false; SbcAccount = ''; SbcLanIps = @(); SbcFiles = @(); Errors = @()
    }
    $err = [System.Collections.Generic.List[string]]::new()
    try { $P.Elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch {}
    try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop; $P.OsCaption = [string]$os.Caption; $P.IsServer = ([int]$os.ProductType -ne 1) } catch {}
    # Who else can log on here decides how serious a readable SBC config is.
    try { $P.DesktopSessions = @(Get-Process -Name explorer -ErrorAction SilentlyContinue | ForEach-Object { $_.SessionId } | Sort-Object -Unique).Count } catch {}
    try {
        $ts = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction Stop
        $P.RdpEnabled = ([int]$ts.fDenyTSConnections -eq 0)
    } catch {}

    $P.Firewall = Get-FirewallSnapshot
    if ($P.Firewall.Error) { [void]$err.Add($P.Firewall.Error) }

    # Process paths and hosted services, in two bulk reads.
    $paths = @{}; $svcs = @{}
    try { foreach ($wp in @(Get-CimInstance Win32_Process -ErrorAction Stop)) { if ($wp.ExecutablePath) { $paths[[int]$wp.ProcessId] = [string]$wp.ExecutablePath } } } catch {}
    $allSvc = @()
    try { $allSvc = @(Get-CimInstance Win32_Service -ErrorAction Stop) } catch {}
    foreach ($s in $allSvc) {
        $sp = [int]$s.ProcessId
        if ($sp -le 0) { continue }
        if (-not $svcs.ContainsKey($sp)) { $svcs[$sp] = [System.Collections.Generic.List[string]]::new() }
        [void]$svcs[$sp].Add([string]$s.Name)
    }
    $sbcSvc = @($allSvc | Where-Object { $_.Name -eq '3CXSBC' }) | Select-Object -First 1
    if ($sbcSvc) { $P.SbcPresent = $true; $P.SbcAccount = [string]$sbcSvc.StartName }

    $cat = Get-SecurityPortCatalog
    $raw = [System.Collections.Generic.List[object]]::new()
    try { foreach ($c in @(Get-NetTCPConnection -State Listen -ErrorAction Stop)) { $raw.Add([pscustomobject]@{ Protocol = 'TCP'; Address = [string]$c.LocalAddress; Port = [int]$c.LocalPort; ProcId = [int]$c.OwningProcess }) } } catch { [void]$err.Add('TCP listeners unreadable: ' + $_.Exception.Message) }
    try { foreach ($u in @(Get-NetUDPEndpoint -ErrorAction Stop)) { $raw.Add([pscustomobject]@{ Protocol = 'UDP'; Address = [string]$u.LocalAddress; Port = [int]$u.LocalPort; ProcId = [int]$u.OwningProcess }) } } catch { [void]$err.Add('UDP endpoints unreadable: ' + $_.Exception.Message) }

    $rows = @{}
    $pnames = @{}
    foreach ($r in $raw) {
        if ($r.Address -match '^(127\.|::1$)') { continue }       # loopback: not reachable from anywhere else
        $key = ('{0}/{1}/{2}' -f $r.Protocol, $r.Port, $r.ProcId)
        if ($rows.ContainsKey($key)) {
            if (@($rows[$key].Addresses) -notcontains $r.Address) { $rows[$key].Addresses = @($rows[$key].Addresses) + $r.Address }
            continue
        }
        if (-not $pnames.ContainsKey($r.ProcId)) {
            $pn = ''
            try { $pp = Get-Process -Id $r.ProcId -ErrorAction SilentlyContinue; if ($pp) { $pn = [string]$pp.ProcessName } } catch {}
            if ($r.ProcId -eq 4) { $pn = 'System' }
            $pnames[$r.ProcId] = $pn
        }
        $pname = $pnames[$r.ProcId]
        # 3CX and SIP ports only, plus anything a 3CX process holds (the SBC's
        # media range sits on ports of its own).
        $info = $cat[('{0}/{1}' -f $r.Protocol, $r.Port)]
        if (-not $info -and $pname -notlike '3cx*') { continue }
        $svcList = @(); if ($svcs.ContainsKey($r.ProcId)) { $svcList = @($svcs[$r.ProcId].ToArray()) }
        $rows[$key] = [pscustomobject]@{
            Protocol = $r.Protocol; Port = $r.Port; Addresses = @($r.Address); ProcId = $r.ProcId; Process = $pname
            Path = [string]$paths[$r.ProcId]; Services = $svcList
            Name = $(if ($info) { $info.Name } else { '' }); Kind = $(if ($info) { $info.Kind } else { 'other' })
            Exposure = $null
        }
    }
    foreach ($row in $rows.Values) {
        # System (PID 4) serves SMB and HTTP.sys from the kernel; its rules name the
        # program "System", which the CIM path lookup never returns.
        $pp = $row.Path; if ($row.ProcId -eq 4) { $pp = 'System' }
        $row.Exposure = Get-ListenerExposure -Protocol $row.Protocol -Port $row.Port -ProgramPath $pp -ProcessName $row.Process -Services $row.Services -Snapshot $P.Firewall
    }
    $P.Listeners = @($rows.Values | Sort-Object Protocol, Port)

    if ($P.SbcPresent) {
        try { $P.SbcLanIps = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } | ForEach-Object { [string]$_.IPAddress }) } catch {}
        if (-not $SkipFileSearch) {
            $root = (Get-LocalSbcPath).Root
            $P.SbcFiles = @(Find-SbcConfigCopies -SbcRoot $root | ForEach-Object {
                $f = $_; $who = @(); $e = ''
                try { $who = @(Get-BroadReadPrincipals -Path $f.Path) } catch { $e = $_.Exception.Message }
                # Whether it holds a secret right now - a yes/no only; the text is
                # dropped here and never reaches a report. On the real site
                # 3cxsbc.conf.local was all comments, with no password in it.
                $sec = $null
                try { $sec = [bool]((Get-Content -LiteralPath $f.Path -Raw -ErrorAction Stop) -match '(?im)^[ \t]*(Password|ProvLink)[ \t]*=[ \t]*\S') } catch {}
                [pscustomobject]@{ Path = $f.Path; InSbcFolder = $f.InSbcFolder; ReadableBy = $who; AclError = $e; HasSecret = $sec }
            })
        }
    }
    $P.Errors = @($err.ToArray())
    return $P
}

function ConvertTo-PortRunText {
    # "UDP/20000-20127 3cxsbc (128 ports)" rather than 128 separate entries: the SBC
    # binds its whole media range, and listing it port by port buried everything else.
    param($Items)
    $out = [System.Collections.Generic.List[string]]::new()
    $sorted = @(@($Items) | Sort-Object Protocol, Process, Port)
    $i = 0
    while ($i -lt $sorted.Count) {
        $a = $sorted[$i]; $j = $i
        while ($j + 1 -lt $sorted.Count -and $sorted[$j + 1].Protocol -eq $a.Protocol -and $sorted[$j + 1].Process -eq $a.Process -and $sorted[$j + 1].Port -eq ($sorted[$j].Port + 1)) { $j++ }
        $proc = $a.Process; if (-not $proc) { $proc = ('pid ' + $a.ProcId) }
        if ($j -eq $i) { [void]$out.Add(('{0}/{1} {2}' -f $a.Protocol, $a.Port, $proc)) }
        else { [void]$out.Add(('{0}/{1}-{2} {3} ({4} ports)' -f $a.Protocol, $a.Port, $sorted[$j].Port, $proc, ($j - $i + 1))) }
        $i = $j + 1
    }
    return @($out.ToArray())
}

function Get-PostureFindings {
    # Pure: turns a gathered posture into findings. Separate from the gathering
    # so it can be tested against constructed cases. 3CX only: the SBC when it
    # runs here, and who else holds a SIP port.
    param($P)
    $F = [System.Collections.Generic.List[object]]::new()
    $fw = $P.Firewall
    $routerNote = 'Windows Firewall only: whether the internet can reach it is decided by the router''s port forwards.'

    if ($fw -and $fw.Error) { $F.Add((New-SecFinding 'info' 'This PC' $fw.Error 'Run as administrator for the full firewall picture.')) }
    if ($fw -and $fw.Unreadable -gt 0) { $F.Add((New-SecFinding 'info' 'This PC' ('{0} firewall rule(s) could not be read and were left out of the port analysis.' -f $fw.Unreadable) 'Run as administrator for the full firewall picture.')) }

    $sbcMedia = [System.Collections.Generic.List[object]]::new()
    $sbcFwOff = $false
    foreach ($l in @($P.Listeners)) {
        $x = $l.Exposure
        if (-not $x) { continue }
        $open = ($x.State -eq 'allowed' -or $x.State -eq 'firewall off')
        if (-not $open -or $x.Scope -eq 'LAN only') { continue }
        $isSbc = ($P.SbcPresent -and $l.Process -eq '3cxsbc')
        if ($isSbc -and $x.State -eq 'firewall off') { $sbcFwOff = $true }
        if ($l.Kind -eq 'sip') {
            if (-not $isSbc) {
                $label = ('{0} {1}/{2}' -f $l.Name, $l.Protocol, $l.Port)
                $proc = $l.Process; if (-not $proc) { $proc = ('pid ' + $l.ProcId) }
                $F.Add((New-SecFinding 'info' 'This PC' ('{0} is held by {1} and allowed in from {2}.' -f $label, $proc, $x.Scope) 'If this is not a 3CX component it may be a softphone - on an SBC box it would compete with the SBC for the phones'' traffic.'))
            }
        } elseif ($isSbc -and $l.Protocol -eq 'UDP') {
            # The SBC's media ports belong with its SIP port.
            $sbcMedia.Add($l)
        }
    }

    if ($P.SbcPresent) {
        $multi = ($P.DesktopSessions -ge 2 -or ($P.IsServer -and $P.RdpEnabled -eq $true))
        $ctx = ''
        if ($P.DesktopSessions -ge 2) { $ctx = (' {0} people have a desktop session on this PC right now.' -f $P.DesktopSessions) }
        elseif ($P.IsServer -and $P.RdpEnabled -eq $true) { $ctx = ' This is a Windows Server with Remote Desktop on.' }
        $acct = ''
        if ($P.SbcAccount) { $acct = (' The 3CXSBC service runs as ' + $P.SbcAccount + ', which is not affected by removing Users'' access.') }
        foreach ($cf in @($P.SbcFiles)) {
            $who = @($cf.ReadableBy)
            $hs = $null; if ($cf.PSObject.Properties['HasSecret']) { $hs = $cf.HasSecret }
            $what = 'It holds the SBC''s tunnel password and provisioning key.'
            if ($hs -eq $false) { $what = 'It holds no password now, but settings put in it override the SBC''s config at every start.' }
            elseif ($null -eq $hs) { $what = 'It may hold the SBC''s tunnel password (its contents could not be checked).' }
            if ($cf.InSbcFolder) {
                if (@($who).Count -gt 0) {
                    $sev = 'review'; if ($multi) { $sev = 'high' }
                    if ($hs -eq $false) { $sev = 'info' }
                    $F.Add((New-SecFinding $sev 'SBC' ('{0} can be read by {1}. {2}{3}' -f $cf.Path, ((@($who)) -join ', '), $what, $ctx) ('Restrict the file to SYSTEM and Administrators.' + $acct + ' Better still, give the SBC a machine nobody else logs on to.')))
                }
            } else {
                $wt = ''; if (@($who).Count -gt 0) { $wt = (' - readable by ' + ((@($who)) -join ', ')) }
                $sev = 'high'; if ($hs -eq $false) { $sev = 'info' }
                $F.Add((New-SecFinding $sev 'SBC' ('Stray copy of an SBC config file at {0}{1}. {2}' -f $cf.Path, $wt, $what) 'The SBC does not use this copy. Delete it once you have confirmed nothing needs it.'))
            }
            if ($cf.AclError) { $F.Add((New-SecFinding 'info' 'SBC' ('Could not read the permissions of {0}: {1}' -f $cf.Path, $cf.AclError) 'Run as administrator.')) }
        }
        $ips = ((@($P.SbcLanIps)) -join ', ')
        $F.Add((New-SecFinding 'info' 'SBC' 'This PC runs the 3CX SBC. An SBC needs NO inbound port from the internet: it dials out to the PBX (TCP 5090), and only this LAN''s phones talk to it.' ('Check the router forwards nothing to this PC (' + $ips + '). Any forward to it - 5060 included - is unnecessary exposure.')))
        $sipRow = @($P.Listeners | Where-Object { $_.Protocol -eq 'UDP' -and $_.Port -eq 5060 -and $_.Process -eq '3cxsbc' }) | Select-Object -First 1
        $sipOpen = ($sipRow -and $sipRow.Exposure -and ($sipRow.Exposure.State -eq 'allowed' -or $sipRow.Exposure.State -eq 'firewall off') -and $sipRow.Exposure.Scope -ne 'LAN only')
        if ($sipOpen -or $sbcMedia.Count -gt 0) {
            $what = @()
            if ($sipOpen) { $what += 'SIP port (UDP 5060)' }
            if ($sbcMedia.Count -gt 0) { $what += ('media ports (' + (@(ConvertTo-PortRunText $sbcMedia) -join ', ') + ')') }
            if ($sbcFwOff) {
                $F.Add((New-SecFinding 'review' 'SBC' ('Windows Firewall is OFF on this PC''s network, so anything that can reach this PC reaches the SBC''s ' + ($what -join ' and ') + ' - only this LAN''s phones need them.') 'Turn Windows Firewall back on, unless another firewall is deliberately in charge here. Make sure the router forwards nothing to this PC.'))
            } else {
                $F.Add((New-SecFinding 'info' 'SBC' ('Windows Firewall lets anyone reach the SBC''s ' + ($what -join ' and ') + ' - only this LAN''s phones need them.') 'Harmless while the router forwards nothing here; narrowing the rule to the local subnet adds a second layer.'))
            }
        }
        if (-not $P.Elevated) {
            $F.Add((New-SecFinding 'info' 'SBC' 'Not run as administrator: the SBC config files'' permissions and some process paths may be missing.' 'Re-run elevated for the complete picture.'))
        }
        if (@($F | Where-Object { $_.Severity -eq 'high' -or $_.Severity -eq 'review' }).Count -eq 0) {
            $F.Add((New-SecFinding 'ok' 'SBC' 'Nothing to fix in the SBC''s config files or in how Windows Firewall treats its ports.' $routerNote))
        }
    } else {
        # Said outright, so a clean result on a laptop is not read as "the SBC is fine".
        $msg = 'No 3CX SBC runs on this PC'
        if (@($P.Listeners).Count -eq 0) { $msg += ', and nothing here holds a SIP or 3CX port' }
        $F.Add((New-SecFinding 'info' 'This PC' ($msg + ' - this check has nothing to report about the 3CX setup.') 'Run it on the Windows machine that hosts the SBC. A Raspberry Pi SBC or a Router Phone cannot be checked from here (see the SIP / SBC tab).'))
    }
    return @($F.ToArray())
}

function Format-PostureReport {
    param($P)
    $rep = New-Object System.Text.StringBuilder
    $os = $P.OsCaption; if (-not $os) { $os = 'Windows' }
    [void]$rep.AppendLine(('=== This PC: {0} ({1}{2}) ===' -f $P.ComputerName, $os, $(if ($P.Elevated) { ', elevated' } else { ', NOT elevated' })))
    $fw = $P.Firewall
    if ($fw) {
        $ap = 'unknown'; if (@($fw.ActiveProfiles).Count) { $ap = (@($fw.ActiveProfiles) -join ', ') }
        [void]$rep.AppendLine('Network profile(s) in use: ' + $ap)
        [void]$rep.AppendLine('Windows Firewall: ' + (@($fw.Profiles | ForEach-Object { ('{0} {1} (inbound default {2})' -f $_.Name, $(if ($_.Enabled) { 'on' } else { 'OFF' }), $_.DefaultInbound) }) -join '; '))
        if (@($fw.ThirdParty).Count) { [void]$rep.AppendLine('Other firewall registered: ' + (@($fw.ThirdParty) -join ', ')) }
        if ($fw.Unreadable -gt 0) { [void]$rep.AppendLine(('{0} firewall rule(s) unreadable without admin rights - left out.' -f $fw.Unreadable)) }
    }
    [void]$rep.AppendLine(('3CX SBC on this PC: {0}' -f $(if ($P.SbcPresent) { 'yes' } else { 'no - nothing below is about the SBC' })))
    [void]$rep.AppendLine('')
    [void]$rep.AppendLine('--- 3CX / SIP ports on this PC ---')
    if (@($P.Listeners).Count -eq 0) { [void]$rep.AppendLine('(nothing listening on a SIP or 3CX port, and no 3CX process listening)') }
    else { [void]$rep.AppendLine(('{0,-5} {1,-11} {2,-22} {3,-18} {4,-14} {5,-16} {6}' -f 'Proto', 'Port', 'Service', 'Process', 'Firewall', 'Allowed from', 'Rule')) }
    $lines = [System.Collections.Generic.List[object]]::new()
    foreach ($l in @($P.Listeners | Sort-Object Protocol, Port)) {
        $st = ''; $sc = ''
        if ($l.Exposure) { $st = $l.Exposure.State; $sc = $l.Exposure.Scope; if ($l.Exposure.Uncertain) { $sc += ' (?)' } }
        $proc = $l.Process; if (-not $proc) { $proc = ('pid ' + $l.ProcId) }
        $rn = ''; if ($l.Exposure -and @($l.Exposure.Rules).Count) { $rn = @($l.Exposure.Rules)[0]; if (@($l.Exposure.Rules).Count -gt 1) { $rn += (' (+{0})' -f (@($l.Exposure.Rules).Count - 1)) } }
        # Consecutive ports with everything else identical become one line.
        $prev = $null; if ($lines.Count -gt 0) { $prev = $lines[$lines.Count - 1] }
        if ($prev -and $prev.Protocol -eq $l.Protocol -and $prev.To -eq ($l.Port - 1) -and $prev.Name -eq $l.Name -and $prev.Proc -eq $proc -and $prev.St -eq $st -and $prev.Sc -eq $sc -and $prev.Rn -eq $rn) {
            $prev.To = $l.Port; continue
        }
        $lines.Add([pscustomobject]@{ Protocol = $l.Protocol; From = $l.Port; To = $l.Port; Name = $l.Name; Proc = $proc; St = $st; Sc = $sc; Rn = $rn })
    }
    foreach ($x in $lines) {
        $pt = [string]$x.From; if ($x.To -ne $x.From) { $pt = ('{0}-{1}' -f $x.From, $x.To) }
        [void]$rep.AppendLine(('{0,-5} {1,-11} {2,-22} {3,-18} {4,-14} {5,-16} {6}' -f $x.Protocol, $pt, $x.Name, $x.Proc, $x.St, $x.Sc, $x.Rn))
    }
    [void]$rep.AppendLine('Firewall = Windows Firewall''s decision on the network profile in use. "(?)" = a program-specific rule could not be confirmed without admin rights. Whether the internet can reach a port is decided by the router, which this tool cannot see.')
    if ($P.SbcPresent) {
        [void]$rep.AppendLine('')
        [void]$rep.AppendLine('--- 3CX SBC config files (checked only for whether a secret is present - no value is ever shown) ---')
        if (@($P.SbcFiles).Count -eq 0) { [void]$rep.AppendLine('No 3cxsbc.conf* found (or the search was skipped).') }
        foreach ($f in @($P.SbcFiles)) {
            $w = 'admins/system only'; if (@($f.ReadableBy).Count) { $w = ('readable by ' + (@($f.ReadableBy) -join ', ')) }
            if ($f.AclError) { $w = ('permissions unreadable: ' + $f.AclError) }
            [void]$rep.AppendLine(('{0}  [{1}]  {2}' -f $f.Path, $(if ($f.InSbcFolder) { 'SBC folder' } else { 'STRAY COPY' }), $w))
        }
    }
    foreach ($e in @($P.Errors)) { [void]$rep.AppendLine('Note: ' + $e) }
    return $rep.ToString()
}

# ---------------------------------------------------------------------------
# Reporting: the JSON export (schema "3cx-checker-report", version 1.0)
# ---------------------------------------------------------------------------
# The CSV flattens everything into Detail1-4 strings and drops the verdicts; this
# carries them as data, for Generate-3cxReport.ps1. Every section says whether and
# when it was measured, because one export can mix runs.
#
# The builder only ever receives what it is handed - never the whole UI state - so
# nothing secret (SSH password, phone passwords, raw event text) can reach it.
# ---------------------------------------------------------------------------

function Get-SiteNameFromPbx {
    # A 3CX-hosted instance name as a site name: examplepbx.3cx.us -> EXAMPLEPBX. Only
    # 3CX-hosted names count - on a custom domain the first label ("pbx") names
    # nothing - and never -Exclude, the tool's own default PBX.
    param([string]$PbxHost,[string]$Exclude = '')
    $h = (((([string]$PbxHost).Trim() -replace '^\s*https?://', '') -replace '/.*$', '') -replace ':\d+$', '')
    if (-not $h) { return '' }
    if ($Exclude -and $h -ieq $Exclude) { return '' }
    $m = [regex]::Match($h, '(?i)^([a-z0-9][a-z0-9-]*)\.(?:my)?3cx\.[a-z]{2,}(?:\.[a-z]{2,})?$')
    if ($m.Success) { return $m.Groups[1].Value.ToUpper() }
    return ''
}

function ConvertTo-CsvSafeText {
    # Spreadsheet formula injection: Excel executes a cell that starts with
    # = + - @ (or a tab / CR) as a formula. The CSV export carries strings that
    # devices on the LAN control - SIP User-Agents, SSH banners, hostnames - so a
    # leading apostrophe neutralises them; Excel shows the text without it. A lone
    # "-" or "+" is not a formula and is left alone. Non-strings pass through.
    param($Value)
    if ($Value -isnot [string] -or $Value.Length -eq 0) { return $Value }
    $c = $Value[0]
    if ($c -eq [char]9 -or $c -eq [char]13) { return ("'" + $Value) }
    if ($Value.Length -ge 2 -and ($c -eq '=' -or $c -eq '+' -or $c -eq '-' -or $c -eq '@')) { return ("'" + $Value) }
    return $Value
}

function ConvertTo-ReportDate {
    # ISO 8601. PowerShell 5.1's ConvertTo-Json would otherwise write "\/Date(...)\/".
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [System.DateTimeKind]::Utc) { return $Value.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture) }
        return ([DateTimeOffset]$Value).ToString("yyyy-MM-dd'T'HH:mm:sszzz", [System.Globalization.CultureInfo]::InvariantCulture)
    }
    return [string]$Value
}

function ConvertTo-PlainData {
    # Walks any object graph into ordered dictionaries, arrays and primitives, with
    # dates as ISO strings and enums as names - so the JSON is the same whatever
    # .NET or PowerShell types the data happened to arrive as.
    param($Value,[int]$Depth = 0)
    if ($null -eq $Value) { return $null }
    if ($Depth -gt 14) { return [string]$Value }
    if ($Value -is [datetime]) { return (ConvertTo-ReportDate $Value) }
    if ($Value -is [string] -or $Value -is [bool] -or $Value -is [char]) { return $Value }
    if ($Value -is [enum]) { return $Value.ToString() }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal] -or $Value -is [single] -or
        $Value -is [int16] -or $Value -is [uint16] -or $Value -is [uint32] -or $Value -is [uint64] -or $Value -is [byte]) {
        if (($Value -is [double] -or $Value -is [single]) -and ([double]::IsNaN([double]$Value) -or [double]::IsInfinity([double]$Value))) { return $null }
        return $Value
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $o = [ordered]@{}
        foreach ($k in $Value.Keys) { $o[[string]$k] = ConvertTo-PlainData -Value $Value[$k] -Depth ($Depth + 1) }
        return $o
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        return ,@(foreach ($x in $Value) { ConvertTo-PlainData -Value $x -Depth ($Depth + 1) })
    }
    $o = [ordered]@{}
    foreach ($p in $Value.PSObject.Properties) {
        if ($p.MemberType -notin @('NoteProperty', 'Property')) { continue }
        $v = $null; try { $v = $p.Value } catch {}
        $o[$p.Name] = ConvertTo-PlainData -Value $v -Depth ($Depth + 1)
    }
    return $o
}

function New-ReportSection {
    param($Time,[hashtable]$Content = @{})
    $o = [ordered]@{ measured = [bool]$Time; measuredLocal = (ConvertTo-ReportDate $Time) }
    foreach ($k in $Content.Keys) { $o[$k] = $Content[$k] }
    return $o
}

function New-3cxReportObject {
    # Builds the report from explicit inputs only. -Times holds when each section
    # was last measured (a missing time means "not run": the section is still
    # present, marked measured = false, never silently dropped).
    param(
        [string]$ToolName = '3CX Desk-Phone Connectivity Checker',
        [string]$ToolVersion = '',
        [hashtable]$Site = @{},
        [hashtable]$Options = @{},
        [hashtable]$Times = @{},
        $Cx = @(), [string]$CxSummary = '',
        $Media = @(), [string]$MediaSummary = '', $Health = $null, $MediaMetrics = $null,
        $Phones = @(), $SbcRows = @(), $LocalSbc = $null, $Roles = @(), $Listeners = @(),
        $SecFindings = @(), $SecPosture = $null, $SecEvents = $null, [string]$SecEventFile = '', $Blacklist = $null,
        [string[]]$Log = @(),
        [datetime]$Now = (Get-Date)
    )
    $str = { param($v) if ($null -eq $v) { return '' }; return [string]$v }

    $cxRows = @(@($Cx) | Where-Object { $_ } | ForEach-Object {
        [ordered]@{ check = (& $str $_.Check); target = (& $str $_.Target); port = (& $str $_.Port); result = (& $str $_.Result); detail = (& $str $_.Detail); status = (& $str $_.Status) } })
    $mdRows = @(@($Media) | Where-Object { $_ } | ForEach-Object {
        [ordered]@{ group = (& $str $_.Group); check = (& $str $_.Check); result = (& $str $_.Result); detail = (& $str $_.Detail); status = (& $str $_.Status) } })
    $phRows = @(@($Phones) | Where-Object { $_ -and $_.MAC } | ForEach-Object {
        [ordered]@{ ip = (& $str $_.IP); mac = (& $str $_.MAC); model = (& $str $_.Model); firmware = (& $str $_.Firmware); sipServer = (& $str $_.SipServer)
                    registration = (& $str $_.Reg); hostname = (& $str $_.Hostname); vq = (& $str $_.Vq); vqDetail = (& $str $_.VqDetail)
                    # Host only - the provisioning path is a secret and is never kept.
                    provisioningHost = (& $str $_.ProvHost); provisioningNote = (& $str $_.ProvNote); provisioningMismatch = [bool]$_.ProvMismatch } })
    $sbRows = @(@($SbcRows) | Where-Object { $_ } | ForEach-Object {
        $r = $_
        $g = { param($n) if ($r.PSObject.Properties[$n]) { return $r.PSObject.Properties[$n].Value }; return $null }
        [ordered]@{ ip = (& $str $r.IP); verdict = (& $str $r.Confidence); platform = (& $str $r.Platform); vendor = (& $str $r.Vendor); hostname = (& $str $r.Hostname)
                    os = (& $str $r.Os); sshOpen = [bool](& $g 'SshOpen'); openPorts = (& $str $r.OpenPorts); sipType = (& $str $r.SipType); detail = (& $str $r.Detail)
                    isThisPc = [bool](& $g 'IsLocalSbc'); health = (& $str (& $g 'LocalHealth')); is3cxRouterPhone = [bool](& $g 'Is3cxRouterPhone'); isRouterPhone = [bool](& $g 'IsRouterPhone')
                    sbcConfirmed = [bool](& $g 'SbcMarker'); forwardsTo = (& $str (& $g 'ForwardsTo')); forwardsMismatch = [bool](& $g 'ForwardsMismatch') } })
    $roleRows = @(@($Roles) | Where-Object { $_ } | ForEach-Object {
        [ordered]@{ role = (& $str $_.Role); ip = (& $str $_.IP); mac = (& $str $_.MAC); vendor = (& $str $_.Vendor); note = (& $str $_.Note); warn = [bool]$_.Warn } })
    $lsRows = @(@($Listeners) | Where-Object { $_ } | ForEach-Object {
        [ordered]@{ localAddress = (& $str $_.LocalAddress); port = $_.LocalPort; state = (& $str $_.State); pid = $_.OwningProcess; process = (& $str $_.ProcessName) } })

    # This PC's SBC: the verdict and the facts behind it - the log's event list and
    # the start/stop history stay out (they are inputs to the verdict, not results).
    $thisPc = $null
    if ($LocalSbc -and $LocalSbc.Present) {
        $L = $LocalSbc.Log
        $logSum = $null
        if ($L) {
            $logSum = [ordered]@{ version = (& $str $L.Version); runStarted = (ConvertTo-ReportDate $L.RunStarted); starts24h = $L.Starts24h; errors7d = $L.Errors7d
                                  inactivity7d = $L.Inactivity7d; dnsFail7d = $(if ($L.PSObject.Properties['DnsFail7d']) { $L.DnsFail7d } else { $null }) }
        }
        $thisPc = [ordered]@{
            present = $true; serviceName = (& $str $LocalSbc.ServiceName); serviceStatus = (& $str $LocalSbc.Status); startType = (& $str $LocalSbc.StartType)
            udp5060Owner = (& $str $LocalSbc.Udp5060Owner); pairedPbx = (& $str $LocalSbc.TunnelAddr); tunnelPort = $LocalSbc.TunnelPort
            tunnel = (& $str $LocalSbc.Tunnel); tunnelDetail = (& $str $LocalSbc.TunnelDetail); reachable = $LocalSbc.Reachable
            sipAnswer = (& $str $LocalSbc.SipAnswer); sipMatched = $(if ($LocalSbc.PSObject.Properties['SipMatched']) { [string]$LocalSbc.SipMatched } else { '' })
            testedFqdn = (& $str $LocalSbc.TestFqdn); mismatch = [bool]$LocalSbc.Mismatch
            health = (& $str $LocalSbc.Health); verdict = (& $str $LocalSbc.Verdict); detail = (& $str $LocalSbc.Detail); log = $logSum
        }
    }

    $healthObj = $null
    if ($Health) {
        $healthObj = [ordered]@{
            level = (& $str $Health.Overall); headline = (& $str $Health.Headline)
            subscores = @(@($Health.Subscores) | Where-Object { $_ } | ForEach-Object { [ordered]@{ name = (& $str $_.Name); level = (& $str $_.Level); summary = (& $str $_.Summary); remedy = (& $str $_.Remedy) } })
            actions = @(@($Health.Actions) | Where-Object { $_ } | ForEach-Object { [string]$_ })
        }
    }

    $postureObj = $null
    if ($SecPosture) {
        $P = $SecPosture
        $postureObj = [ordered]@{
            computer = (& $str $P.ComputerName); os = (& $str $P.OsCaption); elevated = [bool]$P.Elevated; isServer = [bool]$P.IsServer
            desktopSessions = $P.DesktopSessions
            firewall = $(if ($P.Firewall) { [ordered]@{ profiles = $P.Firewall.Profiles; activeProfiles = $P.Firewall.ActiveProfiles; thirdParty = $P.Firewall.ThirdParty
                                                       unreadableRules = $(if ($P.Firewall.PSObject.Properties['Unreadable']) { $P.Firewall.Unreadable } else { 0 }) } } else { $null })
            listeners = @(@($P.Listeners) | Where-Object { $_ } | ForEach-Object {
                [ordered]@{ protocol = $_.Protocol; port = $_.Port; addresses = $_.Addresses; process = (& $str $_.Process); service = (& $str $_.Name); kind = (& $str $_.Kind)
                            firewall = $(if ($_.Exposure) { [ordered]@{ state = $_.Exposure.State; allowedFrom = $_.Exposure.Scope; rules = $_.Exposure.Rules; uncertain = [bool]$_.Exposure.Uncertain } } else { $null }) } })
            sbc = [ordered]@{ present = [bool]$P.SbcPresent; serviceAccount = (& $str $P.SbcAccount); lanIps = $P.SbcLanIps
                              files = @(@($P.SbcFiles) | Where-Object { $_ } | ForEach-Object { [ordered]@{ path = $_.Path; inSbcFolder = [bool]$_.InSbcFolder; readableBy = $_.ReadableBy
                                                                                                             hasSecret = $(if ($_.PSObject.Properties['HasSecret']) { $_.HasSecret } else { $null }) } }) }
        }
    }

    $eventObj = $null
    if ($SecEvents) {
        $E = $SecEvents
        $A = $E.Attacks
        $eventObj = [ordered]@{
            file = [System.IO.Path]::GetFileName($SecEventFile); firstUtc = $E.FirstUtc; lastUtc = $E.LastUtc; events = $E.Count
            sbcs = @(@($E.History) | Where-Object { $_ } | ForEach-Object {
                [ordered]@{ name = $_.Name; publicIp = $_.PublicIp; lanIp = $_.LanIp; isThisPc = [bool]$_.IsThisPc; totalMinutes = [math]::Round([double]$_.TotalMinutes, 1)
                            lastState = $_.LastState; recurring = $_.Recurring
                            outages = @(@($_.Outages) | ForEach-Object { [ordered]@{ downUtc = $_.DownUtc; upUtc = $_.UpUtc; minutes = [math]::Round([double]$_.Minutes, 1); stillDown = [bool]$_.StillDown
                                                                                     startUnknown = [bool]$_.StartUnknown; causeKind = $_.CauseKind; cause = $_.Cause } }) } })
            attacks = $(if ($A) { [ordered]@{
                unsolicitedCalls = $A.Scans; sources = $A.ScanSources; days = $A.ScanDays; peakPerDay = $A.ScanPeakPerDay; userAgents = $A.ScanUserAgents
                topSources = $A.TopSources; topRanges = $A.TopPrefixes; topTwoRangesSharePct = $A.TopPrefixShare; topTargets = $A.TopTargets
                blacklisted = $A.Blacklists; wanBlocked = $A.WanBlocks; noOutboundRule = $A.NoRoute; trunkFailures = $A.TrunkFailures; trunkLastReply = $A.TrunkSample
                otherEventIds = $A.OtherIds } } else { $null })
            reportText = (& $str $E.Report)
        }
    }

    $blObj = $null
    if ($null -ne $Blacklist) {
        $blObj = @(@($Blacklist) | Where-Object { $_ } | ForEach-Object {
            [ordered]@{ ip = $_.Ip; mask = $_.Mask; action = $_.Action; expires = $_.Expires; addresses = $_.Count; description = $_.Description } })
    }

    $rep = [ordered]@{
        schema = '3cx-checker-report'; schemaVersion = '1.0'
        tool = [ordered]@{ name = $ToolName; version = $ToolVersion }
        generatedUtc = (ConvertTo-ReportDate $Now.ToUniversalTime()); generatedLocal = (ConvertTo-ReportDate $Now); timeZone = [System.TimeZoneInfo]::Local.Id
        site = $Site
        lastRunOptions = $Options
        connectivity = (New-ReportSection $Times['connectivity'] @{ summary = $CxSummary; checks = $cxRows })
        media = (New-ReportSection $Times['media'] @{ summary = $MediaSummary; health = $healthObj; metrics = $MediaMetrics; checks = $mdRows })
        phones = (New-ReportSection $Times['phones'] @{ items = $phRows })
        sbc = (New-ReportSection $Times['sbc'] @{ thisPc = $thisPc; lan = $sbRows })
        network = (New-ReportSection $Times['network'] @{ roles = $roleRows; listeners = $lsRows })
        security = [ordered]@{
            findings = @(@($SecFindings) | Where-Object { $_ } | ForEach-Object { [ordered]@{ severity = (& $str $_.Severity); area = (& $str $_.Area); finding = (& $str $_.Finding); action = (& $str $_.Action) } })
            thisPc = (New-ReportSection $Times['security.thisPc'] @{ posture = $postureObj })
            eventLog = (New-ReportSection $Times['security.eventLog'] @{ analysis = $eventObj })
            blacklist = (New-ReportSection $Times['security.blacklist'] @{ entries = $blObj })
        }
        log = @($Log | Select-Object -Last 500)
    }
    return (ConvertTo-PlainData $rep)
}

function ConvertTo-3cxReportJson {
    # PS 5.1's ConvertTo-Json escapes ' < > & as ' and friends: valid JSON, but
    # unreadable in Notepad. They are put back unless the backslash is itself escaped.
    param($Report)
    $json = $Report | ConvertTo-Json -Depth 20
    foreach ($pair in @(@('0027', "'"), @('003c', '<'), @('003e', '>'), @('0026', '&'))) {
        $json = [regex]::Replace($json, ('(?<!\\)((?:\\\\)*)\\u' + $pair[0]), ('$1' + $pair[1]))
    }
    return $json
}

function Get-ReportFileSlug {
    param([string]$Name,[string]$Fallback = 'site')
    $s = (([string]$Name).Trim() -replace '[^A-Za-z0-9-]+', '-').Trim('-')
    if (-not $s) { $s = (([string]$Fallback) -replace '[^A-Za-z0-9-]+', '-').Trim('-') }
    if (-not $s) { $s = 'site' }
    if ($s.Length -gt 40) { $s = $s.Substring(0, 40) }
    return $s
}
