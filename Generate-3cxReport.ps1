<#
.SYNOPSIS
    Companion report generator for 3CX-Checker.ps1.
.DESCRIPTION
    Paste the JSON that 3CX-Checker's "Export report" put on the clipboard - with or
    without the BEGIN/END markers - or browse to the saved .json. Produces a
    self-contained HTML site report in the Output folder next to this script.
.NOTES
    Windows PowerShell 5.1, WinForms, no dependencies.
    Keep this file pure ASCII: PS 5.1 reads BOM-less files as cp1252, so any other
    glyph must be an HTML entity.
    -NoGui loads the functions only (for tests).
#>
[CmdletBinding()]
param([switch]$NoGui)

$script:GeneratorVersion = '1.0.0'
$script:Schema = '3cx-checker-report'

# -----------------------------------------------------------------------------
# Input
# -----------------------------------------------------------------------------
function Extract-3cxReportJson {
    # The export, from a paste (markers or bare JSON) or a file's text. Refuses
    # anything that is not a 3CX Checker report, and names truncation - the usual
    # failure with a long paste - instead of a bare JSON parse error.
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { throw 'Nothing to read - paste the export or browse to the .json file.' }
    $hasBegin = $Text -match '---\s*BEGIN JSON OUTPUT\s*---'
    $hasEnd   = $Text -match '---\s*END JSON OUTPUT\s*---'
    if ($hasBegin -and -not $hasEnd) {
        throw ("The export is truncated: the BEGIN marker is there but the END marker is missing ({0:N0} characters pasted).`n`n" -f $Text.Length +
               "The text was cut off before it was copied. Use 'Browse JSON...' to load the saved .json file instead - 3CX Checker saves one in its Output folder.")
    }
    $json = $Text.Trim()
    $m = [regex]::Match($Text, '(?s)---\s*BEGIN JSON OUTPUT\s*---\s*(.*?)\s*---\s*END JSON OUTPUT\s*---')
    if ($m.Success) { $json = $m.Groups[1].Value.Trim() }
    try { $obj = $json | ConvertFrom-Json -ErrorAction Stop }
    catch {
        $hint = ''
        if ($json -and -not $json.TrimEnd().EndsWith('}')) {
            $hint = ("`n`nIt does not end with '}}', so it looks truncated ({0:N0} characters). Try 'Browse JSON...' to load the saved file." -f $json.Length)
        }
        throw ('Could not read the JSON: ' + $_.Exception.Message + $hint)
    }
    if ([string]$obj.schema -ne $script:Schema) {
        throw ("This is not a 3CX Checker report (schema: '{0}'). Paste the output of 3CX Checker's Export report button." -f [string]$obj.schema)
    }
    $major = ([string]$obj.schemaVersion).Split('.')[0]
    if ($major -ne '1') {
        throw ("This report uses schema version {0}, made by a newer 3CX Checker. Update Generate-3cxReport.ps1 to match." -f [string]$obj.schemaVersion)
    }
    return $obj
}

# -----------------------------------------------------------------------------
# Formatting helpers
# -----------------------------------------------------------------------------
function HtmlEncode {
    param($Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Slugify {
    param([string]$Name)
    $s = (([string]$Name).Trim().ToLower() -replace '[^a-z0-9]+', '-').Trim('-')
    if (-not $s) { $s = 'site' }
    if ($s.Length -gt 40) { $s = $s.Substring(0, 40) }
    return $s
}

function Get-SiteZone {
    # Times are shown in the zone of the PC the checker ran on - site time - which
    # the export records; this PC's zone if that is unknown here.
    param($R)
    try { if ($R.timeZone) { return [System.TimeZoneInfo]::FindSystemTimeZoneById([string]$R.timeZone) } } catch {}
    return [System.TimeZoneInfo]::Local
}

function Format-Time {
    param($Iso,$Zone,[string]$Format = 'ddd d MMM yyyy HH:mm')
    if (-not $Iso) { return '' }
    try {
        $dto = [DateTimeOffset]::Parse([string]$Iso, [System.Globalization.CultureInfo]::InvariantCulture)
        if (-not $Zone) { $Zone = [System.TimeZoneInfo]::Local }
        return [System.TimeZoneInfo]::ConvertTime($dto, $Zone).ToString($Format, [System.Globalization.CultureInfo]::InvariantCulture)
    } catch { return [string]$Iso }
}

function Format-Minutes {
    param($Minutes)
    if ($null -eq $Minutes) { return '' }
    $sec = [int][math]::Round([double]$Minutes * 60)
    if ($sec -lt 60)   { return ('{0}s' -f $sec) }
    if ($sec -lt 3600) { return ('{0}m{1:00}s' -f [int][math]::Floor($sec / 60), ($sec % 60)) }
    $m = [int][math]::Round($sec / 60.0)
    return ('{0}h{1:00}m' -f [int][math]::Floor($m / 60), ($m % 60))
}

function Get-StatusClass {
    param([string]$Status)
    switch -Regex (([string]$Status).ToLower()) {
        '^(ok|green|good)$'                  { return 'ok' }
        '^(warn|review|amber|fair)$'         { return 'warn' }
        '^(fail|high|red|poor)$'             { return 'fail' }
        default                              { return 'info' }
    }
}

function Get-Array { param($Value) if ($null -eq $Value) { return @() }; return @($Value) }

function New-Table {
    # $Rows: arrays of already-encoded HTML cells. $CellClass (optional): a
    # scriptblock given (row, column) returning a CSS class for that cell.
    param([string[]]$Headers,$Rows,[scriptblock]$CellClass = $null,[string]$Class = '')
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<table class="' + $Class + '"><thead><tr>')
    foreach ($h in $Headers) { [void]$sb.Append('<th>' + (HtmlEncode $h) + '</th>') }
    [void]$sb.Append('</tr></thead><tbody>')
    $ri = 0
    foreach ($row in @($Rows)) {
        [void]$sb.Append('<tr>')
        for ($ci = 0; $ci -lt @($row).Count; $ci++) {
            $cls = ''
            if ($CellClass) { $cls = [string](& $CellClass $row $ci $ri) }
            if ($cls) { [void]$sb.Append('<td class="' + $cls + '">') } else { [void]$sb.Append('<td>') }
            [void]$sb.Append([string]@($row)[$ci])
            [void]$sb.Append('</td>')
        }
        [void]$sb.Append('</tr>')
        $ri++
    }
    [void]$sb.Append('</tbody></table>')
    return $sb.ToString()
}

function New-SectionHead {
    # Every section states when it was measured - or that it was not run - because
    # one export can combine several runs.
    param([string]$Title,[string]$Id,$Section,$Zone)
    $note = '<span class="when notrun">Not run in this export</span>'
    if ($Section -and $Section.measured) { $note = '<span class="when">Measured ' + (HtmlEncode (Format-Time $Section.measuredLocal $Zone)) + '</span>' }
    return ('<h2 id="' + $Id + '">' + (HtmlEncode $Title) + ' ' + $note + '</h2>')
}

function Get-ReportCss {
@'
<style>
:root { --ok:#1b7f3b; --okbg:#e6f4ea; --warn:#9a5b00; --warnbg:#fff4e0; --fail:#b3261e; --failbg:#fde7e6; --info:#5f6b77; --infobg:#eef1f5; --ink:#1f2933; --line:#d9dee5; }
* { box-sizing: border-box; }
body { font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; background: #eef2f7; color: var(--ink); font-size: 14px; }
.page { max-width: 1180px; margin: 0 auto; padding: 24px 28px 40px; }
header { background: #16324f; color: #fff; padding: 22px 28px; border-radius: 10px; }
header h1 { margin: 0 0 6px; font-size: 24px; }
header .meta { color: #c9d6e3; font-size: 13px; line-height: 1.6; }
header .meta b { color: #fff; font-weight: 600; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin: 18px 0; }
.tile { background: #fff; border-radius: 10px; padding: 14px 16px; border-left: 6px solid var(--info); box-shadow: 0 1px 2px rgba(0,0,0,.06); }
.tile .label { font-size: 12px; text-transform: uppercase; letter-spacing: .04em; color: var(--info); }
.tile .value { font-size: 22px; font-weight: 700; margin: 4px 0 2px; }
.tile .sub { font-size: 12px; color: #4a5568; }
.tile.ok { border-left-color: var(--ok); } .tile.ok .value { color: var(--ok); }
.tile.warn { border-left-color: #e09200; } .tile.warn .value { color: var(--warn); }
.tile.fail { border-left-color: var(--fail); } .tile.fail .value { color: var(--fail); }
section { background: #fff; border-radius: 10px; padding: 6px 20px 18px; margin: 16px 0; box-shadow: 0 1px 2px rgba(0,0,0,.06); }
h2 { font-size: 18px; margin: 16px 0 10px; }
h3 { font-size: 15px; margin: 18px 0 8px; }
.when { font-size: 12px; font-weight: 400; color: var(--info); margin-left: 8px; }
.when.notrun { color: var(--warn); }
.todo li { margin: 6px 0; line-height: 1.45; }
.todo .area { font-weight: 600; }
table { border-collapse: collapse; width: 100%; font-size: 13px; margin: 6px 0 10px; }
th { text-align: left; background: #f3f5f8; color: #3b4652; font-weight: 600; padding: 7px 8px; border-bottom: 2px solid var(--line); }
td { padding: 6px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
td.ok { color: var(--ok); font-weight: 600; } td.warn { color: var(--warn); font-weight: 600; } td.fail { color: var(--fail); font-weight: 600; } td.info { color: var(--info); }
.pill { display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 12px; font-weight: 600; }
.pill.ok { background: var(--okbg); color: var(--ok); } .pill.warn { background: var(--warnbg); color: var(--warn); }
.pill.fail { background: var(--failbg); color: var(--fail); } .pill.info { background: var(--infobg); color: var(--info); }
.mono { font-family: Consolas, "SF Mono", monospace; font-size: 12px; }
.summary { white-space: pre-wrap; background: #f7f9fb; border: 1px solid var(--line); border-radius: 6px; padding: 10px 12px; font-size: 13px; line-height: 1.5; }
.note { color: var(--info); font-size: 12px; }
.callout { border-left: 4px solid var(--info); background: #f7f9fb; padding: 8px 12px; margin: 8px 0; }
.callout.ok { border-left-color: var(--ok); } .callout.warn { border-left-color: #e09200; } .callout.fail { border-left-color: var(--fail); }
.metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 8px; margin: 8px 0; }
.metric { background: #f7f9fb; border: 1px solid var(--line); border-radius: 6px; padding: 8px 10px; }
.metric .k { font-size: 11px; color: var(--info); text-transform: uppercase; } .metric .v { font-size: 18px; font-weight: 700; }
footer { color: var(--info); font-size: 12px; margin-top: 24px; line-height: 1.5; }
@media print { body { background: #fff; } section, .tile { box-shadow: none; border: 1px solid var(--line); } header { background: #fff; color: #000; border: 1px solid #000; } header .meta, header .meta b { color: #000; } section { break-inside: avoid-page; } }
</style>
'@
}

# -----------------------------------------------------------------------------
# The report
# -----------------------------------------------------------------------------
function Build-3cxReportHtml {
    param($R,[string]$SiteName = '')
    $zone = Get-SiteZone $R
    $site = $R.site
    if (-not $SiteName) { $SiteName = [string]$site.name }
    $title = '3CX site report'
    if ($SiteName) { $title = $SiteName + ' - 3CX site report' }
    $cx = $R.connectivity; $md = $R.media; $ph = $R.phones; $sb = $R.sbc; $nw = $R.network; $sec = $R.security
    $findings = @(Get-Array $sec.findings)
    $rank = @{ high = 0; review = 1; info = 2; ok = 3 }
    $findings = @($findings | Sort-Object { $v = $rank[[string]$_.severity]; if ($null -eq $v) { 4 } else { $v } })
    $sevLabel = @{ high = 'HIGH'; review = 'REVIEW'; info = 'info'; ok = 'OK' }
    $routerIps = @(Get-Array $sb.lan | Where-Object { $_.is3cxRouterPhone } | ForEach-Object { [string]$_.ip })

    $h = New-Object System.Text.StringBuilder
    [void]$h.Append('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$h.Append('<title>' + (HtmlEncode $title) + '</title>' + (Get-ReportCss) + '</head><body><div class="page">')

    # ---- header ----
    $meta = New-Object System.Collections.Generic.List[string]
    if ($site.pbxFqdn)     { [void]$meta.Add('PBX <b>' + (HtmlEncode $site.pbxFqdn) + '</b>') }
    if ($site.localSbcPbx -and $site.localSbcPbx -ne $site.pbxFqdn) { [void]$meta.Add('this PC''s SBC is paired with <b>' + (HtmlEncode $site.localSbcPbx) + '</b>') }
    if ($site.publicIp)    { [void]$meta.Add('site public IP <b>' + (HtmlEncode $site.publicIp) + '</b>') }
    if ($site.subnet)      { [void]$meta.Add('LAN <b>' + (HtmlEncode $site.subnet) + '</b>') }
    $gen = ('Exported ' + (HtmlEncode (Format-Time $R.generatedLocal $zone)) + ' from <b>' + (HtmlEncode $site.computer) + '</b> by ' + (HtmlEncode $R.tool.name) + ' ' + (HtmlEncode $R.tool.version) +
            ' &middot; times in ' + (HtmlEncode $zone.Id))
    [void]$h.Append('<header><h1>' + (HtmlEncode $title) + '</h1><div class="meta">' + ($meta -join ' &middot; ') + '<br>' + $gen + '</div></header>')

    # ---- at a glance ----
    [void]$h.Append('<div class="tiles">')
    $tile = { param($cls, $label, $value, $sub) [void]$h.Append('<div class="tile ' + $cls + '"><div class="label">' + (HtmlEncode $label) + '</div><div class="value">' + (HtmlEncode $value) + '</div><div class="sub">' + $sub + '</div></div>') }
    # Call path (media health)
    if ($md.measured -and $md.health) {
        $lv = [string]$md.health.level
        $word = @{ green = 'Good'; amber = 'Fair'; red = 'Poor'; notmeasured = 'Not measured' }[$lv]; if (-not $word) { $word = $lv }
        & $tile (Get-StatusClass $lv) 'Call path quality' $word (HtmlEncode $md.health.headline)
    } else { & $tile 'info' 'Call path quality' 'Not run' 'No media test in this export.' }
    # PBX connectivity
    if ($cx.measured) {
        $all = @(Get-Array $cx.checks); $bad = @($all | Where-Object { $_.status -eq 'fail' })
        $nInfo = @($all | Where-Object { $_.status -eq 'info' }).Count
        if (@($bad).Count -eq 0) { & $tile 'ok' 'PBX connectivity' 'No failures' (HtmlEncode ('{0} checks, {1} informational.' -f @($all).Count, $nInfo)) }
        else { & $tile 'fail' 'PBX connectivity' ('{0} of {1} failed' -f @($bad).Count, @($all).Count) (HtmlEncode ((@($bad | ForEach-Object { $_.check + ' ' + $_.port }) -join ', '))) }
    } else { & $tile 'info' 'PBX connectivity' 'Not run' '' }
    # Phones
    if ($ph.measured) {
        $items = @(Get-Array $ph.items)
        $read = @($items | Where-Object { $_.sipServer }).Count
        $reg  = @($items | Where-Object { $_.registration -like 'Registered*' }).Count
        $sub = 'Web UI not read.'; if ($read -gt 0) { $sub = ('{0} read, {1} registered' -f $read, $reg) }
        # A phone provisioning from another PBX loses its config at its next reboot,
        # so it turns the tile amber even when every phone is registered right now.
        $stale = @($items | Where-Object { $_.provisioningMismatch }).Count
        if ($stale -gt 0) { $sub += ('. {0} provision(s) from another PBX - see the table.' -f $stale) }
        $cls = 'ok'; if (@($items).Count -eq 0 -or $stale -gt 0) { $cls = 'warn' }
        & $tile $cls 'Yealink phones' ('{0} found' -f @($items).Count) (HtmlEncode $sub)
    } else { & $tile 'info' 'Yealink phones' 'Not run' '' }
    # SBC
    if ($sb.measured) {
        if (@($routerIps).Count -gt 0) {
            $sub = 'A phone carries the others'' traffic to the PBX.'
            if ($sb.thisPc) { $sub += ' A Windows SBC also runs on ' + (HtmlEncode $site.computer) + '.' }
            & $tile 'info' 'SBC' ('Router Phone ' + ($routerIps -join ', ')) $sub
        } elseif ($sb.thisPc) {
            & $tile (Get-StatusClass $sb.thisPc.health) 'SBC' ('On ' + $site.computer) (HtmlEncode ($sb.thisPc.verdict -replace '^THIS PC: 3CX SBC ', ''))
        } else {
            $cand = @(Get-Array $sb.lan | Where-Object { $_.verdict -like 'very likely*' -or $_.verdict -like 'likely*' })
            if (@($cand).Count) { $c0 = @($cand)[0]; & $tile 'ok' 'SBC' ([string]$c0.ip) (HtmlEncode $c0.verdict) }
            else { & $tile 'info' 'SBC' 'None found' 'No local SBC identified on this LAN.' }
        }
    } else { & $tile 'info' 'SBC' 'Not run' '' }
    # Security
    $nHigh = @($findings | Where-Object { $_.severity -eq 'high' }).Count
    $nRev  = @($findings | Where-Object { $_.severity -eq 'review' }).Count
    if (@($findings).Count -eq 0) { & $tile 'info' 'Security' 'Not run' 'No Security tab checks in this export.' }
    elseif ($nHigh -gt 0) { & $tile 'fail' 'Security' ('{0} high' -f $nHigh) ('{0} more to review' -f $nRev) }
    elseif ($nRev -gt 0)  { & $tile 'warn' 'Security' ('{0} to review' -f $nRev) 'Nothing high.' }
    else { & $tile 'ok' 'Security' 'Nothing flagged' '' }
    [void]$h.Append('</div>')

    # ---- what to do ----
    $todo = New-Object System.Collections.Generic.List[string]
    if ($md.measured -and $md.health) { foreach ($a in (Get-Array $md.health.actions)) { [void]$todo.Add('<li><span class="area">Call path:</span> ' + (HtmlEncode $a) + '</li>') } }
    foreach ($f in @($findings | Where-Object { $_.severity -eq 'high' -or $_.severity -eq 'review' })) {
        $act = ''; if ($f.action) { $act = ' <span class="note">&rarr; ' + (HtmlEncode $f.action) + '</span>' }
        [void]$todo.Add('<li><span class="pill ' + (Get-StatusClass $f.severity) + '">' + (HtmlEncode $sevLabel[[string]$f.severity]) + '</span> <span class="area">' + (HtmlEncode $f.area) + ':</span> ' + (HtmlEncode $f.finding) + $act + '</li>')
    }
    [void]$h.Append('<section><h2 id="todo">What to do</h2>')
    if ($todo.Count -gt 0) { [void]$h.Append('<ol class="todo">' + ($todo -join '') + '</ol>') }
    else { [void]$h.Append('<p>Nothing needs action in the checks that ran.</p>') }
    [void]$h.Append('</section>')

    # ---- 3CX connectivity ----
    [void]$h.Append('<section>' + (New-SectionHead '3CX connectivity' 'cx' $cx $zone))
    if ($cx.measured) {
        if ($cx.summary) { [void]$h.Append('<div class="summary">' + (HtmlEncode $cx.summary) + '</div>') }
        # (Not "$rows": New-Table's own -Rows would shadow it inside the colour callback.)
        $cxData = @(Get-Array $cx.checks | ForEach-Object { ,@((HtmlEncode $_.check), (HtmlEncode $_.target), (HtmlEncode $_.port), (HtmlEncode $_.result), (HtmlEncode $_.detail), [string]$_.status) })
        [void]$h.Append((New-Table -Headers @('Check', 'Target', 'Port', 'Result', 'Detail') -Rows @($cxData | ForEach-Object { ,@($_[0..4]) }) -CellClass { param($row, $ci, $ri) if ($ci -eq 3) { return (Get-StatusClass ([string]@($cxData[$ri])[5])) } }))
    }
    [void]$h.Append('</section>')

    # ---- media ----
    [void]$h.Append('<section>' + (New-SectionHead 'Call path quality (media)' 'media' $md $zone))
    if ($md.measured) {
        if ($md.health) {
            [void]$h.Append('<div class="callout ' + (Get-StatusClass $md.health.level) + '"><b>' + (HtmlEncode $md.health.headline) + '</b></div>')
            $subData = @(Get-Array $md.health.subscores | ForEach-Object { ,@((HtmlEncode ([string]$_.level).ToUpper()), (HtmlEncode $_.name), (HtmlEncode $_.summary), (HtmlEncode $_.remedy), [string]$_.level) })
            [void]$h.Append((New-Table -Headers @('Level', 'Area', 'Finding', 'What to do') -Rows @($subData | ForEach-Object { ,@($_[0..3]) }) -CellClass { param($row, $ci, $ri) if ($ci -eq 0) { return (Get-StatusClass ([string]@($subData[$ri])[4])) } }))
        }
        $mt = $md.metrics
        if ($mt -and $null -ne $mt.lossPct) {
            $cell = { param($k, $v) '<div class="metric"><div class="k">' + (HtmlEncode $k) + '</div><div class="v">' + (HtmlEncode $v) + '</div></div>' }
            $parts = @((& $cell 'Packet loss' ('{0}%' -f $mt.lossPct)), (& $cell 'Jitter' ('{0} ms' -f $mt.jitterMs)), (& $cell 'Round trip p50' ('{0} ms' -f $mt.rttP50Ms)), (& $cell 'Round trip p95' ('{0} ms' -f $mt.rttP95Ms)))
            if ($null -ne $mt.mos) { $parts += (& $cell 'Estimated MOS' ([string]$mt.mos)) }
            [void]$h.Append('<div class="metrics">' + ($parts -join '') + '</div>')
            [void]$h.Append('<p class="note">Measured over the SIP signalling path (UDP 5060) and STUN from this PC - good proxies for call audio, but not the audio itself. ' + (HtmlEncode ('{0} of {1} probes answered.' -f $mt.received, $mt.sent)) + '</p>')
        }
        if ($mt -and $mt.soak) {
            $s = $mt.soak
            [void]$h.Append('<p>' + (HtmlEncode ('Soak: {0} minute(s), {1} cycle(s), {2} outage(s); worst loss {3}%, worst jitter {4} ms, worst p95 {5} ms.' -f $s.minutes, $s.cycles, $s.outages, $s.worstLossPct, $s.worstJitterMs, $s.worstRttP95Ms)) + '</p>')
        }
        $mdData = @(Get-Array $md.checks | ForEach-Object { ,@((HtmlEncode $_.group), (HtmlEncode $_.check), (HtmlEncode $_.result), (HtmlEncode $_.detail), [string]$_.status) })
        [void]$h.Append('<h3>All media checks</h3>' + (New-Table -Headers @('Group', 'Check', 'Result', 'Detail') -Rows @($mdData | ForEach-Object { ,@($_[0..3]) }) -CellClass { param($row, $ci, $ri) if ($ci -eq 2) { return (Get-StatusClass ([string]@($mdData[$ri])[4])) } }))
    }
    [void]$h.Append('</section>')

    # ---- phones ----
    [void]$h.Append('<section>' + (New-SectionHead 'Yealink phones' 'phones' $ph $zone))
    if ($ph.measured) {
        $items = @(Get-Array $ph.items)
        if (@($items).Count -eq 0) { [void]$h.Append('<p>No Yealink phones were found on the LAN.</p>') }
        else {
            $prow = @($items | ForEach-Object {
                $via = HtmlEncode $_.sipServer
                if ($_.sipServer -and ($routerIps -contains ([string]$_.sipServer -replace ':\d+$', ''))) { $via += ' <span class="pill info">Router Phone</span>' }
                if ($routerIps -contains [string]$_.ip) { $via += ' <span class="pill info">is the Router Phone</span>' }
                # Host only - the export never carries the provisioning path.
                $prov = HtmlEncode $_.provisioningHost
                if ($_.provisioningMismatch) { $prov += (' <span class="pill fail">stale</span><br><span class="note">' + (HtmlEncode $_.provisioningNote) + '</span>') }
                ,@(('<span class="mono">' + (HtmlEncode $_.ip) + '</span>'), ('<span class="mono">' + (HtmlEncode $_.mac) + '</span>'), (HtmlEncode $_.model), (HtmlEncode $_.firmware), $via, (HtmlEncode $_.registration), (HtmlEncode $_.vq), $prov)
            })
            [void]$h.Append((New-Table -Headers @('IP', 'MAC', 'Model', 'Firmware', 'SIP server', 'Registration', 'Voice-quality readiness', 'Provisions from') -Rows $prow))
        }
    }
    [void]$h.Append('</section>')

    # ---- SIP / SBC ----
    [void]$h.Append('<section>' + (New-SectionHead 'SIP / SBC' 'sbc' $sb $zone))
    if ($sb.measured) {
        if ($sb.thisPc) {
            $t = $sb.thisPc
            [void]$h.Append('<h3>The 3CX SBC on ' + (HtmlEncode $site.computer) + '</h3><div class="callout ' + (Get-StatusClass $t.health) + '"><b>' + (HtmlEncode ($t.verdict -replace '^THIS PC: ', '')) + '</b><br>' + (HtmlEncode $t.detail) + '</div>')
        }
        $lan = @(Get-Array $sb.lan | Where-Object { -not $_.isThisPc })
        if (@($lan).Count) {
            $lrow = @($lan | ForEach-Object { ,@(('<span class="mono">' + (HtmlEncode $_.ip) + '</span>'), (HtmlEncode $_.verdict), (HtmlEncode $_.platform), (HtmlEncode $_.hostname), (HtmlEncode $_.detail)) })
            [void]$h.Append('<h3>SIP responders on the LAN</h3>' + (New-Table -Headers @('IP', 'Verdict', 'Platform', 'Hostname', 'Why') -Rows $lrow))
        } elseif (-not $sb.thisPc) { [void]$h.Append('<p>No SIP responder or Raspberry Pi on the LAN.</p>') }
    }
    [void]$h.Append('</section>')

    # ---- network ----
    [void]$h.Append('<section>' + (New-SectionHead 'Network' 'network' $nw $zone))
    if ($nw.measured) {
        $roleData = @(Get-Array $nw.roles | ForEach-Object { ,@((HtmlEncode $_.role), ('<span class="mono">' + (HtmlEncode $_.ip) + '</span>'), ('<span class="mono">' + (HtmlEncode $_.mac) + '</span>'), (HtmlEncode $_.vendor), (HtmlEncode $_.note), [bool]$_.warn) })
        if (@($roleData).Count) { [void]$h.Append((New-Table -Headers @('Role', 'IP', 'MAC', 'Vendor', 'Note') -Rows @($roleData | ForEach-Object { ,@($_[0..4]) }) -CellClass { param($row, $ci, $ri) if ($ci -eq 4 -and @($roleData[$ri])[5]) { return 'fail' } })) }
        $lsn = @(Get-Array $nw.listeners)
        if (@($lsn).Count) {
            $lr = @($lsn | ForEach-Object { ,@((HtmlEncode $_.localAddress), (HtmlEncode $_.port), (HtmlEncode $_.state), (HtmlEncode $_.process)) })
            [void]$h.Append('<h3>3CX ports listening on ' + (HtmlEncode $site.computer) + '</h3>' + (New-Table -Headers @('Address', 'Port', 'State', 'Process') -Rows $lr))
        }
    }
    [void]$h.Append('</section>')

    # ---- security ----
    $anySec = ($sec.thisPc.measured -or $sec.eventLog.measured -or $sec.blacklist.measured)
    $secHead = [pscustomobject]@{ measured = $anySec; measuredLocal = (@(@($sec.thisPc, $sec.eventLog, $sec.blacklist) | Where-Object { $_.measured } | ForEach-Object { $_.measuredLocal } | Sort-Object) | Select-Object -Last 1) }
    [void]$h.Append('<section>' + (New-SectionHead 'Security' 'security' $secHead $zone))
    if ($anySec) {
        [void]$h.Append('<p class="note">Read-only checks. Not visible to any of them: the router''s port forwards - from inside the LAN there is no honest way to test what the internet can reach.</p>')
        if (@($findings).Count) {
            $frow = @($findings | ForEach-Object { ,@(('<span class="pill ' + (Get-StatusClass $_.severity) + '">' + (HtmlEncode $sevLabel[[string]$_.severity]) + '</span>'), (HtmlEncode $_.area), (HtmlEncode $_.finding), (HtmlEncode $_.action)) })
            [void]$h.Append((New-Table -Headers @('Severity', 'Area', 'Finding', 'What to do') -Rows $frow))
        }
        $ev = $sec.eventLog
        if ($ev.measured -and $ev.analysis) {
            $a = $ev.analysis
            [void]$h.Append('<h3>From the PBX event log</h3><p class="note">' + (HtmlEncode ('{0}: {1} events, {2} to {3}.' -f $a.file, $a.events, (Format-Time $a.firstUtc $zone), (Format-Time $a.lastUtc $zone))) + '</p>')
            foreach ($s in (Get-Array $a.sbcs)) {
                $thisTxt = ''; if ($s.isThisPc) { $thisTxt = ' (this PC)' }
                [void]$h.Append('<p><b>SBC ' + (HtmlEncode $s.name) + '</b> ' + (HtmlEncode ('public {0}, LAN {1}{2}: {3} outage(s), {4} in total.' -f $s.publicIp, $s.lanIp, $thisTxt, @(Get-Array $s.outages).Count, (Format-Minutes $s.totalMinutes))) + '</p>')
                $orow = @(Get-Array $s.outages | ForEach-Object {
                    $dn = '(before the export)'; if ($_.downUtc) { $dn = Format-Time $_.downUtc $zone 'ddd d MMM HH:mm:ss' }
                    $up = '-'; if ($_.upUtc) { $up = Format-Time $_.upUtc $zone 'ddd d MMM HH:mm:ss' }
                    $dur = Format-Minutes $_.minutes; if ($_.stillDown) { $dur = '&gt;' + $dur + ' (still down)' } else { $dur = HtmlEncode $dur }
                    ,@((HtmlEncode $dn), (HtmlEncode $up), $dur, (HtmlEncode $_.cause))
                })
                if (@($orow).Count) { [void]$h.Append((New-Table -Headers @('Down', 'Up', 'Lasted', 'Cause') -Rows $orow)) }
                foreach ($rc in (Get-Array $s.recurring)) { [void]$h.Append('<p class="note">Pattern: ' + (HtmlEncode $rc) + '</p>') }
            }
            $at = $a.attacks
            if ($at -and $at.unsolicitedCalls) {
                $tgts = (@(Get-Array $at.topTargets | ForEach-Object { '{0} ({1} tries)' -f $_.Number, $_.Count }) -join ', ')
                $rngs = (@(Get-Array $at.topRanges | ForEach-Object { '{0} x{1}' -f $_.Prefix, $_.Count }) -join ', ')
                [void]$h.Append('<p>' + (HtmlEncode ('{0} unsolicited calls from {1} addresses were turned away (peak {2} in a day). They tried to reach: {3}. Busiest ranges: {4}.' -f $at.unsolicitedCalls, $at.sources, $at.peakPerDay, $tgts, $rngs)) + '</p>')
            }
        }
        $bl = $sec.blacklist
        if ($bl.measured -and $bl.entries) {
            $brow = @(Get-Array $bl.entries | ForEach-Object { ,@((HtmlEncode $_.action), ('<span class="mono">' + (HtmlEncode $_.ip) + '</span>'), (HtmlEncode $_.expires), (HtmlEncode $_.description)) })
            [void]$h.Append('<h3>3CX IP blacklist</h3>' + (New-Table -Headers @('Action', 'IP', 'Expires', 'Description') -Rows $brow))
        }
        $tp = $sec.thisPc
        if ($tp.measured -and $tp.posture) {
            $p = $tp.posture
            $prow2 = @(Get-Array $p.listeners | ForEach-Object {
                $fw = $_.firewall
                $st = ''; $sc = ''; $ru = ''
                if ($fw) { $st = $fw.state; $sc = $fw.allowedFrom; $ru = (@(Get-Array $fw.rules) | Select-Object -First 1) }
                ,@((HtmlEncode $_.protocol), (HtmlEncode $_.port), (HtmlEncode $_.service), (HtmlEncode $_.process), (HtmlEncode $st), (HtmlEncode $sc), (HtmlEncode $ru))
            })
            [void]$h.Append('<h3>3CX / SIP ports on ' + (HtmlEncode $p.computer) + ' (Windows Firewall)</h3>')
            if (@($prow2).Count) { [void]$h.Append((New-Table -Headers @('Proto', 'Port', 'Service', 'Process', 'Firewall', 'Allowed from', 'Rule') -Rows $prow2)) }
            else { [void]$h.Append('<p>Nothing listening on a SIP or 3CX port.</p>') }
        }
    }
    [void]$h.Append('</section>')

    [void]$h.Append((Build-HardeningHtml -R $R))

    [void]$h.Append('<footer>Generated by Generate-3cxReport.ps1 ' + (HtmlEncode $script:GeneratorVersion) + ' from ' + (HtmlEncode ('{0} {1}' -f $R.schema, $R.schemaVersion)) +
                    '. Every figure comes from the checks listed; sections marked "not run" were not measured in this export, and sections can come from different runs - each says when it was measured.</footer>')
    [void]$h.Append('</div></body></html>')
    return $h.ToString()
}

function Build-HardeningHtml {
    # A crib sheet of established measures - the ones that help whatever the
    # attackers do next - each with this site's own evidence where the export has
    # some. Manual blocking of attacking addresses is deliberately NOT on it: the
    # ranges rotate within days, and 3CX's automatic blacklist already does that job.
    param($R)
    $sec = $R.security
    $a = $null; if ($sec.eventLog.analysis) { $a = $sec.eventLog.analysis.attacks }
    $findings = @(Get-Array $sec.findings)
    $has = { param($rx) @($findings | Where-Object { ([string]$_.finding + ' ' + [string]$_.area) -match $rx }).Count -gt 0 }
    $items = New-Object System.Collections.Generic.List[object]
    $add = { param($title, $how, $why, $evidence) $items.Add([pscustomobject]@{ Title = $title; How = $how; Why = $why; Evidence = $evidence }) }

    $ev = ''
    if ($a -and $a.unsolicitedCalls) {
        $t = (@(Get-Array $a.topTargets | Select-Object -First 2 | ForEach-Object { [string]$_.Number }) -join ' and ')
        $ev = ('{0} toll-fraud probes in the event log, trying to reach {1}.' -f $a.unsolicitedCalls, $t)
    }
    & $add 'Bar what the business never dials - at the carrier' 'Ask the SIP trunk provider to bar international and premium-rate calls the business does not make, and to set a daily spend cap.' 'Works even if an extension or the PBX is compromised: the cost of toll fraud lands at the carrier.' $ev
    & $add 'Allow only the destinations the business calls' 'Outbound rules should permit only the countries and number types actually dialled (plus any allowed-countries setting your 3CX version offers).' 'Toll-fraud probes aim at international numbers; a call the rules cannot route cannot be charged.' $ev

    $ev = ''
    $wb = @(); if ($a) { $wb = @(Get-Array $a.wanBlocked) }
    if (@($wb).Count) {
        $u = (@($wb | ForEach-Object { [string]$_.User } | Where-Object { $_ } | Sort-Object -Unique) -join ', ')
        $ev = ('"Block WAN requests" stopped {0} call attempt(s) from outside the LAN presenting extension {1}''s login.' -f @($wb).Count, $u)
    }
    & $add 'Keep extensions off the internet unless they need it' 'Leave "Block WAN requests" (disallow use outside the LAN) on for every extension that does not work remotely - desk phones behind an SBC or Router Phone do not need it off.' 'A stolen or guessed login is useless from outside the office.' $ev

    $ev = ''
    $sipBl = @(); if ($a) { $sipBl = @(Get-Array $a.blacklisted | Where-Object { [string]$_.Source -like 'SIP*' }) }
    if (@($wb | Where-Object { [string]$_.User -match '^\d+$' }).Count) { $ev = 'The attackers presented a bare extension number as the username.' }
    elseif (@($sipBl).Count) { $ev = ('{0} address(es) blacklisted for SIP password guessing.' -f @($sipBl).Count) }
    & $add 'Make SIP logins unguessable' 'Use an authentication ID that is NOT the extension number, and a long random password - 3CX can generate both; never replace them with simple ones.' 'Guessing needs the username first; a random authentication ID removes the easy half.' $ev

    $ev = ''
    $web = @(); if ($a) { $web = @(Get-Array $a.blacklisted | Where-Object { [string]$_.Source -notlike 'SIP*' }) }
    if (@($web).Count) { $ev = ('{0} address(es) locked out for web-client password guessing, for {1} s each.' -f @($web).Count, ((@($web | ForEach-Object { $_.Seconds } | Sort-Object -Unique)) -join '/')) }
    & $add 'Protect the admin console and web client' 'Turn on two-factor authentication for admin and web-client users where your 3CX version supports it, and give admin rights only to those who need them.' 'The web login is attacked too, and its lockout is short.' $ev

    $ev = ''
    if (& $has 'Allow entry') { $ev = 'The pasted IP blacklist has allow entries that are not this site''s current address.' }
    elseif (& $has 'NOT on the allow list') { $ev = 'This site''s public IP is not on the allow list.' }
    & $add 'Keep the allow list tight - and automatic blacklisting on' 'Allow-list only addresses you control (a static site IP); remove old ISP addresses and setup-time entries. Do not switch off 3CX''s automatic blacklisting.' 'Allow-listed addresses are never locked out. Automatic blacklisting is the defence that keeps up with rotating attackers - manual blocks of their ranges do not.' $ev

    $ev = ''
    $routers = @(Get-Array $R.sbc.lan | Where-Object { $_.is3cxRouterPhone })
    if ($R.sbc.thisPc -or @($routers).Count) { $ev = 'This site reaches the PBX through an SBC or Router Phone, which dial out - nothing needs forwarding in.' }
    if (& $has 'Remote Desktop.*allowed in from Any') { $ev = ($ev + ' Remote Desktop on the SBC''s PC accepts connections from any address - make sure the router does not forward it.').Trim() }
    & $add 'Forward nothing from the internet to the site' 'Check the router: no port forwards to phones, the SBC or its PC (5060, RTP, RDP or anything else). Keep SIP ALG off.' 'An SBC and a Router Phone make outbound connections only; every inbound forward is exposure with no benefit.' $ev

    $ev = ''
    if (& $has '3cxsbc\.conf|Stray copy') { $ev = 'The SBC''s config (tunnel password inside) is readable by ordinary users, and/or a stray copy exists.' }
    & $add 'Guard the SBC''s tunnel password' 'On a Windows SBC, 3cxsbc.conf should be readable by SYSTEM and Administrators only; delete stray copies. Better, run the SBC on a device nobody logs on to.' 'Anyone with that file can impersonate the site''s SBC to the PBX.' $ev

    $ev = ''
    $fwv = @(Get-Array $R.phones.items | ForEach-Object { ('{0} {1}' -f $_.model, $_.firmware).Trim() } | Where-Object { $_ } | Sort-Object -Unique)
    if (@($fwv).Count) { $ev = ('Phone firmware seen: ' + ($fwv -join '; ') + '.') }
    & $add 'Keep 3CX and phone firmware current' 'Apply 3CX updates and approved phone firmware through the 3CX console.' 'Most breaches use known, already-fixed flaws.' $ev

    & $add 'Watch for it' 'Have 3CX notify an administrator of security events, and review the event log periodically - 3CX Checker''s Security tab imports it and summarises attacks and tunnel outages.' 'Attacks are continuous; noticing a change early is the point.' ''

    $hrows = @($items | ForEach-Object {
        $e = '<span class="note">-</span>'; if ($_.Evidence) { $e = HtmlEncode $_.Evidence }
        ,@('&#9744;', ('<b>' + (HtmlEncode $_.Title) + '</b><br>' + (HtmlEncode $_.How)), (HtmlEncode $_.Why), $e)
    })
    return ('<section><h2 id="hardening">Hardening checklist</h2>' +
            '<p class="note">Established measures that help whatever the attackers do next. "This site" shows what this export found; a dash means it could not be checked from here - look in the 3CX console or on the router. Blocking attacking addresses by hand is left off on purpose: in a real log each range was active for only 1 to 4 days, and 3CX''s automatic blacklisting already blocks each new one.</p>' +
            (New-Table -Headers @('', 'Do this', 'Why it helps', 'This site') -Rows $hrows) + '</section>')
}

function Get-GeneratorOutputDir {
    $d = Join-Path $PSScriptRoot 'Output'
    try {
        if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force -ErrorAction Stop | Out-Null }
        $probe = Join-Path $d ('.write-test-' + [guid]::NewGuid().ToString('N'))
        [System.IO.File]::WriteAllText($probe, ''); Remove-Item -LiteralPath $probe -Force
        return $d
    } catch {}
    $d2 = Join-Path ([Environment]::GetFolderPath('MyDocuments')) '3CX-Checker\Output'
    New-Item -ItemType Directory -Path $d2 -Force | Out-Null
    return $d2
}

function Save-3cxReport {
    # Parse, build, write. Returns the HTML path.
    param([string]$Text,[string]$SiteName = '',[string]$OutDir = '')
    $r = Extract-3cxReportJson -Text $Text
    if (-not $SiteName) { $SiteName = [string]$r.site.name }
    if (-not $OutDir) { $OutDir = Get-GeneratorOutputDir }
    $name = $SiteName; if (-not $name) { $name = [string]$r.site.computer }
    $path = Join-Path $OutDir ('3CX-Report-{0}-{1}.html' -f (Slugify $name), (Get-Date -Format 'yyyyMMdd-HHmmss'))
    [System.IO.File]::WriteAllText($path, (Build-3cxReportHtml -R $r -SiteName $SiteName), (New-Object System.Text.UTF8Encoding($false)))
    return $path
}

if ($NoGui) { return }

# -----------------------------------------------------------------------------
# GUI
# -----------------------------------------------------------------------------
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$form = New-Object System.Windows.Forms.Form
$form.Text = ('3CX site report generator ' + $script:GeneratorVersion)
$form.Size = New-Object System.Drawing.Size(860, 640)
$form.MinimumSize = New-Object System.Drawing.Size(640, 420)
$form.StartPosition = 'CenterScreen'
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

$top = New-Object System.Windows.Forms.Panel
$top.Dock = 'Top'; $top.Height = 62
$lblSite = New-Object System.Windows.Forms.Label
$lblSite.Text = 'Site name:'; $lblSite.Location = New-Object System.Drawing.Point(8, 12); $lblSite.Size = New-Object System.Drawing.Size(70, 20)
$txtSite = New-Object System.Windows.Forms.TextBox
$txtSite.Location = New-Object System.Drawing.Point(80, 9); $txtSite.Size = New-Object System.Drawing.Size(260, 24)
$lblHint = New-Object System.Windows.Forms.Label
$lblHint.Text = 'Paste the export from 3CX Checker (Export report puts it on the clipboard, with or without the BEGIN/END lines), or browse to the saved .json:'
$lblHint.Location = New-Object System.Drawing.Point(8, 40); $lblHint.Size = New-Object System.Drawing.Size(830, 18)
$lblHint.ForeColor = [System.Drawing.Color]::DimGray
$top.Controls.AddRange(@($lblSite, $txtSite, $lblHint))

$paste = New-Object System.Windows.Forms.TextBox
$paste.Multiline = $true; $paste.ScrollBars = 'Both'; $paste.WordWrap = $false; $paste.Dock = 'Fill'
$paste.Font = New-Object System.Drawing.Font('Consolas', 9)
$paste.MaxLength = 0

$bottom = New-Object System.Windows.Forms.Panel
$bottom.Size = New-Object System.Drawing.Size($form.ClientSize.Width, 72)
$bottom.Dock = 'Bottom'
$btnBrowse = New-Object System.Windows.Forms.Button
$btnBrowse.Text = 'Browse JSON...'; $btnBrowse.Location = New-Object System.Drawing.Point(8, 8); $btnBrowse.Size = New-Object System.Drawing.Size(120, 28)
$btnClear = New-Object System.Windows.Forms.Button
$btnClear.Text = 'Clear'; $btnClear.Location = New-Object System.Drawing.Point(134, 8); $btnClear.Size = New-Object System.Drawing.Size(80, 28)
$btnGen = New-Object System.Windows.Forms.Button
$btnGen.Text = 'Generate report'; $btnGen.Size = New-Object System.Drawing.Size(160, 28); $btnGen.Anchor = 'Top,Right'
$btnGen.Location = New-Object System.Drawing.Point(($bottom.Width - 170), 8)
$btnGen.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Location = New-Object System.Drawing.Point(8, 44); $lblStatus.Size = New-Object System.Drawing.Size(($bottom.Width - 130), 20); $lblStatus.Anchor = 'Top,Left,Right'
$lblStatus.ForeColor = [System.Drawing.Color]::DimGray
$lblStatus.Text = ('Reports save to: ' + (Get-GeneratorOutputDir))
$lnkOpen = New-Object System.Windows.Forms.LinkLabel
$lnkOpen.Text = ''; $lnkOpen.Size = New-Object System.Drawing.Size(110, 20); $lnkOpen.Anchor = 'Top,Right'
$lnkOpen.Location = New-Object System.Drawing.Point(($bottom.Width - 118), 44)
$bottom.Controls.AddRange(@($btnBrowse, $btnClear, $btnGen, $lblStatus, $lnkOpen))

$form.Controls.Add($paste)
$form.Controls.Add($top)
$form.Controls.Add($bottom)

$state = @{ LastPath = ''; AutoSite = '' }

$paste.Add_TextChanged({
    # Offer the report's own site name while the box is empty or still holds the
    # last one it filled in.
    try {
        $r = Extract-3cxReportJson -Text $paste.Text
        $n = [string]$r.site.name
        if ($n -and (-not $txtSite.Text.Trim() -or $txtSite.Text -eq $state.AutoSite)) { $txtSite.Text = $n; $state.AutoSite = $n }
    } catch {}
})
$btnBrowse.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Filter = 'JSON files (*.json)|*.json|All files (*.*)|*.*'
    $dlg.InitialDirectory = (Get-GeneratorOutputDir)
    if ($dlg.ShowDialog($form) -eq 'OK') {
        try { $paste.Text = [System.IO.File]::ReadAllText($dlg.FileName) }
        catch { [void][System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Could not read the file', 'OK', 'Error') }
    }
})
$btnClear.Add_Click({ $paste.Clear(); $txtSite.Clear(); $state.AutoSite = ''; $lnkOpen.Text = '' })
$btnGen.Add_Click({
    try {
        $path = Save-3cxReport -Text $paste.Text -SiteName $txtSite.Text.Trim()
        $state.LastPath = $path
        $lblStatus.Text = ('Saved: ' + $path)
        $lnkOpen.Text = 'Open report'
        if ([System.Windows.Forms.MessageBox]::Show(("Report saved to:`n$path`n`nOpen it now?"), 'Done', 'YesNo', 'Information') -eq 'Yes') { Start-Process $path }
    } catch {
        [void][System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Could not generate the report', 'OK', 'Error')
    }
})
$lnkOpen.Add_LinkClicked({ if ($state.LastPath -and (Test-Path -LiteralPath $state.LastPath)) { Start-Process $state.LastPath } })

[void]$form.ShowDialog()
$form.Dispose()
