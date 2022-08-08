###############################################################################
#
###############################################################################

###############################################################################
# DrawMenu and Menu credit "JBs Powershell"
# http://mspowershell.blogspot.com/2009/02/cli-menu-in-powershell.html?m=1

function DrawMenu {
    ## supportfunction to the Menu function below
    param ($menuItems, $menuPosition, $menuTitel)
    $fcolor = $host.UI.RawUI.ForegroundColor
    $bcolor = $host.UI.RawUI.BackgroundColor
    $l = $menuItems.length + 1
    cls
    $menuwidth = $menuTitel.length + 4
    Write-Host "`t" -NoNewLine
    Write-Host ("*" * $menuwidth) -fore $fcolor -back $bcolor
    Write-Host "`t" -NoNewLine
    Write-Host "* $menuTitel *" -fore $fcolor -back $bcolor
    Write-Host "`t" -NoNewLine
    Write-Host ("*" * $menuwidth) -fore $fcolor -back $bcolor
    Write-Host ""
    Write-debug "L: $l MenuItems: $menuItems MenuPosition: $menuposition"
    for ($i = 0; $i -le $l;$i++) {
        Write-Host "`t" -NoNewLine
        if ($i -eq $menuPosition) {
            Write-Host "$($menuItems[$i])" -fore $bcolor -back $fcolor
        } else {
            Write-Host "$($menuItems[$i])" -fore $fcolor -back $bcolor
        }
    }
}

function Menu {
    ## Generate a small "DOS-like" menu.
    ## Choose a menuitem using up and down arrows, select by pressing ENTER
    param ([array]$menuItems, $menuTitel = "MENU")
    $vkeycode = 0
    $pos = 0
    DrawMenu $menuItems $pos $menuTitel
    While ($vkeycode -ne 13) {
        $press = $host.ui.rawui.readkey("NoEcho,IncludeKeyDown")
        $vkeycode = $press.virtualkeycode
        Write-host "$($press.character)" -NoNewLine
        If ($vkeycode -eq 38) {$pos--}
        If ($vkeycode -eq 40) {$pos++}
        if ($pos -lt 0) {$pos = $menuItems.length -1}
        if ($pos -ge $menuItems.length) {$pos = 0}
        DrawMenu $menuItems $pos $menuTitel
    }
    Write-Output $($menuItems[$pos])
}

###############################################################################
#
###############################################################################

# navigate to script directory
Push-Location (split-path $MyInvocation.MyCommand.Path)

###############################################################################
# determine if fluent-bit is already installed (via package, in local ./bin directory or in current PATH)
$fluentbit_installed = 0
$fluentbit_path = ''
$fluentbit_bin = ''
$fluent_bit_version = '1.9'
$fluent_bit_full_version = '1.9.6'
if ([Environment]::Is64BitOperatingSystem) {
    $fluent_bit_platform = 'win64'
} else {
    $fluent_bit_platform = 'win32'
}
$fluent_bit_zip = "fluent-bit-$fluent_bit_full_version-$fluent_bit_platform.zip"
$fluent_bit_shafile = "fluent-bit-$fluent_bit_full_version-$fluent_bit_platform.zip.sha256"

if (Test-Path -Path './bin/fluent-bit.exe' -PathType Leaf) {
    # ./bin/fluent-bit.exe exists, we'll use that
    $fluentbit_bin = (Resolve-Path -Path './bin/fluent-bit.exe')
    $fluentbit_path = Split-Path -Path "$fluentbit_bin"

} elseif ((Get-Package | Where-Object -Property Name -like 'fluent-bit').Length -gt 0) {
    # package is installed, get the installation location from the registry and use that
    if ([Environment]::Is64BitOperatingSystem) {
        $fluentbit_path = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\WOW6432Node\Calyptia Inc.\fluent-bit').'(default)'
    } else {
        $fluentbit_path = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Calyptia Inc.\fluent-bit').'(default)'
    }
    $fluentbit_bin = $fluentbit_path + '/bin/fluent-bit.exe'

} else {
    # fluent-bit.exe is in PATH, use that
    $fluentbit_bin = (Get-Command 'fluent-bit.exe' -errorAction SilentlyContinue).Source
    if ($fluentbit_bin) {
        $fluentbit_path = Split-Path -Path "$fluentbit_bin"
    }
}
if ($fluentbit_bin) {
    $fluentbit_bin = (Resolve-Path -Path "$fluentbit_bin")
    $fluentbit_installed = (Test-Path -Path "$fluentbit_bin" -PathType Leaf)
}

###############################################################################
# fluent-bit is not already installed, try to download/extract it
if (-Not $fluentbit_installed) {

    # see if the .zip file already exists, and whether or not we should use it
    if (Test-Path -Path $fluent_bit_zip -PathType Leaf) {
        $title    = "$fluent_bit_zip found"
        $question = "Would you like to use existing $fluent_bit_zip at "+(Get-Location)+'?'
        $choices  = '&Yes', '&No'
        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 0)
        if ($decision -ne 0) {
            Remove-Item "$fluent_bit_zip"
        }
    }

    # download the zip file if requested
    if (-Not (Test-Path -Path $fluent_bit_zip -PathType Leaf)) {
        $title    = 'Download fluent-bit'
        $question = 'Would you like to download fluent-bit (zip) to '+(Get-Location)+'?'
        $choices  = '&Yes', '&No'
        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 0)
        if ($decision -eq 0) {
            $fluentbit_sha_url = "https://fluentbit.io/releases/$fluent_bit_version/$fluent_bit_shafile"
            $fluentbit_url = "https://fluentbit.io/releases/$fluent_bit_version/$fluent_bit_zip"
            Invoke-WebRequest -Uri "$fluentbit_sha_url" -OutFile "$fluent_bit_shafile"
            Invoke-WebRequest -Uri "$fluentbit_url" -OutFile "$fluent_bit_zip"
        }
    }

    # check whether or not we can do the sha sum, and if not, confirm if that's okay
    $fluentbit_sha_good = 0
    $ignore_sha_sum = 0
    if (-Not (Test-Path -Path $fluent_bit_shafile -PathType Leaf)) {
        $title    = "$fluent_bit_shafile not found"
        $question = "Cannot verify SHA256 of $fluent_bit_zip (missing $fluent_bit_shafile), abort?"
        $choices  = '&Yes', '&No'
        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 0)
        if ($decision -eq 1) {
            $ignore_sha_sum = 1
        }
    }

    if ((Test-Path -Path $fluent_bit_shafile -PathType Leaf) -and (Test-Path -Path $fluent_bit_zip -PathType Leaf)) {
        $fluentbit_expected_hash = ((Get-Content "$fluent_bit_shafile" -First 1).ToLower() -split '\s+')[0]
        $fluentbit_zip_hash = (Get-FileHash "$fluent_bit_zip").Hash.ToLower()
        if ($fluentbit_zip_hash -eq $fluentbit_expected_hash) {
            $fluentbit_sha_good = 1
        }
    }

    if (($fluentbit_sha_good -eq 1) -or ($ignore_sha_sum -eq 1)) {
        Expand-Archive "$fluent_bit_zip" -DestinationPath (Get-Location)
        if (Test-Path -Path "fluent-bit-$fluent_bit_full_version-$fluent_bit_platform" -PathType Container) {
            Get-ChildItem -Path "fluent-bit-$fluent_bit_full_version-$fluent_bit_platform" |
                Move-Item -Destination (Get-Location)
            Remove-Item -Path "fluent-bit-$fluent_bit_full_version-$fluent_bit_platform"
            $fluentbit_installed = (Test-Path -Path './bin/fluent-bit.exe' -PathType Leaf)
            if ($fluentbit_installed) {
                $fluentbit_bin = (Resolve-Path -Path './bin/fluent-bit.exe')
                $fluentbit_path = Split-Path -Path "$fluentbit_bin"
            }
        } else {
            Write-Host "Failed to expand $fluent_bit_zip" -ForegroundColor Red
        }
    } else {
        Write-Host "Could not download or verify SHA256 sum of $fluent_bit_zip" -ForegroundColor Red
    }
}

if (-Not $fluentbit_installed) {
    Write-Host "Visit https://docs.fluentbit.io/manual/installation/windows to download and install fluent-bit" -ForegroundColor Red
    Exit 1
}

###############################################################################
# fluent-bit is installed, get a list of the input filters available and prompt the user

$fluentbit_help = &"$fluentbit_bin" --help 2>&1
$inputs_regex = '(?ms)Inputs(.+?)Filters'
$fluentbit_help = $fluentbit_help -join "`n"
$fluentbit_help =
[regex]::Matches($fluentbit_help,$inputs_regex) |
 foreach {$_.groups[1].value -split "`n"} | Where-Object {$_}
$fluentbit_inputs = @()
foreach ($i in $fluentbit_help) {
    $input_name = ($i.Trim() -split '\s+')[0]
    $input_name = $input_name.subString(0, [System.Math]::Min(24, $input_name.Length))
    $fluentbit_inputs = $fluentbit_inputs + $input_name
}
$fluentbit_inputs = $fluentbit_inputs | Sort-Object
$input_chosen = Menu $fluentbit_inputs "Select input plugin (https://docs.fluentbit.io/manual/pipeline/inputs)"

###############################################################################
# prompt the user for values to the parameters for the chosen input plugin

Write-Host "Enter parameters for $input_chosen. Leave parameters blank for defaults."
Write-Host "  see https://docs.fluentbit.io/manual/pipeline/inputs"
Write-Host ""
$param_names = switch ( $input_chosen )
{
    'dummy' { @('Dummy', 'Start_time_sec', 'Start_time_nsec', 'Rate', 'Samples') }
    'random' { @('Samples', 'Interval_Sec', 'Interval_NSec') }
    'statsd' { @('Listen', 'Port') }
    'tail' { @('Buffer_Chunk_Size', 'Buffer_Max_Size', 'Path', 'Path_Key', 'Exclude_Path', 'Offset_Key', 'Read_from_Head', 'Refresh_Interval', 'Rotate_Wait', 'Ignore_Older', 'Skip_Long_Lines', 'Skip_Empty_Lines', 'DB', 'DB.sync', 'DB.locking', 'DB.journal_mode', 'Mem_Buf_Limit', 'Exit_On_Eof', 'Parser', 'Key', 'Inotify_Watcher', 'Tag', 'Tag_Regex', 'Static_Batch_Size') }
    'tcp' { @('Listen', 'Port', 'Buffer_Size', 'Chunk_Size', 'Format', 'Separator') }
    'windows_exporter_metrics' { @('scrape_interval') }
    'winevtlog' { @('Channels', 'Interval_Sec', 'DB') }
    'winlog' { @('Channels', 'Interval_Sec', 'DB') }
    'winstat' { @('Interval_Sec', 'Interval_NSec') }
    default { @() }
}
$param_map = @{}
foreach ($param_name in $param_names) {
    $param_val = Read-Host -Prompt "$input_chosen ${param_name}"
    $param_map[$param_name] = $param_val
}

###############################################################################
# prompt the user for connection and message format parameters

do { $malcolm_ip = Read-Host -Prompt 'Enter Malcolm host or IP address' } until (-Not [string]::IsNullOrWhiteSpace($malcolm_ip))
$malcolm_port = Read-Host -Prompt 'Enter Malcolm Filebeat TCP port (5045)'
if ([string]::IsNullOrWhiteSpace($malcolm_port)) {
    $malcolm_port = '5045'
}
$message_format = Read-Host -Prompt 'Enter fluent-bit output format (json_lines)'
if ([string]::IsNullOrWhiteSpace($message_format)) {
    $message_format = 'json_lines'
}
$message_nest = Read-Host -Prompt 'Nest values under field'
$message_module = Read-Host -Prompt 'Add "module" value'

###############################################################################
# prompt for TLS client ca/certificate/key files
$ca = ''
$cert = ''
$key = ''
if ((Test-Path -Path './ca.crt' -PathType Leaf) -and
    (Test-Path -Path './client.crt' -PathType Leaf) -and
    (Test-Path -Path './client.key' -PathType Leaf)) {
    $ca = './ca.crt'
    $cert = './client.crt'
    $key = './client.key'
} elseif ((Test-Path -Path '../../filebeat/certs' -PathType Container) -and
          (Test-Path -Path '../../filebeat/certs/ca.crt' -PathType Leaf) -and
          (Test-Path -Path '../../filebeat/certs/client.crt' -PathType Leaf) -and
          (Test-Path -Path '../../filebeat/certs/client.key' -PathType Leaf)) {
    $ca = '../../filebeat/certs/ca.crt'
    $cert = '../../filebeat/certs/client.crt'
    $key = '../../filebeat/certs/client.key'
}

while (([string]::IsNullOrWhiteSpace($ca)) -or
       ([string]::IsNullOrWhiteSpace($cert)) -or
       ([string]::IsNullOrWhiteSpace($key)) -or
       (-Not (Test-Path -Path "$ca" -PathType Leaf)) -or
       (-Not (Test-Path -Path "$cert" -PathType Leaf)) -or
       (-Not (Test-Path -Path "$key" -PathType Leaf))) {
    Write-Host "Enter paths and filenames of client certificate files"
    Write-Host "  e.g., files generated in Malcolm/filebeat/certs/ directory"
    $ca = Read-Host -Prompt 'Enter CA certificate file'
    $cert = Read-Host -Prompt 'Enter client certificate file'
    $key = Read-Host -Prompt 'Enter client key file'
}
$ca = (Resolve-Path -Path "$ca")
$cert = (Resolve-Path -Path "$cert")
$key = (Resolve-Path -Path "$key")

###############################################################################
# build fluent-bit.exe command
$fluentbit_command = @()
$fluentbit_command += "$fluentbit_bin"

# todo: get parser file

$fluentbit_command += "-i"
$fluentbit_command += "$input_chosen"

foreach ($element in $param_map.GetEnumerator()) {
    if (-Not ([string]::IsNullOrWhiteSpace($($element.Value)))) {
        $fluentbit_command += "-p"
        $fluentbit_command += $($element.Name)+'="'+$($element.Value)+'"'
    }
}

$fluentbit_command += "-o"
$fluentbit_command += "tcp://${malcolm_ip}:${malcolm_port}"
$fluentbit_command += "-p"
$fluentbit_command += "tls=on"
$fluentbit_command += "-p"
$fluentbit_command += "tls.verify=off"
$fluentbit_command += "-p"
$fluentbit_command += 'tls.ca_file='+'"'+$ca+'"'
$fluentbit_command += "-p"
$fluentbit_command += 'tls.crt_file='+'"'+$cert+'"'
$fluentbit_command += "-p"
$fluentbit_command += 'tls.key_file='+'"'+$key+'"'
$fluentbit_command += "-p"
$fluentbit_command += 'format='+'"'+$message_format+'"'

if (-Not ([string]::IsNullOrWhiteSpace($message_nest))) {
    $fluentbit_command += "-F"
    $fluentbit_command += "nest"
    $fluentbit_command += "-p"
    $fluentbit_command += "Operation=nest"
    $fluentbit_command += "-p"
    $fluentbit_command += "Nested_under=$message_nest"
    $fluentbit_command += "-p"
    $fluentbit_command += "WildCard='*'"
    $fluentbit_command += "-m"
    $fluentbit_command += "'*'"
}
if (-Not ([string]::IsNullOrWhiteSpace($message_module))) {
    $fluentbit_command += "-F"
    $fluentbit_command += "record_modifier"
    $fluentbit_command += "-p"
    $fluentbit_command += '"Record=module '+$message_module+'"'
    $fluentbit_command += "-m"
    $fluentbit_command += "'*'"
}
$fluentbit_command += "-f"
$fluentbit_command += "1"

$fluentbit_command -join ' '

###############################################################################
# done
Pop-Location
