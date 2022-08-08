# navigate to script directory
Push-Location (split-path $MyInvocation.MyCommand.Path)

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
}



Pop-Location
