# configure a windows host to forward auditbeat and winlogbeat logs
# to Malcolm (see https://github.com/idaholab/Malcolm/tree/master/scripts/beats)

$beatversion = "7.6.2"

################################################################################
# Uninstall-Beat
#
# - Remove previous traces of this beat
#
function Uninstall-Beat {
  param( [string]$beat )

  try {
    & "C:\\Program Files\\$beat\\uninstall-service-$beat.ps1"
  }
  catch {
  }
  remove-item "C:\\Program Files\\$beat" -Recurse -erroraction 'silentlycontinue';

}

################################################################################
# Download-Beat
#
# - Download $beat-$beatversion-windows-x86_64.zip from artifacts.elastic.co
# - Unzip to C:\Program Files\beat
# - Download sample config for $beat from idaholab/Malcolm to C:\Program Files\beat
#
function Download-Beat {
  param( [string]$beat )

  Invoke-WebRequest -Uri https://artifacts.elastic.co/downloads/beats/$beat/$beat-oss-$beatversion-windows-x86_64.zip -OutFile $beat-$beatversion-windows-x86_64.zip -UseBasicParsing
  Expand-Archive -LiteralPath $beat-$beatversion-windows-x86_64.zip -DestinationPath 'C:\\Program Files'
  Remove-Item $beat-$beatversion-windows-x86_64.zip
  Rename-Item "C:\\Program Files\\$beat-$beatversion-windows-x86_64" "C:\\Program Files\\$beat"
  ((Get-Content -path "C:\\Program Files\\$beat\\install-service-$beat.ps1" -Raw) -replace 'ProgramData','Program Files') | Set-Content -Path "C:\\Program Files\\$beat\\install-service-$beat.ps1"
  ((Get-Content -path "C:\\Program Files\\$beat\\install-service-$beat.ps1" -Raw) -replace ' -path','  --path') | Set-Content -Path "C:\\Program Files\\$beat\\install-service-$beat.ps1"

  Invoke-WebRequest -UseBasicParsing -OutFile "C:\\Program Files\\$beat\\$beat.yml" -Uri https://raw.githubusercontent.com/idaholab/Malcolm/master/scripts/beats/windows_vm_example/$beat.yml
  (Get-Content "C:\\Program Files\\$beat\\$beat.yml") | Set-Content "C:\\Program Files\\$beat\\$beat.yml"
}

################################################################################
# Connectivity boilerplate to add to the sample .yml files downloaded from
# idaholab/Malcolm
#
$beat_boilerplate = @'

#================================ General ======================================
fields_under_root: true

#================================ Outputs ======================================

#-------------------------- Elasticsearch output -------------------------------
output.elasticsearch:
  enabled: true
  hosts: ["${BEAT_ES_HOST}"]
  protocol: "${BEAT_ES_PROTOCOL}"
  username: "${BEAT_HTTP_USERNAME}"
  password: "${BEAT_HTTP_PASSWORD}"
  ssl.verification_mode: "${BEAT_ES_SSL_VERIFY}"

setup.template.enabled: true
setup.template.overwrite: false
setup.template.settings:
  index.number_of_shards: 1
  index.number_of_replicas: 0

#============================== Dashboards =====================================
setup.dashboards.enabled: "${BEAT_KIBANA_DASHBOARDS_ENABLED}"
setup.dashboards.directory: "${BEAT_KIBANA_DASHBOARDS_PATH}"

#============================== Kibana =====================================
setup.kibana:
  host: "${BEAT_KIBANA_HOST}"
  protocol: "${BEAT_KIBANA_PROTOCOL}"
  username: "${BEAT_HTTP_USERNAME}"
  password: "${BEAT_HTTP_PASSWORD}"
  ssl.verification_mode: "${BEAT_KIBANA_SSL_VERIFY}"

#================================ Logging ======================================
logging.metrics.enabled: false
'@

################################################################################
# Run-Beat-Command
#
# - Run C:\Program Files\$beat\$beat.exe with correct defaults for config paths
# - specify beat, command array and (optionally) stdin string
#
function Run-Beat-Command {
  param( [string]$beat, [array]$command, [string]$stdin)

  $exe = "C:\\Program Files\\$beat\\$beat.exe"
  $exe_config = '--path.home', "C:\\Program Files\\$beat", '--path.config', "C:\\Program Files\\$beat", '--path.data', "C:\\Program Files\\$beat", '--path.logs', "C:\\Program Files\\$beat\\logs", '-c', "C:\\Program Files\\$beat\\$beat.yml", '-E', "keystore.path='C:\\Program Files\\$beat\\$beat.keystore'"

  if (!$stdin) {
    & $exe $exe_config $command
  } else {
    $stdin.Trim() | & $exe $exe_config $command
  }

}

################################################################################
# Configure config .yml and keystore for beat in "C:\\Program Files\\$beat"
#
function Configure-Beat {
  param( [string]$beat )

  cd "C:\\Program Files\\$beat"

  Run-Beat-Command $beat @("keystore","create","--force") $null

  Add-Content -Path "C:\\Program Files\\$beat\\$beat.yml" -Value $beat_boilerplate

  do {
    $es_host = Read-Host "Specify the Elasticsearch IP:port (e.g., 192.168.0.123:9200)"
    $es_host = $es_host.Trim()
  } while (!$es_host)

  do {
    $kb_host = Read-Host "Specify the Kibana IP:port (e.g., 192.168.0.123:5601)"
    $kb_host = $kb_host.Trim()
  } while (!$kb_host)

  do {
    $es_user = Read-Host "Specify the Elasticsearch/Kibana username"
    $es_user = $es_user.Trim()
  } while (!$es_user)

  do {
      $es_pass = Read-Host "Specify the Elasticsearch/Kibana password" -AsSecureString
      $es_pass_confirm = Read-Host "Specify the Elasticsearch/Kibana password (again)" -AsSecureString
      $pwd1_text = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($es_pass))
      $pwd2_text = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($es_pass_confirm))
  } while ($pwd1_text -ne $pwd2_text)
  $es_pass = ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($es_pass))).Trim()

  Run-Beat-Command $beat @("keystore","add","BEAT_ES_PROTOCOL","--stdin","--force") "https"
  Run-Beat-Command $beat @("keystore","add","BEAT_KIBANA_PROTOCOL","--stdin","--force") "https"
  Run-Beat-Command $beat @("keystore","add","BEAT_ES_SSL_VERIFY","--stdin","--force") "none"
  Run-Beat-Command $beat @("keystore","add","BEAT_KIBANA_SSL_VERIFY","--stdin","--force") "none"
  Run-Beat-Command $beat @("keystore","add","BEAT_KIBANA_DASHBOARDS_ENABLED","--stdin","--force") "true"
  Run-Beat-Command $beat @("keystore","add","BEAT_KIBANA_DASHBOARDS_PATH","--stdin","--force") "C:\\Program Files\\$beat\\kibana"
  Run-Beat-Command $beat @("keystore","add","BEAT_ES_HOST","--stdin","--force") "$es_host"
  Run-Beat-Command $beat @("keystore","add","BEAT_KIBANA_HOST","--stdin","--force") "$kb_host"
  Run-Beat-Command $beat @("keystore","add","BEAT_HTTP_USERNAME","--stdin","--force") "$es_user"
  Run-Beat-Command $beat @("keystore","add","BEAT_HTTP_PASSWORD","--stdin","--force") "$es_pass"

  Run-Beat-Command $beat @("keystore","list") $null

  $confirmation = Read-Host "Install $beat as a system service (y/n)"
  if ($confirmation -eq 'y') {
    & "C:\\Program Files\\$beat\\install-service-$beat.ps1"
  }
}

################################################################################
# Main
#
function Main {
  param( [array]$beats)
  $tempdir = New-TemporaryFile
  remove-item $tempdir;
  new-item -type directory -path $tempdir;
  cd $tempdir;

  foreach ($beat in $beats) {
    cd $tempdir;

    Uninstall-Beat $beat
    Download-Beat $beat
    Configure-Beat $beat
  }

  cd $Env:Temp;
  remove-item $tempdir -Recurse;
}

################################################################################
#
if ($args.count -eq 0) {
  Main @("auditbeat","winlogbeat")
} else {
  Main $args
}
