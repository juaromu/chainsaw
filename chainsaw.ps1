################################
### Script to execute F-Secure/Chainsaw - Identify Malicious activitie recorded in WinEvtLogs using Sigma Rules
### Aurora Networks Managed Services
### https://www.auroranetworks.net
### info@auroranetworks.net
################################
##########
# Chainsaw will be run against all event logs found in the default location
# Output converted to JSON and appended to active-responses.log
##########
$ErrorActionPreference = "SilentlyContinue"
# RUN CHAINSAW AND STORE CSVs in TMP folder
c:\"Program Files"\chainsaw\chainsaw.exe hunt  --csv $env:TMP\chainsaw_output --lateral-all --rules c:\"Program Files"\chainsaw\sigma_rules --mapping c:\"Program Files"\chainsaw\mapping_files\sigma-mapping.yml --col-width 2000 win_default
Get-ChildItem $env:TMP\chainsaw_output -Filter *.csv |
Foreach-Object {
    $count = 0
    $Chainsaw_Array = Get-Content $_.FullName | ConvertFrom-Csv
    Foreach ($item in $Chainsaw_Array) {
        echo $item | ConvertTo-Json -Compress | Out-File -width 2000 C:\"Program Files (x86)"\ossec-agent\active-response\active-responses.log -Append -Encoding ascii
    # Sleep 2 seconds every 5 runs
         if(++$count % 5 -eq 0) 
            {
                Start-Sleep -Seconds 2
            }
         }
}