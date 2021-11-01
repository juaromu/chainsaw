**USING WAZUH AND CHAINSAW FOR WINDOWS EVT LOGS FORENSIC ANALYSIS**
## 

## Intro

Wazuh and [Chainsaw](https://github.com/countercept/chainsaw) integration to run forensic analysis.

From Chainsaw’s Github page: Chainsaw provides a powerful ‘first-response’ capability to quickly identify threats within Windows event logs. It offers a generic and fast method of searching through event logs for keywords, and by identifying threats using built-in detection logic and via support for Sigma detection rules.

Chainsaw is a free tool developed by [F-Secure](https://www.f-secure.com/en).

Some use cases:



* After deploying Wazuh in your environment, you can use Chainsaw to collect past artifacts still present in the WinEvtLogs and take Chainsaw’s output to the Wazuh manager for centralised analysis and triage of past events that might still require attention. This centralised collection of artifacts provides a valuable insight of past security events that might have been missed, since there was no EDR tool in place. It can also help to identify persistent footholds.
* Apply DFIR at any given time. By using Wazuh’s wodle commands capability all artifacts in WinEvtLogs can be taken to the manager for analysis.


## Chainsaw - Overview

Chainsaw can be used in search or hunt modes. When run in search mode, parameters such as event IDs or even regex can be used as input. In this integration though chainsaw will be used in hunt mode.

In hunt mode, chainsaw can be executed with built-in capabilities only (see Github page for details) but where it really shines is when Sigma rules are added to the WinEvtLogs analysis, along with lateral movement analysis.

The following subsections cover the metadata collected for each category.


### Windows Defender



* system_time
* id
* computer
* threat_name
* threat_file
* user


### Suspicious Process Creation



* System_time,
* Id,
* Detection_rules,
* Computer_name,
* Event.EventData.Image,
* command_line


### Suspicious command line



* System_time,
* Id,
* Detection_rules,
* Computer_name,
* Event.EventData.CommandLine,
* process_name


### Suspicious File Creation



* System_time,
* Id,
* Detection_rules,
* Computer_name,
* Event.EventData.TargetFilename,
* image


### Suspicious Registry Event



* System_time,
* Id,
* Detection_rules,
* Computer_name,
* Event.EventData.Details,
* target_object


### Suspicious Image Load



* System_time,
* Id,
* Detection_rules,
* Computer_name,
* Event.EventData.Image,
* image_loaded


### RDP Logins



* System_time,
* Id,
* Workstation_name,
* Target_username,
* Source_ip,
* logon_type


### User added to “interesting” group



* System_time,
* Id,
* Computer,
* Change_type,
* User_sid,
* target_group


### New user added to the system



* System_time,
* Id,
* Computer,
* Target_username,
* user_sid


### Security Audit Log was cleared



* System_time,
* Id,
* Computer,
* subject_user


### System Log was cleared



* System_time,
* Id,
* Computer,
* subject_user


## Workflow



1. Whatever the execution approach (locally in a single machine or in several machines, triggered in all windows machines via wodle command, etc.) the powershell script (see below) will execute chainsaw, will output to CSV files, will convert these CSVs to JSON that’ll be appended to the active responses log file.
2. While looping thru, a flow control (sleep timer) will prevent filling up the agent’s queue.
3. Detection rules in the Wazuh Manager will generate alerts accordingly.

NOTE: There’s an [issue](https://github.com/countercept/chainsaw/issues/35) in Chainsaw’s CSV file generation where columns with “\r” cause a break in that line/row and get splitted in 2 different lines.

The folder “c:\Program Files” is used to store the chainsaw folder with the executable and all the sigma rules. Change folder location and settings in the powershell script as per your requirement.

Chainsaw powershell script execution:


```
powershell.exe  -ExecutionPolicy Bypass -File "C:\Program Files\chainsaw\chainsaw.ps1"
```


Content of file “chainsaw.ps1”:


```
################################
### Script to execute F-Secure/Chainsaw - Identify Malicious activities recorded in WinEvtLogs using Sigma Rules
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
```


Chainsaw can also be regularly executed, triggered by a wodle command config on Wazuh manager.

Based on Chainsaw categories mentioned earlier, we can now build Wazuh’s detection rules.

Detection Rules:


```
<!-- Chainsaw Tool - Detection Rules -->
<group name="windows,chainsaw,">
<!-- Windows Defender -->
 <rule id="200001" level="10">
    <field name="system_time">\.+</field>
    <field name="threat_name">\.+</field>
    <field name="threat_file">\.+</field>
    <description>Chainsaw Forensics - Windows Defender</description>
    <options>no_full_log</options>
    <group>windows_defender_forensics,</group>
  </rule>
<!-- Process Creation -->
 <rule id="200002" level="10">
   <field name="system_time">\.+</field>
   <field name="detection_rules">\.+</field>
   <field name="command_line">\.+</field>
   <description>Chainsaw Forensics - Process Creation</description>
   <options>no_full_log</options>
   <group>process_creation_forensics,</group>
 </rule>
<!-- Command Line -->
 <rule id="200003" level="10">
   <field name="system_time">\.+</field>
   <field name="detection_rules">\.+</field>
   <field name="process_name">\.+</field>
   <description>Chainsaw Forensics - Command Line</description>
   <options>no_full_log</options>
   <group>command_line_forensics,</group>
 </rule>
<!-- File Creation -->
 <rule id="200004" level="10">
   <field name="system_time">\.+</field>
   <field name="detection_rules">\.+</field>
   <field name="image">\.+</field>
   <description>Chainsaw Forensics - File Creation</description>
   <options>no_full_log</options>
   <group>file_creation_forensics,</group>
 </rule>
<!-- Registry Event -->
 <rule id="200005" level="10">
   <field name="system_time">\.+</field>
   <field name="detection_rules">\.+</field>
   <field name="target_object">\.+</field>
   <description>Chainsaw Forensics - Registry Event</description>
   <options>no_full_log</options>
   <group>registry_event_forensics,</group>
 </rule>
<!-- Image Loaded -->
 <rule id="200006" level="10">
  <field name="system_time">\.+</field>
  <field name="detection_rules">\.+</field>
  <field name="image_loaded">\.+</field>
  <description>Chainsaw Forensics - Image Loaded</description>
  <options>no_full_log</options>
  <group>image_loaded_forensics,</group>
 </rule>
 <rule id="200007" level="10">
  <field name="system_time">\.+</field>
  <field name="target_username">\.+</field>
  <field name="logon_type">\.+</field>
  <description>Chainsaw Forensics - RDP Logins</description>
  <options>no_full_log</options>
  <group>rdp_logins_forensics,</group>
 </rule>
<!-- User added to Group -->
 <rule id="200008" level="10">
  <field name="system_time">\.+</field>
  <field name="user_sid">\.+</field>
  <field name="target_group">\.+</field>
  <description>Chainsaw Forensics - User Added to Group</description>
  <options>no_full_log</options>
  <group>user_group_forensics,</group>
 </rule>
<!-- User added to System -->
 <rule id="200009" level="10">
  <field name="system_time">\.+</field>
  <field name="target_username">\.+</field>
  <field name="user_sid">\.+</field>
  <description>Chainsaw Forensics - User Added to the System</description>
  <options>no_full_log</options>
  <group>user_system_forensics,</group>
 </rule>
<!-- Event Log Cleared -->
 <rule id="200010" level="10">
  <field name="system_time">\.+</field>
  <field name="subject_user">\.+</field>
  <description>Chainsaw Forensics - Event Log Cleared</description>
  <options>no_full_log</options>
  <group>event_log_forensics,</group>
 </rule>
</group>
```


Each category is mapped to a different rule group, and all of them grouped under [windows,chainsaw].

As mentioned earlier, and due to a bug in the existing release of chainsaw, CSV files are not gerenared properly and events in some categories aren’t properly parsed.
