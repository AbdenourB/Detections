#### Test Rule: https://github.com/elastic/detection-rules/blob/main/rules/windows/credential_access_bruteforce_multiple_logon_failure_followed_by_success.toml
```eql
sequence by winlog.computer_name, source.ip with maxspan=5s
  [authentication where event.action == "logon-failed" and
    winlog.logon.type : "Network" and user.id != null and 
    source.ip != null and source.ip != "127.0.0.1" and source.ip != "::1" and 
    not winlog.event_data.TargetUserSid : "S-1-0-0" and not user.id : "S-1-0-0" and 
    not user.name : ("ANONYMOUS LOGON", "-", "*$") and not user.domain == "NT AUTHORITY" and
    not winlog.event_data.Status : ("0xC000015B", "0XC000005E", "0XC0000133", "0XC0000192")] with runs=5
  [authentication where event.action == "logged-in" and
    winlog.logon.type : "Network" and
    source.ip != null and source.ip != "127.0.0.1" and source.ip != "::1" and
    not user.name : ("ANONYMOUS LOGON", "-", "*$") and not user.domain == "NT AUTHORITY"]
```

# EQL – Multiple Failed Logins Followed by Successful Login – Test using WinRM login

## Scenario 
I tested the Elastic EQL detection rule for **multiple failed logins followed by a successful login** using **WinRM** on a Windows 11 target.  
The goal was to see what fields actually get logged in the Security events and whether the rule works in practice.  

This is based entirely on **my own tests** — 

## Test Setup

- **Machines Tested:** Windows 11 endpoints (2 test machines)  
- **Protocol:** WinRM using NTLM V2  
- **Detection Rule Under Test:**
- **Source:** Windows Event Logs (Security logs)  
- **Accounts Used:** One standard user account  

I triggered several failed login attempts on the test account and then completed a successful login to see if the rule would pick up the pattern.

I used the following powershell script:

```
param (
    [string]$Target = "192.168.56.111",
    [string]$Username = "fadi",
    [string]$BadPassword = "WrongPassword",
    [string]$GoodPassword = "CorrectPassword"
)
# Function to attempt a WinRM login
function Invoke-WinRMLogin {
    param($ComputerName, $User, $Password)
    try {
        $sec = ConvertTo-SecureString $Password -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential($User, $sec)
        Enter-PSSession -ComputerName $ComputerName -Credential $cred -ErrorAction Stop
    } catch {
        Write-Host "Login failed for $User@$ComputerName with password '$Password'"
    }
}
# 5 failed attempts
for ($i = 1; $i -le 5; $i++) {
    Invoke-WinRMLogin -ComputerName $Target -User $Username -Password $BadPassword
    Start-Sleep -Milliseconds 500
}
# 1 successful attempt
Invoke-WinRMLogin -ComputerName $Target -User $Username -Password $GoodPassword
```
## Checking logs in the target machine

Using the following powershell script, i checked all 4625 events, in order to confirm the presence of the required logs
```
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 20 |
  ForEach-Object {
    $xml = [xml]$_.ToXml()
    $d = @{}
    foreach($n in $xml.Event.EventData.Data){ $d[$n.Name] = $n.'#text' }
    [PSCustomObject]@{
      Time = $_.TimeCreated
      TargetUser = $d['TargetUserName']
      LogonType = $d['LogonType']
      AuthPackage = $d['AuthenticationPackage']
      Workstation = $d['WorkstationName']
      IpAddress = $d['IpAddress']
      IpPort = $d['IpPort']
      Status = $d['Status']
    }
  } | Format-Table -AutoSize

```
the output was:

```
Time                TargetUser LogonType AuthPackage Workstation     IpAddress IpPort Status    
----                ---------- --------- ----------- -----------     --------- ------ ------    
9/5/2025 7:18:56 PM fadi       3                     DESKTOP-2FS2MEB -         -      0xc000006d
9/5/2025 7:18:56 PM fadi       3                     DESKTOP-2FS2MEB -         -      0xc000006d
9/5/2025 7:18:56 PM fadi       3                     DESKTOP-2FS2MEB -         -      0xc000006d
9/5/2025 7:18:56 PM fadi       3                     DESKTOP-2FS2MEB -         -      0xc000006d
9/5/2025 7:18:55 PM fadi       3                     DESKTOP-2FS2MEB -         -      
```

The results above shows the absense of a field used as a consition in the detection rule, which is : **source.ip**. This will make the rule miss important event because it cannot find the required fields. the same field is missing on the Event **4624**.

Checkig the event log, we can onserve that the source hostname does exist:
```
Network Information:
    Workstation Name:    DESKTOP-2FKK3EB
    Source Network Address:  -
    Source Port:         -
```

Using kibana timeline, with the abovementioned EQL rule, i was not able to trigger a result.

## Other observations:

Logon-failed **4625** always gives **user.id=S-1-0-0** and **winlog.event_data.TargetUserSid=S-1-0-0**, this will also prevent the rule from matching.
Those two values showd the correct values when the login is seccessful *Event 4624*

The below screenshot shows the above behavior:


```
Time                TargetUser LogonType AuthPackage Workstation     IpAddress IpPort Status     UserName UserId 
----                ---------- --------- ----------- -----------     --------- ------ ------     -------- ------ 
9/5/2025 9:16:49 PM fadi       3                     DESKTOP-2FS2MEB -         -      0xc000006d fadi     S-1-0-0
9/5/2025 9:16:49 PM fadi       3                     DESKTOP-2FS2MEB -         -      0xc000006d fadi     S-1-0-0
9/5/2025 9:16:48 PM fadi       3                     DESKTOP-2FS2MEB -         -      0xc000006d fadi     S-1-0-0
```
This is another condition that will not be met.

## Conclusion

A rule that can match the behavior is :
```
  sequence by winlog.computer_name with maxspan=5s
  [authentication where event.action == "logon-failed" and
    winlog.logon.type : "Network" and 
     source.ip != "127.0.0.1" and source.ip != "::1" and 
    not user.name : ("ANONYMOUS LOGON", "-", "*$") and not user.domain == "NT AUTHORITY" and
    not winlog.event_data.Status : ("0xC000015B", "0XC000005E", "0XC0000133", "0XC0000192")] with runs=5
  [authentication where event.action == "logged-in" and
    winlog.logon.type : "Network" and
     source.ip != "127.0.0.1" and source.ip != "::1" and
    not user.name : ("ANONYMOUS LOGON", "-", "*$") and not user.domain == "NT AUTHORITY"]
```

### I need to try this with another logon types, such as RDP, and see if we get the same behavior.

つづく ...
