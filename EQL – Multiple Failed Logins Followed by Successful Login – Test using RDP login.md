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

# EQL – Multiple Failed Logins Followed by Successful Login – Test using RDP login

## Scenario 
I tested the Elastic EQL detection rule for **multiple failed logins followed by a successful login** using **RDP** login on a Windows 11 target.  
The goal was to see what fields actually get logged in the Security events and whether the rule works in practice.  

this test is related to the one found in the following file, which describes the behavior of remote access using **WinRM**
```
https://github.com/AbdenourB/Detections/blob/main/EQL%20%E2%80%93%20Multiple%20Failed%20Logins%20Followed%20by%20Successful%20Login%20%E2%80%93%20Test%20using%20WinRM%20login.md
```
This is based entirely on **my own tests** — 

## Test Setup

- **Machines Tested:** Windows 11 endpoints (2 test machines)  
- **Protocol:** RDP  
- **Detection Rule Under Test:**
- **Source:** Windows Event Logs (Security logs)  
- **Accounts Used:** One standard user account  

I triggered several failed login attempts on the test account and then completed a successful login to see if the rule would pick up the pattern.

I used hydra to test the RDP brute force scenario:

```
hydra -t 1 -V -f -l fadi -P text.txr rdp://192.168.56.111
```
the output was:

```
Time                 TargetUser LogonType AuthPackage Workstation     IpAddress    IpPort Status     TargetUserId
----                 ---------- --------- ----------- -----------     ---------    ------ ------     ------------
9/5/2025 11:26:16 PM fadi       3                     DESKTOP-2FS2MEB 192.168.56.1 0      0xc000006d S-1-0-0     
9/5/2025 11:26:15 PM fadi       3                     DESKTOP-2FS2MEB 192.168.56.1 0      0xc000006d S-1-0-0     
9/5/2025 11:26:14 PM fadi       3                     DESKTOP-2FS2MEB 192.168.56.1 0      0xc000006d S-1-0-0     
9/5/2025 11:26:13 PM fadi       3                     DESKTOP-2FS2MEB 192.168.56.1 0      0xc000006d S-1-0-0     
9/5/2025 11:26:12 PM fadi       3                     DESKTOP-2FS2MEB 192.168.56.1 0      0xc000006d S-1-0-0
```

Unlike the test with WinRM, we can see that **Events 4625 and 4624** contains the IP address of the source machine as well as the hostname.
Checkig the event log, we can onserve that the source hostname does exist:

```
Network Information:
	Workstation Name:	DESKTOP-2FS2MEB
	Source Network Address:	192.168.56.1
	Source Port:		0
```

## Other observations:

The same as in WinRM Logon-failed **4625** event, it gives **user.id=S-1-0-0** and **winlog.event_data.TargetUserSid=S-1-0-0**.

## Conclusion

A rule that can match the behavior is :
```
  sequence by winlog.computer_name, source.ip with maxspan=5s
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

### The above rule was able to trigger and alert in elastic security, but in order to be able to detect both behaviors, it is a good idea to remove the **source.ip** and aggregate result by hostname.
