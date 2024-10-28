<p align="center">
    <img src="https://github.com/SentinelSamuel/Rename-Computer-Tool/blob/main/Pictures/SentinelOne.png" alt="drawing" style="width:400px;">
</p>

<div align="center">
    <h1>
        Rename-Computer-Tool
    </h1>
</div>


<p align="center">
         This script allows you to rename a computer and even a DC<br/>
</p>

<div align="center">
    <a href="https://fr.sentinelone.com/"><img src="https://img.shields.io/badge/Website-SentinelOne-6100FF?labelColor=FFFFFF&style=flat&link=https://fr.sentinelone.com/" alt="Website" /></a>
</div>

### 1) To launch the tool
```
If the machine is already in a domain, his DC has to be up so the computer can call his DC for a double-check
Then, launch the 'launch.ps1'

Tips :
 - You can create a .lnk to the launch.ps1 to make it easier to launch

 - You can change the default application used on a double click of a .ps1 to allow users to launch a .ps1 just double-clicking on it

 - You can create a Task in the task scheduler that will be run with highest priviledges and will be launched every logon

 - You can add a key : 
    The keys:
        HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run - Runs programs for all users.
        HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run - Runs programs for current user.
```
source : https://stackoverflow.com/questions/24250303/additional-ways-of-running-programs-at-logon
<br/><br/>
For the task scheduler part : 
![image](https://github.com/SentinelSamuel/Rename-Computer-Tool/blob/main/Pictures/TaskScheduler-1.png)
![image](https://github.com/SentinelSamuel/Rename-Computer-Tool/blob/main/Pictures/TaskScheduler-2.png)
![image](https://github.com/SentinelSamuel/Rename-Computer-Tool/blob/main/Pictures/TaskScheduler-3.png)
```
The full script that is used here is (to have logs visibility) :
Action : Start a Program
Program/Script : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Add Arguments (optional) : -ExecutionPolicy Bypass -File C:\Rename-Computer-Tool\Rename-DC-Tool.ps1 -WindowStyle Hidden

The full script that is used here is (to NOT HAVE logs visibility) :
Action : Start a Program
Program/Script : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Add Arguments (optional) : -ExecutionPolicy Bypass -File C:\Rename-Computer-Tool\launch.ps1 -WindowStyle Hidden
(Do not forget to rename the script name in the launch.ps1 script if you rename a DC)
```
![image](https://github.com/SentinelSamuel/Rename-Computer-Tool/blob/main/Pictures/TaskScheduler-4.png)
![image](https://github.com/SentinelSamuel/Rename-Computer-Tool/blob/main/Pictures/TaskScheduler-5.png)
![image](https://github.com/SentinelSamuel/Rename-Computer-Tool/blob/main/Pictures/TaskScheduler-6.png)
<br/>

### 2) Screenshots of the UI 

![image](https://github.com/SentinelSamuel/Rename-Computer-Tool/blob/main/Pictures/PowerShell-App.png)
![image](https://github.com/SentinelSamuel/Rename-Computer-Tool/blob/main/Pictures/LaunchedInALab.png)

### 3) Some Tips
```
- The maximum caracters of a computer name is 15
- You cannot add sapces in the computer name
- There is a file created during the process, named C:\old_computername.txt that will contains the old computer name and that allows you to not launch the script at every restarts of the computer
- So if you delete C:\old_computername.txt, the script launch the pop-up again
- The script is in Always On Top mod (it means that no Windows can go on the top of it so you are sure that you see it when it pops up)
- For Rename-DC-Tool : 
  - It uses a totally diffrent process, it uses DC-Modules.psm1 which is a PowerShell function file that will contain every functions used in the script
  - It rename (if possible) every present SPNs in the DC with the new name
  - It rename every DNS entries that were containing the old computer name pointing on the DC
  - It remove every certificates that contains the old computer name in the subject
  - It reset WinRM configuration (even if there is still a WinRM over HTTPS configured)
  - It configure WinRM over HTTPS (creating a certificate that is placed in the script directory with its password file)
  - It disable WinRM over HTTP (It try 3 times before saying that it didn't work)
  - It disable LDAP
  - It enable LDAPS (creating a certificate that is placed in the script directory with its password file)
  - It creates Firewall Rules for WinRM over HTTPS & LDAPS
  - It removes Firewall Rules for the disabling of LDAP
  - After hitting the OK button, everything is logged in the script directory "Rename-DC.log"
```

### 4) On error
If you got an error from the Rename-DnsForNewComputerName function, it could not be a problem (it search for every DNS entries so it can be wrong and try to rename something that doesnt exist)

