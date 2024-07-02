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
source![https://stackoverflow.com/questions/24250303/additional-ways-of-running-programs-at-logon]

### 2) The initial source code of the exe is the .ps1 file 

![image](https://github.com/SentinelSamuel/Rename-Computer-Tool/assets/114468569/58edc875-20bc-491a-8ee9-a2baa7ddaf4d)

### 3) On error

On error you have to remind that : 
```
- The maximum caracters of a computer name is 15
- There is a file created during the process, named old_computername.txt that will go on C:\old_computername.txt
 and will contain the old computer name, IF YOU REMOVE IT, YOU CAN RESTART THE SCRIPT
```
