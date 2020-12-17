:: Many thanks to Fireye for thier yara rules, Virus total for their yara64.exe, and all the analyst involved!  we thank you!! 
:: This tool is made by Stetson Cybergroup www.stetsoncg.com 

@ Echo OFF

color 0A

for /f "delims=: tokens=*" %%A in ('findstr /b ::::::::::: "%~f0"') do @echo(%%A

powershell "md -Force c:\SolarWindsIOC-%computername%\ | Out-Null"
powershell "md -Force c:\temp\ | Out-Null"

cd c:\SolarWindsIOC-%computername%\
echo.
echo Downloading the tools we need..
powershell -Command Invoke-WebRequest https://raw.githubusercontent.com/JoeW-SCG/SolarWindsIOCScanner/main/SolarWinds.yar -OutFile SolarWinds.yar
powershell -Command Invoke-WebRequest "https://github.com/VirusTotal/yara/releases/download/v4.0.2/yara-v4.0.2-1347-win64.zip" -OutFile yara64.zip
echo. unzipping...
powershell -Command Expand-Archive yara64.zip -Force

echo. Testing computer for SolarWinds IOC's

Powershell -Command "Get-ChildItem -Recurse -filter *.* 'C:\Windows\system32\' 2> $null | ForEach-Object { Write-Host -foregroundcolor "green" "Scanning" $_.FullName $_.Name; ./yara64/yara64.exe -d filename=$_.Name SolarWinds.yar $_.FullName 2> $null >>Warnings.txt}"
Powershell -Command "Get-ChildItem -Recurse -filter *.* 'C:\Windows\syswow64\' 2> $null | ForEach-Object { Write-Host -foregroundcolor "green" "Scanning" $_.FullName $_.Name; ./yara64/yara64.exe -d filename=$_.Name SolarWinds.yar $_.FullName 2> $null >>Warnings.txt}"
Powershell -Command "Get-ChildItem -Recurse -filter *.* 'C:\Program Files\SolarWinds*\' 2> $null | ForEach-Object { Write-Host -foregroundcolor "green" "Scanning" $_.FullName $_.Name; ./yara64/yara64.exe -d filename=$_.Name SolarWinds.yar $_.FullName 2> $null >>Warnings.txt}"
Powershell -Command "Get-ChildItem -Recurse -filter *.* 'C:\ProgramData\SolarWinds*\' 2> $null | ForEach-Object { Write-Host -foregroundcolor "green" "Scanning" $_.FullName $_.Name; ./yara64/yara64.exe -d filename=$_.Name SolarWinds.yar $_.FullName 2> $null >>Warnings.txt}"
Powershell -Command "Get-ChildItem -Recurse -filter *.* 'C:\Program Files (x86)\SolarWinds*\' 2> $null | ForEach-Object { Write-Host -foregroundcolor "green" "Scanning" $_.FullName $_.Name; ./yara64/yara64.exe -d filename=$_.Name SolarWinds.yar $_.FullName 2> $null >>Warnings.txt}"

echo. Testing to see if there are warnings..
setlocal
set file=Warnings.txt
set maxbytesize=10

call :setsize %file%

:testwarnings
if %size% lss %maxbytesize% (
 goto :cleanup
) else (
    echo. Saving logs to temp folder and opening... 
COPY "Warnings.txt" "c:\temp\SWIOC-%COMPUTERNAME%-Warnings.txt"
echo.
echo. Results saved in "c:\temp\SWIOC-%COMPUTERNAME%-Warnings.txt"

timeout 5
goto :cleanup
)
:setsize
set size=%~z1
goto :testwarnings

:cleanup
cd c:\temp\
timeout 5
RD /S /Q c:\SolarWindsIOC-%computername%\

exit







:::::::::::
:::::::::::   _____       __          _       ___           __                
:::::::::::  / ___/____  / /___ _____| |     / (_)___  ____/ /____            
:::::::::::  \__ \/ __ \/ / __ `/ ___/ | /| / / / __ \/ __  / ___/            
::::::::::: ___/ / /_/ / / /_/ / /   | |/ |/ / / / / / /_/ (__  )             
:::::::::::/____/\____/_/\__,_/_/_   |__/|__/_/_/_/_/\__,_/____/ __           
:::::::::::   / ____/  ______  / /___  (_) /_   /_  __/__  _____/ /____  _____
:::::::::::  / __/ | |/_/ __ \/ / __ \/ / __/    / / / _ \/ ___/ __/ _ \/ ___/
::::::::::: / /____>  </ /_/ / / /_/ / / /_     / / /  __(__  ) /_/  __/ /    
:::::::::::/_____/_/|_/ .___/_/\____/_/\__/    /_/  \___/____/\__/\___/_/         
:::::::::::          /_/                                                      
:::::::::::