Update--

         I created a quicker scan that targets key folders directly instead of a general scan accross many folders that shouldnt have IOCs in them. 

         The new files are "SolarWindsIOC-Quick-local.bat" (for no config and local logs) and "SolarWindsIOC-Quick-CONFIG MAILER.bat" (for a configurable emailing of logs)
         
         I also updated the yara rules that are used as FireEye updated theirs. 
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Download the file called "SolarWindsIOC-CONFIG MAILER.bat".

You will need to configure the script to use your existing mail server (or an isp/smarthost in your service area).

Instructions and how this works are in "SolarWinds Breach and Detection" document. 

The "SolarWindsIOC-local.bat" script will require no configuration.  Just run it as admin and it will show results in temp folder when done.

Stay tuned for updates and changes.  
