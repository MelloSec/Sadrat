@echo off
setlocal

:: Define parameters
set "url=%1"
set "zipName=%2"
set "exeName=%3"

:: Download the file
curl.exe -L -o "%cd%\%zipName%" "%url%"

:: Extract the zip file
tar -xf "%cd%\%zipName%" -C "%cd%"

:: Remove the zip file
del "%cd%\%zipName%"

:: Start the executable
start "" "%cd%\%exeName%"

endlocal
