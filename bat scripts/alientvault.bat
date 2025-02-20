@echo off
setlocal EnableDelayedExpansion

:: Jump to main so that function definitions below are skipped.
goto :main

:DownloadJq
echo jq is not installed. Attempting to download jq...
:: Determine system architecture reliably.
set "ARCH=%PROCESSOR_ARCHITECTURE%"
if "%ARCH%"=="" set "ARCH=AMD64"
if defined PROCESSOR_ARCHITEW6432 set "ARCH=%PROCESSOR_ARCHITEW6432%"
if /I "%ARCH%"=="AMD64" (
    set "jq_url=https://github.com/stedolan/jq/releases/download/jq-1.6/jq-win64.exe"
) else (
    set "jq_url=https://github.com/stedolan/jq/releases/download/jq-1.6/jq-win32.exe"
)
echo Downloading jq from %jq_url%...
curl -L -o jq.exe "%jq_url%"
if exist jq.exe (
    echo jq downloaded successfully.
    set "PATH=%CD%;%PATH%"
) else (
    echo Failed to download jq. Please install jq manually and rerun the script.
    pause
    exit /b 1
)
exit /b

:main
:: ============================================================
:: Check for curl; if missing, print error and exit.
:: ============================================================
where curl >nul 2>&1
if errorlevel 1 (
    echo curl is not installed. Please install curl and rerun the script.
    pause
    exit /b 1
) else (
    echo curl is installed.
)

:: ============================================================
:: Check for jq; if missing, call the function to download it.
:: ============================================================
where jq >nul 2>&1
if errorlevel 1 (
    call :DownloadJq
) else (
    echo jq is installed.
)

echo.
:: ============================================================
:: Prompt for the domain.
:: ============================================================
set /p domain="Enter the domain (e.g., example.com): "

:: Set initial pagination parameters.
set page=1
set limit=500

echo.
echo Fetching URLs from AlienVault OTX for domain: %domain%

:fetch_loop
echo.
echo Fetching page %page%...
curl -s "https://otx.alienvault.com/api/v1/indicators/hostname/%domain%/url_list?limit=%limit%&page=%page%" -o response.json

:: Check if response.json is valid.
for /f "usebackq delims=" %%a in (`findstr /r /c:"url_list" response.json`) do set dummy=%%a
if not defined dummy (
    echo No valid response received. Exiting.
    goto end_script
)

:: Extract and display URLs using jq.
for /f "delims=" %%u in ('jq -r ".url_list[]?.url" response.json') do (
    echo %%u
)

:: Count the number of URLs returned.
for /f "delims=" %%c in ('jq -r ".url_list | length" response.json') do (
    set count=%%c
)
echo Found !count! URL(s) on page %page%.

if !count! LSS %limit% (
    echo Reached the last page.
    goto end_script
)

set /a page=%page%+1
goto fetch_loop

:end_script
echo.
echo Done fetching URLs.
del response.json
pause
