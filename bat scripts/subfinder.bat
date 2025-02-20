@echo off
setlocal EnableDelayedExpansion

echo ===============================
echo   ADVANCED SUBDOMAIN ENUMERATOR
echo ===============================
set /p domain="Enter the domain (e.g., example.com): "
echo.

:: -- Check dependencies --
where curl >nul 2>&1
if errorlevel 1 (
    echo [ERROR] curl is not installed. Please install curl and try again.
    pause
    exit /b 1
)

where jq >nul 2>&1
if errorlevel 1 (
    call :DownloadJq
)

:: -- Fetch subdomains from crt.sh --
echo [*] Fetching subdomains from crt.sh...
curl -s "https://crt.sh/?q=%domain%&output=json" -o crt_subs.json
if not exist crt_subs.json (
    echo [ERROR] Failed to retrieve data from crt.sh.
    pause
    exit /b 1
)
:: Extract subdomains and sort uniquely (using Windows sort /unique)
jq -r ".[].name_value" crt_subs.json | sort /unique > subdomains_crt.txt

:: -- Fetch subdomains from ThreatCrowd --
echo [*] Fetching subdomains from ThreatCrowd...
curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%domain%" -o tc_subs.json
if exist tc_subs.json (
    jq -r ".subdomains[]" tc_subs.json | sort /unique > subdomains_tc.txt
) else (
    echo [WARNING] ThreatCrowd data not available.
)

:: -- Combine and deduplicate --
echo [*] Combining results...
type nul > combined_subdomains.txt
if exist subdomains_crt.txt (
    type subdomains_crt.txt >> combined_subdomains.txt
)
if exist subdomains_tc.txt (
    type subdomains_tc.txt >> combined_subdomains.txt
)

sort /unique combined_subdomains.txt > final_subdomains.txt

echo.
echo [*] Unique subdomains found:
type final_subdomains.txt
echo.
echo Results saved in final_subdomains.txt

:: -- Clean up temporary files --
del crt_subs.json 2>nul
del tc_subs.json 2>nul
del subdomains_crt.txt 2>nul
del subdomains_tc.txt 2>nul
del combined_subdomains.txt 2>nul

pause
exit /b

:DownloadJq
    echo [*] jq not found. Downloading jq...
    set "ARCH=%PROCESSOR_ARCHITECTURE%"
    if defined PROCESSOR_ARCHITEW6432 set "ARCH=%PROCESSOR_ARCHITEW6432%"
    if /I "%ARCH%"=="AMD64" (
        set "jq_url=https://github.com/stedolan/jq/releases/download/jq-1.6/jq-win64.exe"
    ) else (
        set "jq_url=https://github.com/stedolan/jq/releases/download/jq-1.6/jq-win32.exe"
    )
    echo [*] Downloading jq from %jq_url%...
    curl -L -o jq.exe "%jq_url%"
    if exist jq.exe (
        echo [*] jq downloaded successfully.
        set "PATH=%CD%;%PATH%"
    ) else (
        echo [ERROR] Failed to download jq. Please install jq manually.
        pause
        exit /b 1
    )
exit /b
