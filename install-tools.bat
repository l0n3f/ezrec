@echo off
setlocal enabledelayedexpansion

echo.
echo ================================================================
echo                   ezrec Tool Installation
echo ================================================================
echo.
echo 🔧 Installing required tools for ezrec...

REM Check if Go is installed
echo 📋 Checking Go installation...
go version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Go is not installed. Please install Go first:
    echo    Download from: https://golang.org/dl/
    echo    Choose the Windows installer ^(.msi^) for your architecture
    echo.
    pause
    exit /b 1
) else (
    for /f "tokens=3" %%i in ('go version') do set GO_VERSION=%%i
    echo ✅ Found Go version: !GO_VERSION!
)

REM Function to install a tool
:install_tool
set tool_name=%1
set tool_url=%2
echo 🔧 Installing %tool_name%...
go install -v %tool_url% >nul 2>&1
if %errorlevel% equ 0 (
    echo ✅ %tool_name% installed successfully
) else (
    echo ❌ Failed to install %tool_name%
    set /a failed_count+=1
)
goto :eof

set failed_count=0

echo.
echo 📦 Installing ProjectDiscovery tools...
call :install_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
call :install_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx@latest"  
call :install_tool "katana" "github.com/projectdiscovery/katana/cmd/katana@latest"
call :install_tool "nuclei" "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
call :install_tool "dnsx" "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"

echo.
echo 📦 Installing other reconnaissance tools...
call :install_tool "amass" "github.com/OWASP/Amass/v4/...@master"
call :install_tool "gau" "github.com/lc/gau/v2/cmd/gau@latest"
call :install_tool "waybackurls" "github.com/tomnomnom/waybackurls@latest"
call :install_tool "ffuf" "github.com/ffuf/ffuf@latest"

echo.
echo 📋 Verifying tool installations...
set tools=subfinder httpx katana nuclei amass gau waybackurls ffuf
set available_count=0
set total_count=0

for %%t in (%tools%) do (
    set /a total_count+=1
    where %%t >nul 2>&1
    if !errorlevel! equ 0 (
        echo ✅ %%t is available
        set /a available_count+=1
    ) else (
        echo ⚠️ %%t is not available in PATH
    )
)

echo.
if !available_count! equ !total_count! (
    echo 🎉 All tools installed successfully!
) else (
    echo ⚠️ !available_count!/!total_count! tools are available in PATH
    echo Some tools may not be accessible. Check your Go installation and PATH.
)

echo.
echo ================================================================
echo                    Installation Summary
echo ================================================================
echo 📋 Installed tools:
echo   • subfinder - Subdomain enumeration
echo   • amass - Subdomain enumeration  
echo   • httpx - HTTP probing
echo   • katana - Web crawling
echo   • gau - Historical URL discovery
echo   • waybackurls - Wayback Machine URLs
echo   • nuclei - Vulnerability scanning
echo   • ffuf - Fuzzing
echo   • dnsx - DNS toolkit
echo.
echo 🚀 Next steps:
echo   1. Restart your command prompt to refresh PATH
echo   2. Run 'ezrec --help' to get started
echo   3. Try 'ezrec recon --domain example.com --subdomains --httpx'
echo.
echo 🔧 If you encounter issues:
echo   - Verify Go is in PATH: go version
echo   - Check tools: where subfinder
echo   - Go binaries location: echo %%GOPATH%%\bin or %%USERPROFILE%%\go\bin
echo.
echo ✅ Installation completed! You're ready to use ezrec!
echo.
pause