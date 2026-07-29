@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"

echo.
echo ========================================
echo   Yuemi Vault - One-click installation
echo ========================================
echo.

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
set "INSTALL_EXIT_CODE=%ERRORLEVEL%"

echo.
if not "%INSTALL_EXIT_CODE%"=="0" (
  echo Installation failed. Review the message above and try again.
  echo.
  pause
  exit /b %INSTALL_EXIT_CODE%
)

echo Installation completed successfully.
echo Double-click start.cmd to run Yuemi Vault.
echo.
pause
exit /b 0
