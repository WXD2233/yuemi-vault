@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"

if not exist "node_modules\.bin\vinext.cmd" (
  echo Project dependencies are not installed.
  echo Running the one-click installer first...
  call "%~dp0install.cmd"
  if errorlevel 1 exit /b %ERRORLEVEL%
)

echo.
echo Starting Yuemi Vault...
echo Keep this window open while using the application.
echo Open the Local URL printed below in your browser.
echo.

call npm.cmd run dev
set "START_EXIT_CODE=%ERRORLEVEL%"

if not "%START_EXIT_CODE%"=="0" (
  echo.
  echo Yuemi Vault stopped with an error.
  pause
)

exit /b %START_EXIT_CODE%
