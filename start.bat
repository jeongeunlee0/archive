@echo off
setlocal
cd /d "%~dp0"
chcp 65001 >nul
title Bootcamp Archive - local server
set "NODE=node"
if exist "runtime\node.exe" set "NODE=runtime\node.exe"
if "%NODE%"=="node" (
  where node >nul 2>nul
  if errorlevel 1 (
    echo  [!] Node.js not found. Copy the runtime folder back or install Node.js LTS.
    start "" "https://nodejs.org/ko"
    pause
    exit /b 1
  )
)
"%NODE%" server.js --open
echo.
pause