@echo off
cd /d "%~dp0"
if exist "%~dp0desktop\releases\3.2.1\VULN\VULN.exe" (
  start "" "%~dp0desktop\releases\3.2.1\VULN\VULN.exe"
  exit /b 0
)
if not exist "%~dp0desktop\dist-vuln\vuln.jar" (
  echo Execute desktop\build.ps1 primeiro.
  pause
  exit /b 1
)
start "" "%~dp0..\.tools\jdk\bin\javaw.exe" --add-modules jdk.httpserver -Djava.io.tmpdir="%~dp0work" -jar "%~dp0desktop\dist-vuln\vuln.jar"
