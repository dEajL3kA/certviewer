@echo off
cd /d "%~dp0"

set "MVS_PATH=C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional"
set "PANDOC=C:\Program Files\Pandoc\pandoc.exe"
set "INFO_ZIP=%CD%\etc\utilities\win32\zip.exe"

echo ----------------------------------------------------------------
echo Clean up...
echo ----------------------------------------------------------------

for %%d in (packages src\bin src\obj out) do (
	echo %%~d
	if exist %%~d\. rmdir /S /Q %%~d
)

for /F "tokens=* usebackq" %%i in (`start /B /WAIT "date" "%CD%\etc\utilities\win32\date.exe" "+%%Y-%%m-%%d"`) do (
	set "BUILD_DATE=%%~i"
)

echo ----------------------------------------------------------------
echo Build application...
echo ----------------------------------------------------------------

call "%MVS_PATH%\Common7\Tools\VsMSBuildCmd.bat"

MSBuild /t:Restore "%CD%\CertViewer.sln"
MSBuild /t:Rebuild /p:Configuration=Release /p:Platform="Any CPU" "%CD%\CertViewer.sln"

echo ----------------------------------------------------------------
echo Create bundles...
echo ----------------------------------------------------------------

mkdir "out"
mkdir "out\target"

copy /B "src\bin\Release\CertViewer.exe" "out\target"
copy /B "src\bin\Release\CertViewer.exe.config" "out\target"
copy /B "src\bin\Release\BouncyCastle.Crypto.dll" "out\target"
copy /B "LICENSE.txt" "out\target"

"%PANDOC%" -f markdown -t html5 --metadata title="CertViewer" --embed-resources -o "out\target\README.html" "README.md"
attrib +R "out\target\*.*"

set "OUTFILE=%CD%\out\CertViewer.%BUILD_DATE%.zip"
pushd "out\target"
"%INFO_ZIP%" -r -9 "%OUTFILE%" *.*
popd
attrib +R "%OUTFILE%"

echo.
echo Completed.
echo.

pause
