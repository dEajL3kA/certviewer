@echo off
cd /d "%~dp0"

set "PANDOC=C:\Program Files\Pandoc\pandoc.exe"
set "INFO_ZIP=%CD%\etc\utilities\win32\zip.exe"

if not exist "%VS2019INSTALLDIR%\Common7\Tools\VsDevCmd.bat" (
	echo Error: VS2019INSTALLDIR not found!
	goto:finished
)

call "%VS2019INSTALLDIR%\Common7\Tools\VsDevCmd.bat" -no_logo

echo ------------------------------------------------------------------------------
echo Clean up...
echo ------------------------------------------------------------------------------

for %%d in (bin obj out packages) do (
	echo %%~d
	if exist %%~d\. rmdir /S /Q %%~d
)

for /F "tokens=* usebackq" %%i in (`start /B /WAIT "date" "%CD%\etc\utilities\win32\date.exe" "+%%Y-%%m-%%d"`) do (
	set "BUILD_DATE=%%~i"
)

echo ------------------------------------------------------------------------------
echo Build application...
echo ------------------------------------------------------------------------------

MSBuild /t:Restore /p:Configuration=Release /p:Platform="Any CPU" "%CD%\CertViewer.sln"
if %ERRORLEVEL% neq 0 goto:finished

MSBuild /t:Rebuild /p:Configuration=Release /p:Platform="Any CPU" /p:EnableCosturaFody="true" "%CD%\CertViewer.sln"
if %ERRORLEVEL% neq 0 goto:finished

echo ------------------------------------------------------------------------------
echo Create bundles...
echo ------------------------------------------------------------------------------

mkdir "out\target"

copy /B "bin\Release\CertViewer.exe*" "out\target"
copy /B "LICENSE.txt" "out\target"

"%PANDOC%" -f markdown -t html5 --metadata pagetitle="CertViewer" --embed-resources --standalone --css "etc\style\github-markdown.css" -o "out\target\README.html" "README.md"
"%CD%\etc\utilities\win32\minifier.exe" "out\target\README.html"

attrib +R "out\target\*.*"

set "ZIP_OUTFILE=%CD%\out\CertViewer.%BUILD_DATE%.zip"
pushd "out\target"
"%INFO_ZIP%" -z -r -9 "%ZIP_OUTFILE%" *.* < "%CD%\LICENSE.txt"
popd

attrib +R "out\CertViewer.%BUILD_DATE%.zip"

echo.
echo Completed.
echo.

:finished
pause
