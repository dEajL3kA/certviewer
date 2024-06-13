@echo off
cd /d "%~dp0"

if "%PANDOC%"=="" (
	set "PANDOC=C:\Program Files\Pandoc\pandoc.exe"
)

if "%VS2019INSTALLDIR%"=="" (
	set "VS2019INSTALLDIR=C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional"
)

if not exist "%PANDOC%" (
	echo Error: PANDOC executable not found!
	goto:finished
)

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

for /F "tokens=* usebackq" %%i in (`start /B /WAIT "date" "%CD%\etc\utilities\unxutils\date.exe" "+%%Y-%%m-%%d"`) do (
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

"%CD%\etc\utilities\unxutils\grep.exe" -v "shields.io" "README.md" | "%PANDOC%" -f markdown -t html5 --metadata pagetitle="CertViewer" --embed-resources --standalone --css "etc\style\github-markdown.css" -o "out\target\README.html"

attrib +R "out\target\*.*"

set "ZIP_EXEFILE=%CD%\etc\utilities\info-zip\zip.exe"
set "ZIP_OUTFILE=%CD%\out\CertViewer.%BUILD_DATE%.zip"
pushd "out\target"
"%ZIP_EXEFILE%" -z -r -9 "%ZIP_OUTFILE%" *.* < "%CD%\LICENSE.txt"
popd

attrib +R "out\CertViewer.%BUILD_DATE%.zip"

echo.
echo Completed.
echo.

:finished
pause
