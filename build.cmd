@echo off
cd /d "%~dp0"

set MSBUILD_PATH=

for /f "usebackq delims=" %%i in (`etc\utilities\vswhere\vswhere.exe -latest -requires Microsoft.Component.MSBuild Microsoft.Net.Component.4.7.2.TargetingPack Microsoft.Net.ComponentGroup.DevelopmentPrerequisites -find MSBuild\**\Bin\MSBuild.exe`) do (
	set "MSBUILD_PATH=%%~fi"
	set "PATH=%%~dpi;%PATH%"
)

if not exist "%MSBUILD_PATH%" (
	echo Visual Studio with .NET Framework 4.7.2 component not found !!!
	pause && goto:eof
)

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

"%MSBUILD_PATH%" /t:Restore /p:Configuration=Release /p:Platform="Any CPU" "%CD%\CertViewer.sln"
if %ERRORLEVEL% neq 0 goto:finished

"%MSBUILD_PATH%" /t:Rebuild /p:Configuration=Release /p:Platform="Any CPU" /p:EnableCosturaFody="true" "%CD%\CertViewer.sln"
if %ERRORLEVEL% neq 0 goto:finished

echo ------------------------------------------------------------------------------
echo Create bundles...
echo ------------------------------------------------------------------------------

mkdir "out\target"

copy /B "bin\Release\CertViewer.exe*" "out\target"
copy /B "LICENSE.txt" "out\target"

"%CD%\etc\utilities\unxutils\grep.exe" -v "shields.io" "README.md" | "%CD%\etc\utilities\pandoc\pandoc.exe" -f markdown -t html5 --metadata pagetitle="CertViewer" --embed-resources --standalone --css "etc\style\github-markdown.css" -o "out\target\README.html"

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
