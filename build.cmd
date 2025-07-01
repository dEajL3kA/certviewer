@echo off
cd /d "%~dp0"

set MSBUILD_PATH=

for /f "usebackq delims=" %%i in (`etc\utilities\vswhere\vswhere.exe -products * -latest -requires Microsoft.Component.MSBuild Microsoft.Net.Component.4.7.2.TargetingPack Microsoft.Net.ComponentGroup.DevelopmentPrerequisites -find MSBuild\**\Bin\MSBuild.exe`) do (
	set "MSBUILD_PATH=%%~fi"
	set "PATH=%%~dpi;%PATH%"
)

if "%GIT_EXEFILE%" == "" (
	if exist "%ProgramFiles%\Git\bin\git.exe" (
		set "GIT_EXEFILE=%ProgramFiles%\Git\bin\git.exe"
	) else (
		if exist "%ProgramFiles(x86)%\Git\bin\git.exe" (
			set "GIT_EXEFILE=%ProgramFiles(x86)%\Git\bin\git.exe"
		) else (
			if exist "%LOCALAPPDATA%\Programs\Git\bin\git.exe" (
				set "GIT_EXEFILE=%LOCALAPPDATA%\Programs\Git\bin\git.exe"
			)
		)
	)
)

if "%PANDOC_EXEFILE%" == "" (
	if exist "%ProgramFiles%\Pandoc\pandoc.exe" (
		set "PANDOC_EXEFILE=%ProgramFiles%\Pandoc\pandoc.exe"
	) else (
		if exist "%ProgramFiles(x86)%\Pandoc\pandoc.exe" (
			set "PANDOC_EXEFILE=%ProgramFiles(x86)%\Pandoc\pandoc.exe"
		) else (
			if exist "%LOCALAPPDATA%\Pandoc\pandoc.exe" (
				set "PANDOC_EXEFILE=%LOCALAPPDATA%\Pandoc\pandoc.exe"
			)
		)
	)
)

if not exist "%MSBUILD_PATH%" (
	echo Visual Studio with .NET Framework 4.7.2 component not found !!!
	pause && goto:eof
)

if not exist "%GIT_EXEFILE%" (
	echo Git executable file not found !!!
	pause && goto:eof
)

if not exist "%PANDOC_EXEFILE%" (
	echo Pandoc executable file not found !!!
	pause && goto:eof
)

echo Using MSBuild: %MSBUILD_PATH%"
echo Using Git: "%GIT_EXEFILE%"
echo Using Pandoc: "%PANDOC_EXEFILE%"

echo ------------------------------------------------------------------------------
echo Clean up...
echo ------------------------------------------------------------------------------

for %%d in (.vs bin obj out packages) do (
	echo %%~d
	if exist "%%~d" (
		rmdir /S /Q "%%~d" || del /F /Q "%%~d"
	)
	if exist "%%~d" (
		echo Directory "%%~d" could not be removed !!!
		pause && goto:eof
	)
)

for /F "tokens=* usebackq" %%i in (`etc\utilities\unxutils\date.exe "+%%Y-%%m-%%d"`) do (
	set "BUILD_DATE=%%~i"
)

for /F "tokens=* usebackq" %%i in (`etc\utilities\unxutils\date.exe "+%%H:%%M:%%S"`) do (
	set "BUILD_TIME=%%~i"
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

"%GIT_EXEFILE%" describe --long --dirty > "out\CertViewer.%BUILD_DATE%.txt"
set /p BUILD_VERS=< "out\CertViewer.%BUILD_DATE%.txt"
echo Version %BUILD_VERS%, built on %BUILD_DATE% at %BUILD_TIME%> "out\target\VERSION.txt"

copy /B "bin\Release\CertViewer.exe*" "out\target"
copy /B "LICENSE.txt" "out\target"

"%CD%\etc\utilities\unxutils\grep.exe" -v "shields.io" "README.md" | "%PANDOC_EXEFILE%" -f markdown -t html5 --metadata pagetitle="CertViewer" --embed-resources --standalone --css "etc\style\github-markdown.css" -o "out\target\README.html"

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
