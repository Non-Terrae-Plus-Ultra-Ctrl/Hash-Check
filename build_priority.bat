@echo off
echo ===== Building x64 =====
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe" HashCheck.vcxproj /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v143 /m /v:minimal /nologo
if errorlevel 1 exit /b 1
echo ===== Building Win32 =====
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars32.bat" >nul 2>&1
"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe" HashCheck.vcxproj /p:Configuration=Release /p:Platform=Win32 /p:PlatformToolset=v143 /m /v:minimal /nologo
if errorlevel 1 exit /b 1
echo ===== BUILD OK =====
exit /b 0