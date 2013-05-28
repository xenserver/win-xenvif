call "%VS%\VC\vcvarsall.bat" x86
msbuild.exe /m:4 /p:Configuration="%CONFIGURATION%" /p:Platform="%PLATFORM%" /t:"%TARGET%" /p:SignMode="ProductionSign" %SOLUTION%.sln
if errorlevel 1 goto error
exit 0

:error
exit 1
