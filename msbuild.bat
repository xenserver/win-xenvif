call "%VS%\VC\vcvarsall.bat" x86
@echo on
msbuild.exe /m:1 /p:Configuration="%CONFIGURATION%" /p:Platform="%PLATFORM%" /t:"%TARGET%" %EXTRA% %FILE%
if errorlevel 1 goto error
exit 0

:error
exit 1
