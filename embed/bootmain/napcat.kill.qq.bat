@echo off
chcp 65001
setlocal enabledelayedexpansion

echo 列出所有带有 --enable-logging 参数的 QQ.exe 进程:
for /f "tokens=2 delims=," %%i in ('wmic process where "name='QQ.exe' and commandline like '%%--enable-logging%%'" get processid /format:csv') do (
    echo PID: %%i
)

set /p pid=请输入要清除的QQ.exe进程PID (输入0清除所有QQ.exe进程):

if "%pid%"=="0" (
    taskkill /f /im QQ.exe
) else (
    taskkill /f /pid %pid%
)

endlocal

pause