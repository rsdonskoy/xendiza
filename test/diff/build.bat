@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" -arch=x64 >nul
cd /d "%~dp0"
cl /nologo /std:c++20 /EHsc /O2 /Zc:preprocessor /I..\..\include /I. harness.cpp ..\..\src\xendiza.cpp ..\..\src\xendiza_x64.cpp ..\..\src\xendiza_x86.cpp ..\..\src\vex.cpp ..\..\src\vex_decode.cpp /Fe:out\harness.exe /Fo:out\
