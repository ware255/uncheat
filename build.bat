@echo off
g++ -c src/*.cpp -Os -s
ar rcs libuncheat.a *.o
mkdir uncheat > nul 2>&1
copy /Y .\src\uncheat.h .\uncheat\ > nul
copy /B /Y .\libuncheat.a .\uncheat\ > nul

del *.o *.a
