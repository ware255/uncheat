@echo off
g++ -c src/*.cpp -Ofast
ar rcs libuncheat.a uncheat.o
mkdir uncheat > nul 2>&1
copy /Y .\src\uncheat.h .\uncheat\ > nul
copy /B /Y .\libuncheat.a .\uncheat\ > nul
g++ -o main.exe main.cpp -Iuncheat -L. -static -luncheat -Ofast -s -Wall -Wextra

del *.o *.a