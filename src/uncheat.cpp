#include "uncheat.h"

bool ucl::ISDebuggerPresent() {
    HMODULE hKernel32 = GetModuleHandleA(uc("kernel32.dll"));
    if (!hKernel32) return false;
    FARPROC pIsDebuggerPresent = GetProcAddress(hKernel32, uc("IsDebuggerPresent"));
    if (!pIsDebuggerPresent) return false;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot) return false;
    PROCESSENTRY32W ProcessEntry;
    ProcessEntry.dwSize = sizeof(PROCESSENTRY32W);
    if (!Process32FirstW(hSnapshot, &ProcessEntry)) return false;
    bool bDebuggerPresent = false;
    HANDLE hProcess = NULL;
    DWORD dwFuncBytes = 0;
    const DWORD dwCurrentPID = GetCurrentProcessId();
    do {
        try {
            if (dwCurrentPID == ProcessEntry.th32ProcessID) continue;
            hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessEntry.th32ProcessID);
            if (NULL == hProcess) continue;
            if (!ReadProcessMemory(hProcess, (LPCVOID)pIsDebuggerPresent, &dwFuncBytes, sizeof(DWORD), NULL)) continue;
            if (dwFuncBytes != *(PDWORD)pIsDebuggerPresent) {
                bDebuggerPresent = true;
                break;
            }
        }
        catch (...) {
            if (hProcess) CloseHandle(hProcess);
        }
    } while (Process32NextW(hSnapshot, &ProcessEntry));
    if (hSnapshot) CloseHandle(hSnapshot);
    return bDebuggerPresent;
}