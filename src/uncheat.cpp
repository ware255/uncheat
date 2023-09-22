#include "uncheat.h"

PVOID GetPEB() {
#ifdef _WIN64
    return (PVOID)__readgsqword(0x0C * sizeof(PVOID));
#else
    return (PVOID)__readfsdword(0x0C * sizeof(PVOID));
#endif
}

PVOID GetPEB64() {
    PVOID pPeb = 0;
#ifndef _WIN64
    if (IsWin8OrHigher()) {
        BOOL isWow64 = FALSE;
        typedef BOOL(WINAPI *pfnIsWow64Process)(HANDLE hProcess, PBOOL isWow64);
        pfnIsWow64Process fnIsWow64Process = (pfnIsWow64Process)
            GetProcAddress(GetModuleHandleA(uc("Kernel32.dll")), uc("IsWow64Process"));
        if (fnIsWow64Process(GetCurrentProcess(), &isWow64)) {
            if (isWow64) {
                pPeb = (PVOID)__readfsdword(0x0C * sizeof(PVOID));
                pPeb = (PVOID)((PBYTE)pPeb + 0x1000);
            }
        }
    }
#endif
    return pPeb;
}

void ucl::CheckNtGlobalFlag() {
    PVOID pPeb = GetPEB();
    PVOID pPeb64 = GetPEB64();
    DWORD offsetNtGlobalFlag = 0;
#ifdef _WIN64
    offsetNtGlobalFlag = 0xBC;
#else
    offsetNtGlobalFlag = 0x68;
#endif
    DWORD NtGlobalFlag = *(PDWORD)((PBYTE)pPeb + offsetNtGlobalFlag);
    if (NtGlobalFlag & NT_GLOBAL_FLAG_DEBUGGED) ExitProcess(-1);
    if (pPeb64) {
        DWORD NtGlobalFlagWow64 = *(PDWORD)((PBYTE)pPeb64 + 0xBC);
        if (NtGlobalFlagWow64 & NT_GLOBAL_FLAG_DEBUGGED) ExitProcess(-1);
    }
}

bool ucl::ISDEBUGGERPRESENT() {
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
