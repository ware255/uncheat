#include "uncheat.h"
const wchar_t *mes = L"Ты осел.";
const wchar_t *mez = L"Вы просто идиот.";

void ucl::junk() {
    int a; a ^= a;
    int b; b ^= b;
    a = a > 0 ? 0 : 1;
    for (; a <= sizeof(long long); b++) a *= 2;
    b = a * b; a ^= b;
    if (!(a^a)&0 != 0) goto h;
    else goto i;
h:  err();
i:  return;
}

unsigned int fnv_1_hash_32(char *string) {
    constexpr unsigned int FNV_OFFSET_BASIS_32 = 2166136261U;
    constexpr unsigned int FNV_PRIME_32 = 16777619U;
    unsigned int hash;
    size_t len = strnlen_s(string, 50);

    hash = FNV_OFFSET_BASIS_32;
    for (size_t i = 0 ; i < len ; ++i) hash = (FNV_PRIME_32 * hash) ^ (string[i]);

    return hash;
}

PDWORD ucl::GetFuncAddressHash(const char *library, DWORD hash) {
    PDWORD functionAddress = {};
    HMODULE libraryBase = LoadLibraryA(library);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;
    PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)libraryBase + dosHeader->e_lfanew);
    
    DWORD_PTR exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    
    PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)libraryBase + exportDirectoryRVA);

    PDWORD addresOfFunctionsRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfFunctions);
    PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNames);
    PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNameOrdinals);

    for (DWORD i = 0; i < imageExportDirectory->NumberOfFunctions; i++) {
        DWORD functionNameRVA = addressOfNamesRVA[i];
        DWORD_PTR functionNameVA = (DWORD_PTR)libraryBase + functionNameRVA;
        char* functionName = (char*)functionNameVA;
        DWORD_PTR functionAddressRVA = 0;

        DWORD functionNameHash = fnv_1_hash_32(functionName);

        if (functionNameHash == hash) {
            functionAddressRVA = addresOfFunctionsRVA[i[addressOfNameOrdinalsRVA]];
            functionAddress = (PDWORD)((DWORD_PTR)libraryBase + functionAddressRVA);
            return functionAddress;
        }
    }
    return 0;
}

void ucl::err() {
    char lib[] = "user32";
    const char a = GetTickCount() % 0x80;
    const int b = 0x1c4e3f6c ^ a;
    for (size_t i{}; i < sizeof(lib); ++i) lib[i] ^= a;
    for (size_t i{}; i < sizeof(lib); ++i) lib[i] ^= a;
    ((int(*)(HWND, LPCWSTR, LPCWSTR, UINT))GetFuncAddressHash(lib, b ^ a))(NULL, mez, mes, MB_OK);
    ExitProcess(-1);
}

void ucl::HardwareDebugRegisters() {
    void(*j)() = junk;
    char lib[] = "kernel32";
    const char a = GetTickCount() % 0x80;
    const int b = 0x4faadae6 ^ a;
    const int c = 0x68eb854c ^ a;
    for (size_t i{}; i < sizeof(lib); ++i) lib[i] ^= a;
    CONTEXT ctx = { 0 }; [](){}();
    for (size_t i{}; i < sizeof(lib); ++i) lib[i] ^= a;
    HANDLE hThread = ((HANDLE(*)())GetFuncAddressHash(lib, b ^ a))();
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS; j();
    PDWORD faddress = GetFuncAddressHash(lib, c ^ a);
    if (((WINBOOL(*)(HANDLE, LPCONTEXT))faddress)(hThread, &ctx)) {
        if ((ctx.Dr0 != 0x00) || (ctx.Dr1 != 0x00) ||
            (ctx.Dr2 != 0x00) || (ctx.Dr3 != 0x00) ||
            (ctx.Dr6 != 0x00) || (ctx.Dr7 != 0x00)) {
            [](){}; j(); err();
        }
    }
}
