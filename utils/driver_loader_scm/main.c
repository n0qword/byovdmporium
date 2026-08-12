/*
 *
 *
 * Run elevated (Administrator). SeLoadDriverPrivilege is enabled at runtime.
 *
 * Build (MSVC x64 Native Tools):
 *   cl /nologo /W4 /O2 /DUNICODE /D_UNICODE main.c driver_loader.c /Fe:driver_loader.exe advapi32.lib
 *
 * Build (MinGW-w64):
 *   x86_64-w64-mingw32-gcc -O2 -municode -o driver_loader.exe main.c driver_loader.c -ladvapi32
 */
#include "driver_loader.h"

#include <stdio.h>
#include <stdlib.h>

static void show_usage(const wchar_t *programName)
{
    wprintf(L"Usage:\n");
    wprintf(L"  %s load   <ServiceName> <PathTo.sys> [DisplayName]\n", programName);
    wprintf(L"  %s unload <ServiceName>\n", programName);
    wprintf(L"\n");
    wprintf(L"This tool creates a kernel driver service and then loads or unloads it.\n");
    wprintf(L"Administrator rights are required.\n");
}

static void report_status(DL_STATUS status)
{
    wprintf(L"Result: %hs\n", StatusString(status));
    if (status != DL_OK) {
        DWORD win32Error = GetLastWin32Error();
        LONG ntStatus = GetLastNtStatus();

        if (win32Error)
            wprintf(L"  Win32 error: 0x%08lX (%lu)\n", (unsigned long)win32Error, (unsigned long)win32Error);
        if (ntStatus)
            wprintf(L"  NTSTATUS   : 0x%08lX\n", (unsigned long)(ULONG)ntStatus);
    }
}

static int handle_load(int argc, wchar_t **argv)
{
    const wchar_t *serviceName = argv[2];
    const wchar_t *driverPath = (argc >= 4) ? argv[3] : NULL;
    const wchar_t *displayName = (argc >= 5) ? argv[4] : NULL;

    if (!driverPath) {
        show_usage(argv[0]);
        return 1;
    }

    wprintf(L"[*] Loading driver service '%s' from '%s'...\n", serviceName, driverPath);
    DL_STATUS status = LoadDriver(serviceName, displayName, driverPath);
    report_status(status);
    return (status == DL_OK) ? 0 : 2;
}

static int handle_unload(wchar_t **argv)
{
    const wchar_t *serviceName = argv[2];

    wprintf(L"[*] Unloading driver service '%s'...\n", serviceName);
    DL_STATUS status = UnloadDriver(serviceName);
    report_status(status);
    return (status == DL_OK) ? 0 : 2;
}

int wmain(int argc, wchar_t **argv)
{
    const wchar_t *programName = (argc > 0 && argv[0]) ? argv[0] : L"driver_loader";

    if (argc < 3) {
        show_usage(programName);
        return 1;
    }

    if (_wcsicmp(argv[1], L"load") == 0)
        return handle_load(argc, argv);

    if (_wcsicmp(argv[1], L"unload") == 0)
        return handle_unload(argv);

    show_usage(programName);
    return 1;
}
