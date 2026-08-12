/*
 * driver_loader.c — SCM-based service creation plus NtLoadDriver/NtUnloadDriver
 */
#include "driver_loader.h"

#include <stdio.h>
#include <wchar.h>
#include <winternl.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef NTSTATUS (NTAPI *PFN_NtLoadDriver)(PUNICODE_STRING driver_service_name);
typedef NTSTATUS (NTAPI *PFN_NtUnloadDriver)(PUNICODE_STRING driver_service_name);
typedef VOID     (NTAPI *PFN_RtlInitUnicodeString)(PUNICODE_STRING destination_string, PCWSTR source_string);

static DWORD g_last_win32_error = 0;
static LONG  g_last_nt_status  = 0;

DWORD GetLastWin32Error(void) { return g_last_win32_error; }
LONG  GetLastNtStatus(void)   { return g_last_nt_status; }

static void ResetErrors(void)
{
    g_last_win32_error = 0;
    g_last_nt_status = 0;
}

const char *StatusString(DL_STATUS status)
{
    switch (status) {
    case DL_OK:                 return "OK";
    case DL_ERR_INVALID_ARG:    return "invalid argument";
    case DL_ERR_PRIVILEGE:      return "failed to enable SeLoadDriverPrivilege";
    case DL_ERR_SCM_OPEN:       return "failed to open Service Control Manager";
    case DL_ERR_CREATE_SERVICE: return "failed to create or update service";
    case DL_ERR_OPEN_SERVICE:   return "failed to open service";
    case DL_ERR_START_SERVICE:  return "failed to start service";
    case DL_ERR_STOP_SERVICE:   return "failed to stop service";
    case DL_ERR_DELETE_SERVICE: return "failed to delete service";
    case DL_ERR_NTLOAD:         return "NtLoadDriver failed";
    case DL_ERR_NTUNLOAD:       return "NtUnloadDriver failed";
    case DL_ERR_PATH:           return "invalid or missing driver path";
    case DL_ERR_ALREADY_EXISTS: return "service already exists or driver already loaded";
    case DL_ERR_NOT_FOUND:      return "service not found";
    default:                    return "unknown error";
    }
}

BOOL EnableLoadDriverPrivilege(void)
{
    HANDLE token = NULL;
    TOKEN_PRIVILEGES privileges;
    LUID luid;

    g_last_win32_error = 0;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        g_last_win32_error = GetLastError();
        return FALSE;
    }

    if (!LookupPrivilegeValueW(NULL, SE_LOAD_DRIVER_NAME, &luid)) {
        g_last_win32_error = GetLastError();
        CloseHandle(token);
        return FALSE;
    }

    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = luid;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    SetLastError(ERROR_SUCCESS);
    if (!AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), NULL, NULL)) {
        g_last_win32_error = GetLastError();
        CloseHandle(token);
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        g_last_win32_error = ERROR_NOT_ALL_ASSIGNED;
        CloseHandle(token);
        return FALSE;
    }

    CloseHandle(token);
    return TRUE;
}

static BOOL ResolveNtFunctions(
    PFN_NtLoadDriver *p_load,
    PFN_NtUnloadDriver *p_unload,
    PFN_RtlInitUnicodeString *p_init)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        g_last_win32_error = GetLastError();
        return FALSE;
    }

    if (p_load)
        *p_load = (PFN_NtLoadDriver)(void *)GetProcAddress(ntdll, "NtLoadDriver");
    if (p_unload)
        *p_unload = (PFN_NtUnloadDriver)(void *)GetProcAddress(ntdll, "NtUnloadDriver");
    if (p_init)
        *p_init = (PFN_RtlInitUnicodeString)(void *)GetProcAddress(ntdll, "RtlInitUnicodeString");

    if ((p_load && !*p_load) || (p_unload && !*p_unload) || (p_init && !*p_init)) {
        g_last_win32_error = ERROR_PROC_NOT_FOUND;
        return FALSE;
    }

    return TRUE;
}

static BOOL BuildServiceRegPath(const wchar_t *service_name, wchar_t *out, size_t cch_out)
{
    const wchar_t *prefix = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\";

    if (!service_name || !service_name[0] || !out || cch_out == 0)
        return FALSE;

    if (wcslen(prefix) + wcslen(service_name) + 1 > cch_out)
        return FALSE;

    wcscpy_s(out, cch_out, prefix);
    wcscat_s(out, cch_out, service_name);
    return TRUE;
}

static BOOL NormalizeDriverPath(const wchar_t *input_path, wchar_t *output_path, DWORD cch_out)
{
    DWORD length;

    if (!input_path || !input_path[0])
        return FALSE;

    length = GetFullPathNameW(input_path, cch_out, output_path, NULL);
    if (length == 0 || length >= cch_out) {
        g_last_win32_error = GetLastError();
        return FALSE;
    }

    if (GetFileAttributesW(output_path) == INVALID_FILE_ATTRIBUTES) {
        g_last_win32_error = GetLastError();
        return FALSE;
    }

    return TRUE;
}

static DL_STATUS CreateOrUpdateService(
    const wchar_t *service_name,
    const wchar_t *display_name,
    const wchar_t *driver_path_abs,
    SC_HANDLE *service_handle)
{
    SC_HANDLE manager = NULL;
    SC_HANDLE service = NULL;
    const wchar_t *friendly_name = (display_name && display_name[0]) ? display_name : service_name;

    *service_handle = NULL;

    manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!manager) {
        g_last_win32_error = GetLastError();
        return DL_ERR_SCM_OPEN;
    }

    service = CreateServiceW(manager, service_name, friendly_name, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, driver_path_abs, NULL, NULL, NULL, NULL, NULL);

    if (service) {
        *service_handle = service;
        CloseServiceHandle(manager);
        return DL_OK;
    }

    g_last_win32_error = GetLastError();
    if (g_last_win32_error != ERROR_SERVICE_EXISTS) {
        CloseServiceHandle(manager);
        return DL_ERR_CREATE_SERVICE;
    }

    service = OpenServiceW(manager, service_name, SERVICE_ALL_ACCESS);
    if (!service) {
        g_last_win32_error = GetLastError();
        CloseServiceHandle(manager);
        return DL_ERR_OPEN_SERVICE;
    }

    if (!ChangeServiceConfigW(service, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, driver_path_abs, NULL, NULL, NULL, NULL, NULL, friendly_name)) {
        g_last_win32_error = GetLastError();
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
        return DL_ERR_CREATE_SERVICE;
    }

    *service_handle = service;
    CloseServiceHandle(manager);
    return DL_OK;
}

DL_STATUS LoadDriver(
    const wchar_t *service_name,
    const wchar_t *display_name,
    const wchar_t *driver_path)
{
    wchar_t absolute_path[DRIVER_LOADER_MAX_PATH];
    wchar_t registry_path[DRIVER_LOADER_MAX_PATH];
    SC_HANDLE service = NULL;
    DL_STATUS status;
    UNICODE_STRING unicode_name;
    PFN_NtLoadDriver nt_load = NULL;
    PFN_RtlInitUnicodeString rtl_init = NULL;
    NTSTATUS nt_status;

    ResetErrors();

    if (!service_name || !service_name[0] || !driver_path || !driver_path[0])
        return DL_ERR_INVALID_ARG;

    if (!NormalizeDriverPath(driver_path, absolute_path, DRIVER_LOADER_MAX_PATH))
        return DL_ERR_PATH;

    if (!EnableLoadDriverPrivilege())
        return DL_ERR_PRIVILEGE;

    status = CreateOrUpdateService(service_name, display_name, absolute_path, &service);
    if (status != DL_OK)
        return status;

    CloseServiceHandle(service);
    service = NULL;

    if (!BuildServiceRegPath(service_name, registry_path, DRIVER_LOADER_MAX_PATH))
        return DL_ERR_INVALID_ARG;

    if (!ResolveNtFunctions(&nt_load, NULL, &rtl_init))
        return DL_ERR_NTLOAD;

    rtl_init(&unicode_name, registry_path);
    nt_status = nt_load(&unicode_name);
    g_last_nt_status = (LONG)nt_status;

    if (NT_SUCCESS(nt_status))
        return DL_OK;

    if ((ULONG)nt_status == 0xC000010Eu)
        return DL_OK;

    return DL_ERR_NTLOAD;
}

DL_STATUS UnloadDriver(const wchar_t *service_name)
{
    wchar_t registry_path[DRIVER_LOADER_MAX_PATH];
    UNICODE_STRING unicode_name;
    PFN_NtUnloadDriver nt_unload = NULL;
    PFN_RtlInitUnicodeString rtl_init = NULL;
    NTSTATUS nt_status;
    SC_HANDLE manager = NULL;
    SC_HANDLE service = NULL;
    SERVICE_STATUS service_status;
    BOOL unload_accepted = FALSE;

    ResetErrors();

    if (!service_name || !service_name[0])
        return DL_ERR_INVALID_ARG;

    if (!EnableLoadDriverPrivilege())
        return DL_ERR_PRIVILEGE;

    if (!BuildServiceRegPath(service_name, registry_path, DRIVER_LOADER_MAX_PATH))
        return DL_ERR_INVALID_ARG;

    if (!ResolveNtFunctions(NULL, &nt_unload, &rtl_init))
        return DL_ERR_NTUNLOAD;

    rtl_init(&unicode_name, registry_path);
    nt_status = nt_unload(&unicode_name);
    g_last_nt_status = (LONG)nt_status;

    if (NT_SUCCESS(nt_status)) {
        unload_accepted = TRUE;
    } else {
        ULONG code = (ULONG)nt_status;
        if (code == 0xC0000034u || code == 0xC000000Eu || code == 0xC0000010u)
            unload_accepted = TRUE;
    }

    manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!manager) {
        g_last_win32_error = GetLastError();
        return DL_ERR_SCM_OPEN;
    }

    service = OpenServiceW(manager, service_name, SERVICE_ALL_ACCESS);
    if (!service) {
        g_last_win32_error = GetLastError();
        CloseServiceHandle(manager);
        if (g_last_win32_error == ERROR_SERVICE_DOES_NOT_EXIST)
            return unload_accepted ? DL_OK : DL_ERR_NOT_FOUND;
        return DL_ERR_OPEN_SERVICE;
    }

    ZeroMemory(&service_status, sizeof(service_status));
    if (!ControlService(service, SERVICE_CONTROL_STOP, &service_status)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_NOT_ACTIVE && err != ERROR_INVALID_SERVICE_CONTROL)
            g_last_win32_error = err;
    }

    if (!DeleteService(service)) {
        g_last_win32_error = GetLastError();
        if (g_last_win32_error != ERROR_SERVICE_MARKED_FOR_DELETE) {
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
            return DL_ERR_DELETE_SERVICE;
        }
    }

    CloseServiceHandle(service);
    CloseServiceHandle(manager);

    if (!unload_accepted && !NT_SUCCESS(nt_status))
        return DL_ERR_NTUNLOAD;

    return DL_OK;
}
