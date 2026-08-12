/*
 * a small helper for loading and unloading kernel drivers
 *
 * This module uses SCM service creation plus NtLoadDriver / NtUnloadDriver.
 * It is designed for simple command-line tools that need to load a .sys driver
 * from user mode while preserving the service registry entry.
 *
 * Requires Administrator or an already enabled SeLoadDriverPrivilege.
 */
#ifndef DRIVER_LOADER_H
#define DRIVER_LOADER_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsvc.h>

#ifndef DRIVER_LOADER_MAX_PATH
#define DRIVER_LOADER_MAX_PATH MAX_PATH
#endif

typedef enum DL_STATUS {
    DL_OK = 0,
    DL_ERR_INVALID_ARG,
    DL_ERR_PRIVILEGE,
    DL_ERR_SCM_OPEN,
    DL_ERR_CREATE_SERVICE,
    DL_ERR_OPEN_SERVICE,
    DL_ERR_START_SERVICE,
    DL_ERR_STOP_SERVICE,
    DL_ERR_DELETE_SERVICE,
    DL_ERR_NTLOAD,
    DL_ERR_NTUNLOAD,
    DL_ERR_PATH,
    DL_ERR_ALREADY_EXISTS,
    DL_ERR_NOT_FOUND,
    DL_ERR_UNKNOWN
} DL_STATUS;

/*
 * LoadDriver
 * ----------
 * Creates or updates a kernel driver service and loads it via NtLoadDriver.
 *
 * serviceName  : short service name (example: "MyDriver")
 * displayName  : optional friendly name for the service (can be NULL)
 * driverPath   : path to a .sys file, absolute path recommended
 *
 * Returns DL_OK on success.
 */
DL_STATUS LoadDriver(
    const wchar_t *serviceName,
    const wchar_t *displayName,
    const wchar_t *driverPath
);

/*
 * UnloadDriver
 * ------------
 * Unloads the driver using NtUnloadDriver and removes the service entry.
 *
 * serviceName : same name used by LoadDriver
 */
DL_STATUS UnloadDriver(const wchar_t *serviceName);

BOOL EnableLoadDriverPrivilege(void);
const char *StatusString(DL_STATUS status);
DWORD GetLastWin32Error(void);
LONG GetLastNtStatus(void);


#endif /* DRIVER_LOADER_H */
