#  Driver Loader(SCM + NtLoadDriver)

<img width="971" height="387" alt="Image" src="https://github.com/user-attachments/assets/82d2eb0b-61cb-4690-b22a-e0d103502ac0" />
<img width="758" height="339" alt="Image" src="https://github.com/user-attachments/assets/f1802466-52d6-4597-a69c-0b17507c68d0" />

1. Enables **SeLoadDriverPrivilege**
2. Creates (or updates) a **kernel driver service** via SCM (`CreateService` / `ChangeServiceConfig`)
3. Loads the driver with **`NtLoadDriver`** on  
   `\Registry\Machine\System\CurrentControlSet\Services\<ServiceName>`
4. Unloads with **`NtUnloadDriver`**, then **stops + `DeleteService`**

## API

```c
#include "driver_loader.h"

DL_STATUS LoadDriver(
    const wchar_t *serviceName,   /* e.g. L"MyDrv" */
    const wchar_t *displayName,   /* optional, can be NULL */
    const wchar_t *driverPath     /* absolute or relative .sys path */
);

DL_STATUS UnloadDriver(const wchar_t *serviceName);
```

## CLI

```text
driver_loader.exe load   MyDrv C:\path\to\driver.sys "My Driver"
driver_loader.exe unload MyDrv
```

Run **as Administrator**.

## Build

```bash
x86_64-w64-mingw32-gcc -O2 -municode -o driver_loader.exe main.c driver_loader.c -ladvapi32
```
