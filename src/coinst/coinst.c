/* Copyright (c) Citrix Systems Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, 
 * with or without modification, are permitted provided 
 * that the following conditions are met:
 * 
 * *   Redistributions of source code must retain the above 
 *     copyright notice, this list of conditions and the 
 *     following disclaimer.
 * *   Redistributions in binary form must reproduce the above 
 *     copyright notice, this list of conditions and the 
 *     following disclaimer in the documentation and/or other 
 *     materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND 
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR 
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE.
 */

#include <windows.h>
#include <setupapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <strsafe.h>
#include <malloc.h>

#include <version.h>

__user_code;

#define MAXIMUM_BUFFER_SIZE 1024

#define SERVICES_KEY "SYSTEM\\CurrentControlSet\\Services"

#define PARAMETERS_KEY(_Driver)    \
        SERVICES_KEY ## "\\" ## #_Driver ## "\\Parameters"

#define STATUS_KEY(_Driver)    \
        SERVICES_KEY ## "\\" ## #_Driver ## "\\Status"

static VOID
#pragma prefast(suppress:6262) // Function uses '1036' bytes of stack: exceeds /analyze:stacksize'1024'
__Log(
    IN  const CHAR  *Format,
    IN  ...
    )
{
    TCHAR               Buffer[MAXIMUM_BUFFER_SIZE];
    va_list             Arguments;
    size_t              Length;
    SP_LOG_TOKEN        LogToken;
    DWORD               Category;
    DWORD               Flags;
    HRESULT             Result;

    va_start(Arguments, Format);
    Result = StringCchVPrintf(Buffer, MAXIMUM_BUFFER_SIZE, Format, Arguments);
    va_end(Arguments);

    if (Result != S_OK && Result != STRSAFE_E_INSUFFICIENT_BUFFER)
        return;

    Result = StringCchLength(Buffer, MAXIMUM_BUFFER_SIZE, &Length);
    if (Result != S_OK)
        return;

    LogToken = SetupGetThreadLogToken();
    Category = TXTLOG_VENDOR;
    Flags = TXTLOG_DETAILS;

    SetupWriteTextLog(LogToken, Category, Flags, Buffer);
    Length = __min(MAXIMUM_BUFFER_SIZE - 1, Length + 2);

    __analysis_assume(Length < MAXIMUM_BUFFER_SIZE);
    __analysis_assume(Length >= 2);
    Buffer[Length] = '\0';
    Buffer[Length - 1] = '\n';
    Buffer[Length - 2] = '\r';

    OutputDebugString(Buffer);
}

#define Log(_Format, ...) \
        __Log(__MODULE__ "|" __FUNCTION__ ": " _Format, __VA_ARGS__)

static PTCHAR
GetErrorMessage(
    IN  DWORD   Error
    )
{
    PTCHAR      Message;
    ULONG       Index;

    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | 
                  FORMAT_MESSAGE_FROM_SYSTEM |
                  FORMAT_MESSAGE_IGNORE_INSERTS,
                  NULL,
                  Error,
                  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                  (LPTSTR)&Message,
                  0,
                  NULL);

    for (Index = 0; Message[Index] != '\0'; Index++) {
        if (Message[Index] == '\r' || Message[Index] == '\n') {
            Message[Index] = '\0';
            break;
        }
    }

    return Message;
}

static const CHAR *
FunctionName(
    IN  DI_FUNCTION Function
    )
{
#define _NAME(_Function)        \
        case DIF_ ## _Function: \
            return #_Function;

    switch (Function) {
    _NAME(INSTALLDEVICE);
    _NAME(REMOVE);
    _NAME(SELECTDEVICE);
    _NAME(ASSIGNRESOURCES);
    _NAME(PROPERTIES);
    _NAME(FIRSTTIMESETUP);
    _NAME(FOUNDDEVICE);
    _NAME(SELECTCLASSDRIVERS);
    _NAME(VALIDATECLASSDRIVERS);
    _NAME(INSTALLCLASSDRIVERS);
    _NAME(CALCDISKSPACE);
    _NAME(DESTROYPRIVATEDATA);
    _NAME(VALIDATEDRIVER);
    _NAME(MOVEDEVICE);
    _NAME(DETECT);
    _NAME(INSTALLWIZARD);
    _NAME(DESTROYWIZARDDATA);
    _NAME(PROPERTYCHANGE);
    _NAME(ENABLECLASS);
    _NAME(DETECTVERIFY);
    _NAME(INSTALLDEVICEFILES);
    _NAME(ALLOW_INSTALL);
    _NAME(SELECTBESTCOMPATDRV);
    _NAME(REGISTERDEVICE);
    _NAME(NEWDEVICEWIZARD_PRESELECT);
    _NAME(NEWDEVICEWIZARD_SELECT);
    _NAME(NEWDEVICEWIZARD_PREANALYZE);
    _NAME(NEWDEVICEWIZARD_POSTANALYZE);
    _NAME(NEWDEVICEWIZARD_FINISHINSTALL);
    _NAME(INSTALLINTERFACES);
    _NAME(DETECTCANCEL);
    _NAME(REGISTER_COINSTALLERS);
    _NAME(ADDPROPERTYPAGE_ADVANCED);
    _NAME(ADDPROPERTYPAGE_BASIC);
    _NAME(TROUBLESHOOTER);
    _NAME(POWERMESSAGEWAKE);
    default:
        break;
    }

    return "UNKNOWN";

#undef  _NAME
}

static BOOLEAN
InstallClass(
    IN  PTCHAR  Class
    )
{
    HKEY        Key;
    DWORD       OldLength;
    DWORD       NewLength;
    DWORD       Type;
    LONG        Error;
    PTCHAR      Classes;
    ULONG       Offset;

    Error = RegCreateKeyEx(HKEY_LOCAL_MACHINE,
                           PARAMETERS_KEY(XENFILT),
                           0,
                           NULL,
                           REG_OPTION_NON_VOLATILE,
                           KEY_ALL_ACCESS,
                           NULL,
                           &Key,
                           NULL);
    if (Error != ERROR_SUCCESS) {
        SetLastError(Error);
        goto fail1;
    }

    OldLength = 0;
    Error = RegQueryValueEx(Key,
                            "UnplugClasses",
                            NULL,
                            &Type,
                            NULL,
                            &OldLength);
    if (Error != ERROR_SUCCESS) {
        if (Error != ERROR_FILE_NOT_FOUND) {
            SetLastError(Error);
            goto fail2;
        }

        OldLength = sizeof (TCHAR);
        Type = REG_MULTI_SZ;
    }

    if (Type != REG_MULTI_SZ) {
        SetLastError(ERROR_BAD_FORMAT);
        goto fail3;
    }

    NewLength = OldLength + (DWORD)((strlen(Class) + 1) * sizeof (TCHAR));

    Classes = malloc(NewLength);
    if (Classes == NULL)
        goto fail4;

    memset(Classes, 0, NewLength);

    Offset = 0;
    if (OldLength != sizeof (TCHAR)) {
        Error = RegQueryValueEx(Key,
                                "UnplugClasses",
                                NULL,
                                NULL,
                                (PBYTE)Classes,
                                &OldLength);
        if (Error != ERROR_SUCCESS) {
            SetLastError(Error);
            goto fail5;
        }

        while (Classes[Offset] != '\0') {
            ULONG   ClassLength;

            ClassLength = (ULONG)strlen(&Classes[Offset]) / sizeof (TCHAR);

            if (_stricmp(&Classes[Offset], Class) == 0) {
                Log("%s already present", Class);
                goto done;
            }

            Offset += ClassLength + 1;
        }
    }

    memmove(&Classes[Offset], Class, strlen(Class));
    Log("added %s", Class);

    Error = RegSetValueEx(Key,
                          "UnplugClasses",
                          0,
                          Type,
                          (PBYTE)Classes,
                          NewLength);
    if (Error != ERROR_SUCCESS) {
        SetLastError(Error);
        goto fail6;
    }

done:
    free(Classes);

    RegCloseKey(Key);

    return TRUE;

fail6:
fail5:
    free(Classes);

fail4:
fail3:
fail2:
    RegCloseKey(Key);

fail1:
    return FALSE;
}

static BOOLEAN
RemoveClass(
    IN  PTCHAR  Class
    )
{
    HKEY        Key;
    DWORD       OldLength;
    DWORD       NewLength;
    DWORD       Type;
    LONG        Error;
    PTCHAR      Classes;
    ULONG       Offset;
    ULONG       ClassLength;

    Error = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                         PARAMETERS_KEY(XENFILT),
                         0,
                         KEY_ALL_ACCESS,
                         &Key);
    if (Error != ERROR_SUCCESS) {
        SetLastError(Error);
        goto fail1;
    }

    OldLength = 0;
    Error = RegQueryValueEx(Key,
                            "UnplugClasses",
                            NULL,
                            &Type,
                            NULL,
                            &OldLength);
    if (Error != ERROR_SUCCESS) {
        if (Error != ERROR_FILE_NOT_FOUND) {
            SetLastError(Error);
            goto fail2;
        }

        goto done;
    }

    if (Type != REG_MULTI_SZ) {
        SetLastError(ERROR_BAD_FORMAT);
        goto fail3;
    }

    Classes = malloc(OldLength);
    if (Classes == NULL)
        goto fail4;

    memset(Classes, 0, OldLength);

    Error = RegQueryValueEx(Key,
                            "UnplugClasses",
                            NULL,
                            NULL,
                            (PBYTE)Classes,
                            &OldLength);
    if (Error != ERROR_SUCCESS) {
        SetLastError(Error);
        goto fail5;
    }

    Offset = 0;
    ClassLength = 0;
    while (Classes[Offset] != '\0') {
        ClassLength = (ULONG)strlen(&Classes[Offset]) / sizeof (TCHAR);

        if (_stricmp(&Classes[Offset], Class) == 0)
            goto remove;

        Offset += ClassLength + 1;
    }

    free(Classes);
    goto done;

remove:
    NewLength = OldLength - ((ClassLength + 1) * sizeof (TCHAR));

    memmove(&Classes[Offset],
            &Classes[Offset + ClassLength + 1],
            (NewLength - Offset) * sizeof (TCHAR));
            
    Log("removed %s", Class);

    if (NewLength == 1) {
        Error = RegDeleteValue(Key,
                               "UnplugClasses");
    } else {
        Error = RegSetValueEx(Key,
                              "UnplugClasses",
                              0,
                              Type,
                              (PBYTE)Classes,
                              NewLength);
    }
    if (Error != ERROR_SUCCESS) {
        SetLastError(Error);
        goto fail6;
    }

    free(Classes);

done:
    RegCloseKey(Key);

    return TRUE;

fail6:
fail5:
    free(Classes);

fail4:
fail3:
fail2:
    RegCloseKey(Key);

fail1:
    return FALSE;
}

static BOOLEAN
IsClassEmulated(
    IN  PTCHAR      Class,
    OUT PBOOLEAN    Present
    )
{
    HKEY            Key;
    DWORD           Length;
    DWORD           Type;
    LONG            Error;
    PTCHAR          Devices;
    ULONG           Count;
    ULONG           Offset;

    Error = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                         STATUS_KEY(XENFILT),
                         0,
                         KEY_READ,
                         &Key);
    if (Error != ERROR_SUCCESS) {
        if (Error == ERROR_FILE_NOT_FOUND)
            goto done;

        SetLastError(Error);
        goto fail1;
    }

    Length = 0;
    Error = RegQueryValueEx(Key,
                            Class,
                            NULL,
                            &Type,
                            NULL,
                            &Length);
    if (Error != ERROR_SUCCESS) {
        if (Error == ERROR_FILE_NOT_FOUND) {
            RegCloseKey(Key);
            goto done;
        }

        SetLastError(Error);
        goto fail2;
    }

    if (Type != REG_MULTI_SZ) {
        SetLastError(ERROR_BAD_FORMAT);
        goto fail3;
    }

    Devices = malloc(Length);
    if (Devices == NULL)
        goto fail4;

    memset(Devices, 0, Length);

    Error = RegQueryValueEx(Key,
                            Class,
                            NULL,
                            NULL,
                            (PBYTE)Devices,
                            &Length);
    if (Error != ERROR_SUCCESS) {
        SetLastError(Error);
        goto fail5;
    }

    Count = 0;

    Offset = 0;
    while (Devices[Offset] != '\0') {
        ULONG   DeviceLength;

        DeviceLength = (ULONG)strlen(&Devices[Offset]) / sizeof (TCHAR);

        Count++;
        Offset += DeviceLength + 1;
    }

    *Present = (Count != 0) ? TRUE : FALSE;

    free(Devices);

    RegCloseKey(Key);

done:
    return TRUE;

fail5:
    free(Devices);

fail4:
fail3:
fail2:
    RegCloseKey(Key);

fail1:
    return FALSE;
}

static BOOLEAN
RequestReboot(
    IN  HDEVINFO            DeviceInfoSet,
    IN  PSP_DEVINFO_DATA    DeviceInfoData
    )
{
    SP_DEVINSTALL_PARAMS    DeviceInstallParams;

    DeviceInstallParams.cbSize = sizeof (DeviceInstallParams);

    if (!SetupDiGetDeviceInstallParams(DeviceInfoSet,
                                       DeviceInfoData,
                                       &DeviceInstallParams))
        goto fail1;

    DeviceInstallParams.Flags |= DI_NEEDREBOOT;

    Log("Flags = %08x", DeviceInstallParams.Flags);

    if (!SetupDiSetDeviceInstallParams(DeviceInfoSet,
                                       DeviceInfoData,
                                       &DeviceInstallParams))
        goto fail2;

    return TRUE;

fail2:
fail1:
    return FALSE;
}

static FORCEINLINE HRESULT
__DifInstallPreProcess(
    IN  HDEVINFO                    DeviceInfoSet,
    IN  PSP_DEVINFO_DATA            DeviceInfoData,
    IN  PCOINSTALLER_CONTEXT_DATA   Context
    )
{
    UNREFERENCED_PARAMETER(DeviceInfoSet);
    UNREFERENCED_PARAMETER(DeviceInfoData);
    UNREFERENCED_PARAMETER(Context);

    Log("<===>");

    return ERROR_DI_POSTPROCESSING_REQUIRED; 
}

static FORCEINLINE HRESULT
__DifInstallPostProcess(
    IN  HDEVINFO                    DeviceInfoSet,
    IN  PSP_DEVINFO_DATA            DeviceInfoData,
    IN  PCOINSTALLER_CONTEXT_DATA   Context
    )
{
    HRESULT                         Error;
    BOOLEAN                         Present;
    BOOLEAN                         Success;

    Log("====>");

    Error = Context->InstallResult;
    if (Error != NO_ERROR) {
        SetLastError(Error);
        goto fail1;
    }

    Success = InstallClass("VIF");
    if (!Success)
        goto fail2;

    Success = IsClassEmulated("VIF", &Present);
    if (!Success)
        goto fail3;

    if (!Present)
        goto done;

    Success = RequestReboot(DeviceInfoSet, DeviceInfoData);
    if (!Success)
        goto fail4;

done:
    Log("<====");

    return NO_ERROR;

fail4:
    Log("fail4");

fail3:
    Log("fail3");

fail2:
    Log("fail2");

fail1:
    Error = GetLastError();

    {
        PTCHAR  Message;

        Message = GetErrorMessage(Error);
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }

    return Error;
}

static DECLSPEC_NOINLINE HRESULT
DifInstall(
    IN  HDEVINFO                    DeviceInfoSet,
    IN  PSP_DEVINFO_DATA            DeviceInfoData,
    IN  PCOINSTALLER_CONTEXT_DATA   Context
    )
{
    SP_DEVINSTALL_PARAMS            DeviceInstallParams;
    HRESULT                         Error;

    DeviceInstallParams.cbSize = sizeof (DeviceInstallParams);

    if (!SetupDiGetDeviceInstallParams(DeviceInfoSet,
                                       DeviceInfoData,
                                       &DeviceInstallParams))
        goto fail1;

    Log("Flags = %08x", DeviceInstallParams.Flags);

    Error = (!Context->PostProcessing) ?
            __DifInstallPreProcess(DeviceInfoSet, DeviceInfoData, Context) :
            __DifInstallPostProcess(DeviceInfoSet, DeviceInfoData, Context);

    return Error;

fail1:
    Error = GetLastError();

    {
        PTCHAR  Message;

        Message = GetErrorMessage(Error);
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }

    return Error;
}

static FORCEINLINE HRESULT
__DifRemovePreProcess(
    IN  HDEVINFO                    DeviceInfoSet,
    IN  PSP_DEVINFO_DATA            DeviceInfoData,
    IN  PCOINSTALLER_CONTEXT_DATA   Context
    )
{
    UNREFERENCED_PARAMETER(DeviceInfoSet);
    UNREFERENCED_PARAMETER(DeviceInfoData);
    UNREFERENCED_PARAMETER(Context);

    Log("<===>");

    return ERROR_DI_POSTPROCESSING_REQUIRED; 
}

static FORCEINLINE HRESULT
__DifRemovePostProcess(
    IN  HDEVINFO                    DeviceInfoSet,
    IN  PSP_DEVINFO_DATA            DeviceInfoData,
    IN  PCOINSTALLER_CONTEXT_DATA   Context
    )
{
    HRESULT                         Error;
    BOOLEAN                         Success;

    Log("====>");

    Error = Context->InstallResult;
    if (Error != NO_ERROR) {
        SetLastError(Error);
        goto fail1;
    }

    Success = RemoveClass("VIF");
    if (!Success)
        goto fail2;

    Success = RequestReboot(DeviceInfoSet, DeviceInfoData);
    if (!Success)
        goto fail3;

    Log("<====");

    return NO_ERROR;

fail3:
    Log("fail3");

fail2:
    Log("fail2");

fail1:
    Error = GetLastError();

    {
        PTCHAR  Message;

        Message = GetErrorMessage(Error);
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }

    return Error;
}

static DECLSPEC_NOINLINE HRESULT
DifRemove(
    IN  HDEVINFO                    DeviceInfoSet,
    IN  PSP_DEVINFO_DATA            DeviceInfoData,
    IN  PCOINSTALLER_CONTEXT_DATA   Context
    )
{
    SP_DEVINSTALL_PARAMS            DeviceInstallParams;
    HRESULT                         Error;

    DeviceInstallParams.cbSize = sizeof (DeviceInstallParams);

    if (!SetupDiGetDeviceInstallParams(DeviceInfoSet,
                                       DeviceInfoData,
                                       &DeviceInstallParams))
        goto fail1;

    Log("Flags = %08x", DeviceInstallParams.Flags);

    Error = (!Context->PostProcessing) ?
            __DifRemovePreProcess(DeviceInfoSet, DeviceInfoData, Context) :
            __DifRemovePostProcess(DeviceInfoSet, DeviceInfoData, Context);

    return Error;

fail1:
    Error = GetLastError();

    {
        PTCHAR  Message;

        Message = GetErrorMessage(Error);
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }

    return Error;
}

DWORD CALLBACK
Entry(
    IN  DI_FUNCTION                 Function,
    IN  HDEVINFO                    DeviceInfoSet,
    IN  PSP_DEVINFO_DATA            DeviceInfoData,
    IN  PCOINSTALLER_CONTEXT_DATA   Context
    )
{
    HRESULT                         Error;

    Log("%s (%s) ===>",
        MAJOR_VERSION_STR "." MINOR_VERSION_STR "." MICRO_VERSION_STR "." BUILD_NUMBER_STR,
        DAY_STR "/" MONTH_STR "/" YEAR_STR);

    switch (Function) {
    case DIF_INSTALLDEVICE: {
        SP_DRVINFO_DATA         DriverInfoData;
        BOOLEAN                 DriverInfoAvailable;

        DriverInfoData.cbSize = sizeof (DriverInfoData);
        DriverInfoAvailable = SetupDiGetSelectedDriver(DeviceInfoSet,
                                                       DeviceInfoData,
                                                       &DriverInfoData) ?
                              TRUE :
                              FALSE;

        // If there is no driver information then the NULL driver is being
        // installed. Treat this as we would a DIF_REMOVE.
        Error = (DriverInfoAvailable) ?
                DifInstall(DeviceInfoSet, DeviceInfoData, Context) :
                DifRemove(DeviceInfoSet, DeviceInfoData, Context);
        break;
    }
    case DIF_REMOVE:
        Error = DifRemove(DeviceInfoSet, DeviceInfoData, Context);
        break;
    default:
        if (!Context->PostProcessing) {
            Log("%s PreProcessing",
                FunctionName(Function));

            Error = NO_ERROR;
        } else {
            Log("%s PostProcessing (%08x)",
                FunctionName(Function),
                Context->InstallResult);

            Error = Context->InstallResult;
        }

        break;
    }

    Log("%s (%s) <===",
        MAJOR_VERSION_STR "." MINOR_VERSION_STR "." MICRO_VERSION_STR "." BUILD_NUMBER_STR,
        DAY_STR "/" MONTH_STR "/" YEAR_STR);

    return (DWORD)Error;
}

DWORD CALLBACK
Version(
    IN  HWND        Window,
    IN  HINSTANCE   Module,
    IN  PTCHAR      Buffer,
    IN  INT         Reserved
    )
{
    UNREFERENCED_PARAMETER(Window);
    UNREFERENCED_PARAMETER(Module);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(Reserved);

    Log("%s (%s)",
        MAJOR_VERSION_STR "." MINOR_VERSION_STR "." MICRO_VERSION_STR "." BUILD_NUMBER_STR,
        DAY_STR "/" MONTH_STR "/" YEAR_STR);

    return NO_ERROR;
}

static FORCEINLINE const CHAR *
__ReasonName(
    IN  DWORD       Reason
    )
{
#define _NAME(_Reason)          \
        case DLL_ ## _Reason:   \
            return #_Reason;

    switch (Reason) {
    _NAME(PROCESS_ATTACH);
    _NAME(PROCESS_DETACH);
    _NAME(THREAD_ATTACH);
    _NAME(THREAD_DETACH);
    default:
        break;
    }

    return "UNKNOWN";

#undef  _NAME
}

BOOL WINAPI
DllMain(
    IN  HINSTANCE   Module,
    IN  DWORD       Reason,
    IN  PVOID       Reserved
    )
{
    UNREFERENCED_PARAMETER(Module);
    UNREFERENCED_PARAMETER(Reserved);

    Log("%s (%s): %s",
        MAJOR_VERSION_STR "." MINOR_VERSION_STR "." MICRO_VERSION_STR "." BUILD_NUMBER_STR,
        DAY_STR "/" MONTH_STR "/" YEAR_STR,
        __ReasonName(Reason));

    return TRUE;
}
