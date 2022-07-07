#include <Windows.h>
#include "Console.h"
#include <stdio.h>
#include "hooklib/hook.h"

using Signature = void (__cdecl *) (int);
Signature g_TestFunc = NULL;

extern "C" __declspec(dllexport)
void __cdecl PatchedFunc(int a)
{
    printf("I am the Patched: %d\n", a);

    g_TestFunc(10);
}

void ApplyHook()
{
    FARPROC pTestFunc = GetProcAddress(GetModuleHandle(0), "TestFunc");

    PHOOK_DESCRIPTOR pHook = CreateHook(pTestFunc, PatchedFunc, (PVOID *) &g_TestFunc);

    EnableHook(pHook);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        ApplyHook();
    }

    return TRUE;
}
