#include <Windows.h>
#include <stdio.h>
#include "trampy/Trampy.h"

using Signature = void (__cdecl *) (int);
Signature g_TestFunc = NULL;

extern "C" __declspec(dllexport)
void __cdecl TestFunc(int a)
{
    printf("I am the Original: %d\n", a);
}

extern "C" __declspec(dllexport)
void __cdecl PatchedFunc(int a)
{
    printf("I am the Patched: %d\n", a);
}

int main()
{
    PHOOK_DESCRIPTOR pHook = Trampy::CreateHook(
        GetProcAddress(GetModuleHandle(0), "TestFunc"),
        PatchedFunc,
        (PVOID *) &g_TestFunc
    );

    TestFunc(3);

    Trampy::EnableAllHooks();

    TestFunc(3);

    Trampy::DisableAllHooks();

    TestFunc(3);

    return 0;
}