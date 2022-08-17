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

    g_TestFunc(10);
}

void ApplyHook()
{
    FARPROC pTestFunc = GetProcAddress(GetModuleHandle(0), "TestFunc");

    PHOOK_DESCRIPTOR pHook = Trampy::CreateHook(pTestFunc, PatchedFunc, (PVOID *) &g_TestFunc);

    Trampy::EnableHook(pHook);
}

int main()
{
    TestFunc(3);

    ApplyHook();

    TestFunc(3);

    return 0;
}