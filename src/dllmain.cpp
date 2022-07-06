#include <Windows.h>
#include "Console.h"
#include <stdio.h>
#include <vector>
#include "hooklib/disasm/disasm.h"

extern "C" __declspec(dllexport)
void __cdecl PatchedFunc(int a)
{
    printf("I am the Patched: %d\n", a);
}

#define PACKED(def) __pragma( pack(push, 1) ) struct def __pragma( pack(pop) )

#pragma pack(push, 1)
typedef struct _REL_INSTR
{
    BYTE Opcode;
    DWORD Operand;
}
REL_INSTR, *PREL_INSTR;
#pragma pack(pop)

#define MAX_INSTR_SIZE 15

typedef struct _HOOK_DESCRIPTOR
{
    BOOL bEnabled;
    LPVOID Original;
    LPVOID Hooked;

    struct
    {
        BYTE Buffer[MAX_INSTR_SIZE];
        USHORT Amount;
    }
    StolenBytes;
}
HOOK_DESCRIPTOR, *PHOOK_DESCRIPTOR;

typedef struct _TRAMPOLINE_FUNC
{
    REL_INSTR CallPatched;
    BYTE StolenBytes;
    REL_INSTR JmpOriginal;
}
TRAMPOLINE_FUNC, *PTRAMPOLINE_FUNC;

std::vector<HOOK_DESCRIPTOR> g_Hooks;

PHOOK_DESCRIPTOR CreateHook(LPVOID pOriginal, LPVOID pPatched)
{
    g_Hooks.push_back({ });

    PHOOK_DESCRIPTOR pHook = &g_Hooks.back();
    pHook->bEnabled = FALSE;
    pHook->Original = pOriginal;
    pHook->Hooked = pPatched;

    return pHook;
}

void ProtectedWrite(LPVOID pDest, LPVOID pSrc, SIZE_T byteAmount)
{
    DWORD oldProtect;
    VirtualProtect(pDest, byteAmount, PAGE_EXECUTE_READWRITE, &oldProtect);

    memcpy_s(
        pDest,
        byteAmount,
        pSrc,
        byteAmount
    );

    VirtualProtect(pDest, byteAmount, oldProtect, &oldProtect);
}

LPVOID CreateTrampoline(PHOOK_DESCRIPTOR pHook)
{
    SIZE_T trampolineSize = sizeof(REL_INSTR) + MAX_INSTR_SIZE + sizeof(REL_INSTR);
    LPVOID pTrampoline = VirtualAlloc(NULL, trampolineSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (!pTrampoline)
    {
        printf("VirtualAlloc failed - unable to allocate Trampoline function.\n");
        return NULL;
    }

    PBYTE replicatedBytes = (PBYTE) pTrampoline + sizeof(REL_INSTR);

    memset(
        replicatedBytes,
        0x90,
        MAX_INSTR_SIZE
    );

    SIZE_T replicatedAmount;
    Disassembler::EnableReplicating(replicatedBytes, MAX_INSTR_SIZE, &replicatedAmount);

    pHook->StolenBytes.Amount = (USHORT) Disassembler::Run((PBYTE) pHook->Original, sizeof(REL_INSTR));
    Disassembler::DisableReplicating();

    /* Create CALL from Trampoline to Patched function */
    PBYTE ipAfterCall = (PBYTE) pTrampoline + sizeof(REL_INSTR);
    DWORD offsetToHook = (PBYTE) pHook->Hooked - ipAfterCall;
    REL_INSTR  callHook = { 0xE8, offsetToHook };

    memcpy_s(
        pTrampoline,
        trampolineSize,
        &callHook,
        sizeof(REL_INSTR)
    );

    /* Replicate Stolen Bytes after CALL to Patched function */
    memcpy_s(
        ipAfterCall,
        replicatedAmount,
        replicatedBytes,
        replicatedAmount
    );

    /* Create JMP from Trampoline to Original function, after stolen bytes */
    PBYTE ipAfterJmp = ipAfterCall + MAX_INSTR_SIZE + sizeof(REL_INSTR);
    PBYTE ipAfterStolen = (PBYTE) pHook->Original + pHook->StolenBytes.Amount;
    DWORD offsetToOriginal = ipAfterStolen - ipAfterJmp;
    REL_INSTR jmpToOriginal = { 0xE9, offsetToOriginal };

    memcpy_s(
        ipAfterCall + MAX_INSTR_SIZE,
        sizeof(REL_INSTR),
        &jmpToOriginal,
        sizeof(REL_INSTR)
    );

    return pTrampoline;
}

void EnableHook(PHOOK_DESCRIPTOR pHook)
{
    BYTE replicatedBytes[MAX_INSTR_SIZE];

    SIZE_T replicatedAmount;
    Disassembler::EnableReplicating(replicatedBytes, MAX_INSTR_SIZE, &replicatedAmount);

    pHook->StolenBytes.Amount = (USHORT) Disassembler::Run((PBYTE) pHook->Original, sizeof(REL_INSTR));
    Disassembler::DisableReplicating();

    LPVOID pTrampoline = CreateTrampoline(pHook);

    memcpy_s(pHook->StolenBytes.Buffer, MAX_INSTR_SIZE, pHook->Original, pHook->StolenBytes.Amount);

    if (pHook->StolenBytes.Amount < sizeof(REL_INSTR))
    {
        printf("Original function is too small for patch.\n");
        exit(1);
    }

    PBYTE ipAfterJmp = (PBYTE) pHook->Original + sizeof(REL_INSTR);
    DWORD offsetToHook = (PBYTE) pTrampoline - ipAfterJmp;
    REL_INSTR jmpToHook = { 0xE9, offsetToHook };

    ProtectedWrite(pHook->Original, &jmpToHook, sizeof(REL_INSTR));
}

void DisableHook(PHOOK_DESCRIPTOR pHook)
{
    ProtectedWrite(
        pHook->Original,
        pHook->StolenBytes.Buffer,
        pHook->StolenBytes.Amount
    );

    pHook->bEnabled = FALSE;
}

void ApplyHook()
{
    FARPROC pTestFunc = GetProcAddress(GetModuleHandle(0), "TestFunc");

    PHOOK_DESCRIPTOR pHook = CreateHook(pTestFunc, &PatchedFunc);
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
