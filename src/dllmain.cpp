#include <Windows.h>
#include "Console.h"
#include <stdio.h>
#include <vector>
#include "hooklib/disasm/disasm.h"

using Signature = void (__cdecl *) (int);

Signature g_TestFunc = NULL;

extern "C" __declspec(dllexport)
void __cdecl PatchedFunc(int a)
{
    printf("I am the Patched: %d\n", a);

    g_TestFunc(10);
}

#pragma pack(push, 1)
typedef struct _INSTR_SINGLE_OP
{
    BYTE Opcode;
    DWORD Operand;
}
INSTR_SINGLE_OP, *PINSTR_SINGLE_OP;
#pragma pack(pop)

#define MAX_INSTR_SIZE 15

typedef struct _HOOK_DESCRIPTOR
{
    BOOL bEnabled;
    LPVOID pOriginal;
    LPVOID pHooked;
    LPVOID *ppTrampoline;

    struct
    {
        BYTE Buffer[MAX_INSTR_SIZE];
        SIZE_T Amount;
    }
    StolenBytes;
}
HOOK_DESCRIPTOR, *PHOOK_DESCRIPTOR;

std::vector<HOOK_DESCRIPTOR> g_Hooks;

PHOOK_DESCRIPTOR CreateHook(LPVOID pOriginal, LPVOID pPatched, LPVOID *ppTrampoline)
{
    g_Hooks.push_back({ });

    PHOOK_DESCRIPTOR pHook = &g_Hooks.back();
    pHook->bEnabled = FALSE;
    pHook->pOriginal = pOriginal;
    pHook->pHooked = pPatched;
    pHook->ppTrampoline = ppTrampoline;

    return pHook;
}

/*
Write into protected memory region.
@param pDest, the destination of our data.
@param pSrc, the data we want to write.
@param byteAmount, the amount of bytes we want to write.
*/
void ProtectedWrite(LPVOID pDest, LPVOID pSrc, SIZE_T byteAmount)
{
    DWORD oldProtect;
    /* Make protected destination writable */
    if (VirtualProtect(
        pDest,
        byteAmount,
        PAGE_EXECUTE_READWRITE,
        &oldProtect
    ))
    {
        // Error
    }

    /* Copy bytes from from source to destination */
    if (memcpy_s(
        pDest,
        byteAmount,
        pSrc,
        byteAmount
    ))
    {
        // Error
    }

    /* Make protected destination writable again */
    if (VirtualProtect(
        pDest,
        byteAmount,
        oldProtect,
        &oldProtect
    ))
    {
        // Error
    }
}

/*
Disassembles Original function of given Hook.
Replicates Original instructions into Trampoline of Hook.
@param pHook, the Hook's descriptor.
@param pTrampoline, the Trampoline function pointer.
@return the amount of bytes replicated (i.e. written into Trampoline).
*/
SIZE_T DisassembleAndReplicate(PHOOK_DESCRIPTOR pHook, PBYTE pTrampoline)
{
    /* Make disassembler replicate instructions into Trampoline */
    SIZE_T replicatedAmount;
    Disassembler::EnableReplication(pTrampoline, MAX_INSTR_SIZE, &replicatedAmount);
    /* Run disassembler, ensure enough bytes are disassembled for a JMP instruction */
    pHook->StolenBytes.Amount = Disassembler::Run((PBYTE) pHook->pOriginal, sizeof(INSTR_SINGLE_OP));
    /* Disable replication */
    Disassembler::DisableReplication();
    /* Return replicated amount */
    return replicatedAmount;
}

/*
Write JMP instruction from Trampoline to Original, following the replicated instructions in Trampoline.
@param pHook the Hook's descriptor.
@param pTrampoline the Trampoline function pointer.
*/
void WriteJmpToOriginal(PHOOK_DESCRIPTOR pHook, PBYTE pTrampoline, SIZE_T replicatedAmount)
{
    /* IP in Trampoline after executing replicated bytes */
    PBYTE ipAfterReplicated = pTrampoline + replicatedAmount;
    /* IP in Trampoline after executing replicated bytes & after JMP to Original */
    PBYTE ipAfterJmp = ipAfterReplicated + sizeof(INSTR_SINGLE_OP);
    /* IP in Original after stolen bytes, where the rest of the function exists */
    PBYTE ipAfterStolen = (PBYTE) pHook->pOriginal + pHook->StolenBytes.Amount;
    /* Offset from Trampoline to Original, used to continue execution of Original */
    DWORD offsetToOriginal = ipAfterStolen - ipAfterJmp;
    /* Write JMP instruction after replicated bytes */
    *(PINSTR_SINGLE_OP) ipAfterReplicated = { 0xE9 /* JMP*/, offsetToOriginal};
}

LPVOID CreateTrampoline(PHOOK_DESCRIPTOR pHook)
{
    /* Allocate memory for Trampoline Function */
    SIZE_T trampolineSize = MAX_INSTR_SIZE + sizeof(INSTR_SINGLE_OP);
    LPVOID pTrampoline = VirtualAlloc(NULL, trampolineSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    /* If failed to allocate Trampoline Function, throw error */
    if (!pTrampoline)
    {
        printf("Failed to create Trampoline Function: VirtualAlloc returned NULL.\n");
        return NULL;
    }

    /* Disassemble Original & replicate instructions into Trampoline */
    SIZE_T replicatedAmount = DisassembleAndReplicate(pHook, (PBYTE) pTrampoline);

    /* Write JMP instruction to Original from Trampoline, after replicated bytes */
    WriteJmpToOriginal(pHook, (PBYTE) pTrampoline, replicatedAmount);

    /* Make Trampoline Function executable & read-only */
    DWORD oldProtect;
    VirtualProtect(
        /* Start at Trampoline's base */
        pTrampoline,
        /* Protect entire Trampoline function */
        trampolineSize,
        /* Make Trampoline executable & read-only (read-only is good practice for functions) */
        PAGE_EXECUTE_READ,
        /* Save old protection to variable (required) */
        &oldProtect
    );

    return pTrampoline;
}

/*
Backups to-be-stolen bytes from Original to buffer.
@param pHook, the Hook's descriptor.
*/
void BackupStolenBytes(PHOOK_DESCRIPTOR pHook)
{
    /* Backup Stolen Bytes into buffer before overwriting */
    memcpy_s(
        /* Copy into Stolen Bytes buffer */
        pHook->StolenBytes.Buffer,
        /* The size of the Stolen Bytes buffer */
        sizeof(pHook->StolenBytes.Buffer) /* MAX_INSTR_SIZE */,
        /* Copy bytes from the Original function */
        pHook->pOriginal,
        /* Copy only the required amount of bytes */
        pHook->StolenBytes.Amount
    );
}

/*
Write JMP instruction from base of Original to Hook.
@param pHook, the Hook's descriptor.
*/
void WriteJmpToHook(PHOOK_DESCRIPTOR pHook)
{
    /* IP in Original after this JMP instruction */
    PBYTE ipAfterJmp = (PBYTE) pHook->pOriginal + sizeof(INSTR_SINGLE_OP);
    /* Offset from Original to Hooked function */
    DWORD offsetToHook = (PBYTE) pHook->pHooked - ipAfterJmp;
    /* JMP from Original to Hook */
    INSTR_SINGLE_OP jmpToHook = { 0xE9 /* JMP */, offsetToHook};
    /* Write the JMP instruction to the beginning of Original, with proper protection */
    ProtectedWrite(pHook->pOriginal, &jmpToHook, sizeof(INSTR_SINGLE_OP));
}

void EnableHook(PHOOK_DESCRIPTOR pHook)
{
    *pHook->ppTrampoline = CreateTrampoline(pHook);

    if (pHook->StolenBytes.Amount < sizeof(INSTR_SINGLE_OP))
    {
        printf("Failed to hook function: Original function was too small (5 bytes minimum).\n");
        return;
    }

    BackupStolenBytes(pHook);

    WriteJmpToHook(pHook);
}

void DisableHook(PHOOK_DESCRIPTOR pHook)
{
    ProtectedWrite(
        pHook->pOriginal,
        pHook->StolenBytes.Buffer,
        pHook->StolenBytes.Amount
    );

    pHook->bEnabled = FALSE;
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
