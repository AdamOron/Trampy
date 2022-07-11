#include "hook.h"
#include <vector>

/*
The maximum size of a single instruction.
Including prefixes, opcode, opreands, e.t.c.
*/
#define MAX_INSTR_SIZE 15

/*
The opcode for a JMP.
This is a relative-JMP, with a 4-byte relative-address operand.
*/
#define JMP_OPCODE 0xE9

/*
Struct describing a Hook.
*/
typedef struct _HOOK_DESCRIPTOR
{
    /*
    Is the Hook enabled.
    */
    BOOL bEnabled;
    /*
    Pointer to the Hook's Original function.
    */
    LPVOID pOriginal;
    /*
    Pointer to the Hook's Hook function.
    */
    LPVOID pHooked;
    /*
    Pointer to the target Trampoline function.
    Once created, this pointer will direct to the Trampoline.
    */
    LPVOID *ppTrampoline;

    /*
    Anonymous struct defining a StolenBytes buffer.
    */
    struct
    {
        /*
        The byte-buffer itself, with a capacity of MAX_INSTR_SIZE,
        as we won't need to steal more than a single instruction.
        */
        BYTE Buffer[MAX_INSTR_SIZE];
        /*
        The amount of stolen bytes stored in the buffer.
        */
        SIZE_T Amount;
    }
    StolenBytes;
}
HOOK_DESCRIPTOR, *PHOOK_DESCRIPTOR;

std::vector<HOOK_DESCRIPTOR> g_Hooks;

/*
Struct defining a single-operand instruction (e.g. JMPs, CALLs, e.t.c).
This struct is not padded, its size is exactly 5 bytes.
*/
#pragma pack(push, 1)
typedef struct _INSTR_SINGLE_OP
{
    /*
    This instruction's opcode.
    */
    BYTE Opcode;
    /*
    This instruction's operand.
    Assumes it's a 4-byte (DWORD) operand.
    */
    DWORD Operand;
}
INSTR_SINGLE_OP, *PINSTR_SINGLE_OP;
#pragma pack(pop)

/*
Creates a Hook desriptor.
@param pOriginal, pointer to the original function.
@param pHooked, pointer to the hooked function.
@param ppTrampoline, pointer to the destination trampoline function.
@return pointer to the newly created Hook within the Hook list.
*/
PHOOK_DESCRIPTOR CreateHook(LPVOID pOriginal, LPVOID pHooked, LPVOID *ppTrampoline)
{
    /* Push empty HOOK_DESCRIPTOR to Hook list */
    g_Hooks.push_back({ });

    /* Extract pointer to newly created Hook */
    PHOOK_DESCRIPTOR pHook = &g_Hooks.back();
    /* Initialize newly created Hook */
    pHook->bEnabled = FALSE;
    pHook->pOriginal = pOriginal;
    pHook->pHooked = pHooked;
    pHook->ppTrampoline = ppTrampoline;

    /* Return pointer to newly created Hook */
    return pHook;
}

/*
Write into protected memory region.
@param pDest, the destination of our data.
@param pSrc, the data we want to write.
@param byteAmount, the amount of bytes we want to write.
@return TRUE if the function succeeds, FALSE if it fails.
*/
BOOL ProtectedWrite(LPVOID pDest, LPVOID pSrc, SIZE_T byteAmount)
{
    DWORD oldProtect;
    /*
    Make protected destination writable.
    If VirtualProtect returns FALSE, it failed.
    */
    if (!VirtualProtect(
        pDest,
        byteAmount,
        PAGE_EXECUTE_READWRITE,
        &oldProtect
    ))
    {
        printf("ProtectedWrite failed: VirtualProtect returned FALSE.\n");
        return FALSE;
    }

    /*
    Copy bytes from from source to destination.
    If memcpy_s returns non-zero, it failed.
    */
    if (memcpy_s(
        pDest,
        byteAmount,
        pSrc,
        byteAmount
    ))
    {
        printf("ProtectedWrite failed: memcpy_s returned non-zero.\n");
        return FALSE;
    }

    /*
    Revert protection change.
    If VirtualProtect returns FALSE, it failed.
    */
    if (!VirtualProtect(
        pDest,
        byteAmount,
        oldProtect,
        &oldProtect
    ))
    {
        printf("ProtectedWrite failed: VirtualProtect returned FALSE.\n");
        return FALSE;
    }

    return TRUE;
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
    *(PINSTR_SINGLE_OP) ipAfterReplicated = { JMP_OPCODE, offsetToOriginal };
}

/*
Creates Trampoline function.
@param pHook, the Hook's descriptor.
@return pointer to the created Trampoline function, or FALSE if the function failed.
*/
LPVOID CreateTrampoline(PHOOK_DESCRIPTOR pHook)
{
    /* Allocate memory for Trampoline Function */
    SIZE_T trampolineSize = MAX_INSTR_SIZE + sizeof(INSTR_SINGLE_OP);
    LPVOID pTrampoline = VirtualAlloc(NULL, trampolineSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    /* If failed to allocate Trampoline Function, throw error */
    if (!pTrampoline)
    {
        printf("CreateTrampoline failed: VirtualAlloc returned NULL.\n");
        return NULL;
    }

    /* Disassemble Original & replicate instructions into Trampoline */
    SIZE_T replicatedAmount = DisassembleAndReplicate(pHook, (PBYTE) pTrampoline);

    /* Write JMP instruction to Original from Trampoline, after replicated bytes */
    WriteJmpToOriginal(pHook, (PBYTE) pTrampoline, replicatedAmount);

    /*
    Make Trampoline Function executable & read-only.
    If VirtualProtect returns FALSE, it failed.
    */
    DWORD oldProtect;
    if (!VirtualProtect(
        /* Start at Trampoline's base */
        pTrampoline,
        /* Protect entire Trampoline function */
        trampolineSize,
        /* Make Trampoline executable & read-only (read-only is good practice for functions) */
        PAGE_EXECUTE_READ,
        /* Save old protection to variable (required) */
        &oldProtect
    ))
    {
        printf("CreateTrampoline failed: VirtualProtect returned FALSE.\n");
        return NULL;
    }

    return pTrampoline;
}

/*
Backups to-be-stolen bytes from Original to buffer.
@param pHook, the Hook's descriptor.
@return TRUE if the function succeeds, FALSE if it fails.
*/
BOOL BackupStolenBytes(PHOOK_DESCRIPTOR pHook)
{
    /*
    Backup Stolen Bytes into buffer before overwriting.
    If memcpy_s returns non-zero, it failed.
    */
    return !memcpy_s(
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
@return TRUE if the function succeeds, FALSE if it fails.
*/
BOOL WriteJmpToHook(PHOOK_DESCRIPTOR pHook)
{
    /* IP in Original after this JMP instruction */
    PBYTE ipAfterJmp = (PBYTE) pHook->pOriginal + sizeof(INSTR_SINGLE_OP);
    /* Offset from Original to Hooked function */
    DWORD offsetToHook = (PBYTE) pHook->pHooked - ipAfterJmp;
    /* JMP from Original to Hook */
    INSTR_SINGLE_OP jmpToHook = { JMP_OPCODE, offsetToHook };
    /*
    Write the JMP instruction to the beginning of Original, with proper protection.
    If ProtectedWrite fails, WriteJmpToHook fails.
    */
    return ProtectedWrite(
        /* Write to beginning of Original */
        pHook->pOriginal,
        /* Write the JMP instruction */
        &jmpToHook,
        /* The size of the JMP instruction */
        sizeof(jmpToHook)
    );
}

/*
Enable the Hook, i.e. make it functional.
@param pHook, the Hook's descriptor.
@return TRUE if the function succeeds, FALSE if it fails.
*/
BOOL EnableHook(PHOOK_DESCRIPTOR pHook)
{
    /* Create Trampoline function, save pointer to it */
    LPVOID pTrampoline = CreateTrampoline(pHook);

    /* If CreateTrampoline fails, EnableHook fails */
    if (!pTrampoline)
        return FALSE;

    *pHook->ppTrampoline = pTrampoline;

    /* If stolen byte amount is smaller than a JMP instruction, we can't patch */
    if (pHook->StolenBytes.Amount < sizeof(INSTR_SINGLE_OP))
    {
        printf("Failed to hook function: Original function was too small (5 bytes minimum).\n");
        return FALSE;
    }

    /*
    Backup to-be-stolen bytes at the beginning of Original.
    If BackupStolenBytes fails, EnableHook fails.
    */
    if (!BackupStolenBytes(pHook))
        return FALSE;

    /*
    Write JMP from Original to Hook (overwrites first bytes in Original).
    If WriteJmpToHook fails, EnableHook fails.
    */
    if (!WriteJmpToHook(pHook))
        return FALSE;

    return TRUE;
}

/*
Disable the Hook, i.e. revert to original state.
@param pHook, the Hook's descriptor.
@return TRUE if the Hook was succesfully disabled, FALSE otherwise.
*/
BOOL DisableHook(PHOOK_DESCRIPTOR pHook)
{
    /* If Hook isn't enabled, don't disable it */
    if (pHook->bEnabled)
        return FALSE;

    /*
    Write stolen bytes to Original.
    If ProtectedWrite fails, DisableHook fails.
    */
    if (!ProtectedWrite(
        pHook->pOriginal,
        pHook->StolenBytes.Buffer,
        pHook->StolenBytes.Amount
    ))
    {
        return FALSE;
    }

    pHook->bEnabled = FALSE;

    return TRUE;
}
