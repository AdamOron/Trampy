#include "disasm.h"
#include "instr/Opcode.h"
#include "instr/ModRegRM.h"
#include "instr/SIB.h"
#include "instr/OpcodeMaps.h"
#include <stdio.h>

/* Max amount of prefixes allowed per instruction */
#define MAX_PREFIXES 4

/* Value of operand-size-override prefix */
#define OPERAND_SIZE_OVERRIDE_PREFIX 0x66

/* Cache of all prefix bytes */
const BYTE g_PrefixCache[] = { 0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65, OPERAND_SIZE_OVERRIDE_PREFIX, 0x67 };

/* Cache of all Addressing Methods that use a ModRM byte */
const ADDRESSING_METHOD g_UsesModRM[] = { E, G, M, S, C, D, N, P, Q, R, U, V, W };

/* Cache of all Addressing Methods that use immediate values */
const ADDRESSING_METHOD g_UsesImm[] = { A, I, J, O };

/*
Struct describing the state of the dissasembler.
There's a single instance of this struct and it's global, as there's only a single dissasembler running at once.
This means that disassembling cannot be multi-threaded.
*/
struct _DISASSEMBLER_STATE
{
	/*
	The machine code buffer.
	This could be a pointer to a function or anything of the sorts.
	*/
	PBYTE Buffer;
	/*
	The disassembler's instruction pointer.
	Points to the next byte to be read.
	*/
	PBYTE Ip;
	/*
	Amount of bytes that we need to disassemble.
	*/
	SIZE_T RequiredBytes;

	/*
	Struct defining an instruction.
	This instruction is the current instruction that's being disassembled.
	*/
	struct _INSTRUCTION
	{
		/*
		Pointer to the beginning of the instruction.
		*/
		PBYTE Start;
		/*
		The current size of the instruction.
		*/
		USHORT Size;
		/*
		Describes whether the instruction uses a ModRM byte or not.
		*/
		BOOL bModRM;
		/*
		Describes whether the instruction uses a SIB byte or not.
		*/
		BOOL bSib;
		/*
		The amount of prefixes used by this instruction.
		*/
		USHORT PrefixAmount;
		/*
		Describes whether the instruction uses an operand-size-override prefix.
		*/
		BOOL bOperandSizeOverride;
	} Instruction;
}
g_Disasm;

/*
Struct defining the state of the replicator.
The replicator is responsible for replicating the machine code, so it is valid & executable from its new location.
By default, the replicator is disabled.
There's a single instance of this struct and it's global.
*/
struct _REPLICATOR_STATE
{
	BOOL bEnabled;
	PBYTE Buffer;
	SIZE_T BufferSize;
	PBYTE Ip;
	OUT SIZE_T *pReplicatedAmount;
}
g_Rep = { FALSE };

/*
Enable replication of machine code.
@param repBuffer is a byte-buffer which stores the replicated code.
@param repBufferSize is the size of the replicated code's buffer.
@param pReplicatedAmount is the amount of replicated bytes.
*/
void Disassembler::EnableReplication(PBYTE repBuffer, SIZE_T repBufferSize, OUT SIZE_T *pReplicatedAmount)
{
	g_Rep = { TRUE, repBuffer, repBufferSize, repBuffer, pReplicatedAmount };
}

/*
Disables the replication.
*/
void Disassembler::DisableReplication()
{
	g_Rep.bEnabled = FALSE;
}

/*
Initialize the disassembler.
*/
void InitializeDisassembler()
{
	g_Disasm = { NULL };
}

/*
Initialize the current instruction struct.
*/
void InitializeInstruction()
{
	g_Disasm.Instruction = { g_Disasm.Ip, 0, FALSE, FALSE, 0, FALSE };
}

/*
Advance to the next X bytes.
@param byteAmount is the amount of bytes to advance, or 1 by default.
@return the IP before the advancement.
*/
PBYTE Advance(USHORT byteAmount = 1)
{
	/* Increment the instruction's size */
	g_Disasm.Instruction.Size += byteAmount;
	/* Save current IP */
	PBYTE ip = g_Disasm.Ip;
	/* Increment IP */
	g_Disasm.Ip += byteAmount;
	/* Return unincremented IP */
	return ip;
}

/*
Write given bytes to the replicate.
@param pBytes is the buffer of bytes to be written.
@param byteAmount is the amount of bytes to be written.
*/
void Replicate(PBYTE pBytes, USHORT byteAmount)
{
	/* Exit function if replication is disabled */
	if (!g_Rep.bEnabled)
		return;

	/* If buffer is too small for the bytes */
	if (g_Rep.Ip + byteAmount > g_Rep.Buffer + g_Rep.BufferSize)
	{
		/* Extend buffer through reallocation */
		g_Rep.BufferSize = max(g_Rep.BufferSize * 2, g_Rep.BufferSize + byteAmount * 2);

		/* Temporarily save previous buffer */
		PBYTE prevBuffer = g_Rep.Buffer;
		/* Reallocate extended buffer */
		do
			g_Rep.Buffer = (PBYTE) realloc(prevBuffer, g_Rep.BufferSize);
		while (!g_Rep.Buffer);
	}

	/* Copy given bytes to the replicate buffer */
	memcpy_s(g_Rep.Ip, byteAmount, pBytes, byteAmount);
	/* Increment replicate's IP */
	g_Rep.Ip += byteAmount;
}

/*
Advance both the disassembler & the replicate.
Copys the advanced bytes to the replicate.
@param byteAmount is the amount of bytes to advance.
@return the IP before the advancement.
*/
PBYTE AdvanceAndRep(USHORT byteAmount = 1)
{
	Replicate(g_Disasm.Ip, byteAmount);
	return Advance(byteAmount);
}

/*
@return whether current byte is a prefix or not.
*/
bool IsPrefix()
{
	BYTE current = *g_Disasm.Ip;

	/* Iterate over all prefix bytes in cache */
	for (BYTE prefix : g_PrefixCache)
	{
		/* If prefix matchs current byte, return true */
		if (prefix == current)
			return TRUE;
	}

	/* Return false, we found no prefix byte */
	return FALSE;
}

/*
Parse all following prefixes, if there are any.
*/
void ParsePrefixes()
{
	USHORT maxPrefixes = MAX_PREFIXES;
	/*
	There can only be MAX_PREFIXES prefixes.
	Once current byte isn't a prefix, the following bytes won't be prefixes as well.
	*/
	while (maxPrefixes-- && IsPrefix())
	{
		/* Get prefix & advance to next byte */
		BYTE prefix = *AdvanceAndRep();

		/* If current prefix byte is the opreand-size-override prefix */
		if (prefix == OPERAND_SIZE_OVERRIDE_PREFIX /* 0x66 */)
			/* Mark the instruction */
			g_Disasm.Instruction.bOperandSizeOverride = TRUE;

		/* Increment instruction's prefix amount */
		g_Disasm.Instruction.PrefixAmount++;
	}
}

/*
Consume SIB byte if we haven't already.
*/
void AddSIB()
{
	if (g_Disasm.Instruction.bSib)
		return;

	g_Disasm.Instruction.bSib = TRUE;
	AdvanceAndRep();
}

/*
Parse ModRM byte of current instruction.
*/
void ParseModRM()
{
	/* Create pointer to MOD_REG_RM struct, which is the byte after the opcode (the opcode comes after all prefixes) */
	const PMOD_REG_RM pModRM = (const PMOD_REG_RM) (g_Disasm.Instruction.Start + g_Disasm.Instruction.PrefixAmount + 1);

	/* If RM specifies the SP register, and the instruction isn't Reg-to-Reg, we have a SIB */
	if (pModRM->Rm == RM_SP /* 100b */ &&
		pModRM->Mod != MOD_REG)
		AddSIB();

	switch (pModRM->Mod)
	{
	case MOD_DISP8:
		/* If we're in 8-bit displacement mode, consume 1 byte (8 bits) */
		AdvanceAndRep();
		break;

	case MOD_NODISP:
		if (pModRM->Rm != RM_BP /* 101b */)
			break;
		/* If we're in no-displacement mode & RM specifies BP, we have a 32-bit displacement-only instruction */
	case MOD_DISP32:
		/* If we're in 32-bit displacement mode, consume 4 bytes (32 bits) */
		AdvanceAndRep(4);
		break;
	}
}

/*
Add ModRM byte, if it hasn't already been added.
This function also makes sure the ModRM byte is parsed.
*/
void AddModRM()
{
	if (g_Disasm.Instruction.bModRM)
		return;

	g_Disasm.Instruction.bModRM = TRUE;
	AdvanceAndRep();

	ParseModRM();
}

/*
Check if the operand descriptor specifies usage of a ModRM byte.
@param pOperand is the operand to be checked.
@return whether given operand uses ModRM or not.
*/
bool IsModRM(const OPERAND_DESCRIPTOR *pOperand)
{
	/* Iterate over all Operand Addressing Methods that are known to use ModRM */
	for (ADDRESSING_METHOD addrMethod : g_UsesModRM)
		/* If operand's Addressing Method matches, it uses ModRM */
		if (addrMethod == pOperand->AddressingMethod)
			return TRUE;

	return FALSE;
}

/*
Check if the operand descriptor specifies usage of an immediate operand.
@param pOperand is the operand to be checked.
@return whether given operand is immediate or not.
*/
bool IsImm(const OPERAND_DESCRIPTOR *pOperand)
{
	/* Iterate over all Operand Addressing Methods that are known to use immediates */
	for (ADDRESSING_METHOD addrMethod : g_UsesImm)
		/* If operand's Addressing Method matches, it is immediate */
		if (addrMethod == pOperand->AddressingMethod)
			return TRUE;

	return FALSE;
}

/*
Calculates size of operand, considering prefixes as well.
@param pOperad, the operand to be checked.
@return size of given operand, in bytes.
*/
USHORT OperandSize(const OPERAND_DESCRIPTOR *pOperand)
{
	bool operandSizeOverride = g_Disasm.Instruction.bOperandSizeOverride;

	/* Addressing Method of O disregards the Operand Type attribute */
	if (pOperand->AddressingMethod == O)
		return operandSizeOverride ? WORD_SIZE : DWORD_SIZE;

	/*
	Return size depending on the Operand Type.
	Some types are affected by the operand-size-override prefix.
	*/
	switch (pOperand->OperandType)
	{
	case b:
		return BYTE_SIZE;
	case c:
		return operandSizeOverride ? BYTE_SIZE : WORD_SIZE;
	case d:
		return DWORD_SIZE;
	case p:
		return WORD_SIZE /* pointer prefix */ + (operandSizeOverride ? WORD_SIZE : DWORD_SIZE) /* pointer suffix */;
	case v:
		return operandSizeOverride ? WORD_SIZE : DWORD_SIZE;
	case w:
		return WORD_SIZE;
	case z:
		return operandSizeOverride ? WORD_SIZE : DWORD_SIZE;
	}

	/* If no match found, throw error */
	printf("***Unrecognized Operand: %d***\n", pOperand->OperandType);
	exit(1);
	return 0;
}

/*
Checks how many bytes are required to represent signed number.
@return minimum amount of bytes required to represent number.
*/
USHORT RequiredBytes(int64_t number)
{
	if (number == (int8_t) (number & 0xFF))
		return BYTE_SIZE;

	if (number == (int16_t) (number & 0xFFFF))
		return WORD_SIZE;

	if (number == (int32_t) (number & 0xFFFFFFFF))
		return DWORD_SIZE;

	return QWORD_SIZE;
}

/*
Replicates a Relative Address & patches it, so it's valid and working from the replicated buffer.
This function is called when the IP points at a Relative Address operand.
*/
void ReplicateRA(USHORT operandSize)
{
	/*
	TODO: Before offsetting relative address, check if we're jumping outside replicated bytes.
	If the address we're jumping to is also replicated, we shouldn't offset the address.
	This is difficult right now, because we need to know the size of the entire instruction to calculate the address we're jumping to.
	*/

	if (!g_Rep.bEnabled)
		return;

	/* First, calculate the offset from the replicate's IP to the original IP */
	int32_t fixedRa = g_Disasm.Ip - g_Rep.Ip;;

	/* Add to the offset the actual Relative Address */
	switch(operandSize)
	{
	case BYTE_SIZE:
		fixedRa += *(int8_t *) g_Disasm.Ip;
		break;

	case WORD_SIZE:
		fixedRa += *(int16_t *) g_Disasm.Ip;
		break;

	case DWORD_SIZE:
		fixedRa += *(int32_t *) g_Disasm.Ip;
		break;

	default:
		printf("Unsupported Relative-Address Operand Size: %d\n", operandSize);
		exit(1);
		break;
	}

	/*
	If the amount of bytes required to represent the relative address are larger than the operand's size,
	we are unable to save the relative offset. This will actually probably never happen, as assemblers
	automatically use the E9 opcode (which takes a DWORD as parameter), rather than EB for example (which takes a BYTE as parameter).
	*/
	if (RequiredBytes(fixedRa) > operandSize)
	{
		printf("**** JMP is too large for given operand size. ****\n");
		exit(1);
	}

	/* Write to the replicate the new offseted Relative Address */
	Replicate((PBYTE) &fixedRa, operandSize);
}

/*
Parse an operand.
*/
void ParseOperand(const OPERAND_DESCRIPTOR *pOperand)
{
	/* If operand uses ModRM byte, parse it */
	if (IsModRM(pOperand))
		AddModRM();

	/* If operand is immediate, parse it */
	if (IsImm(pOperand))
	{
		USHORT operandSize = OperandSize(pOperand);

		/* If operand is a Relative Address */
		if (pOperand->AddressingMethod == J)
		{
			/* Replicate the Relative Address properly */
			ReplicateRA(operandSize);
			Advance(operandSize);
		}
		else
		{
			AdvanceAndRep(operandSize);
		}
	}
}

/*
Parse all operands of an opcode.
@param opcode is the opcode to be parsed.
*/
void ParseOperands(BYTE opcode)
{
	/* Get Opcode Descriptor from the Opcode Map */
	const OPCODE_DESCRIPTOR *pOpcodeEntry = &g_OpcodeMap[opcode];
	/* Iterate over all operands in the descriptor */
	for (USHORT i = 0; i < pOpcodeEntry->OperandAmount; i++)
		/* Parse operand */
		ParseOperand(&pOpcodeEntry->Operands[i]);
}

/*
Parse entire instruction.
*/
void ParseInstruction()
{
	/* Initialize instruction struct */
	InitializeInstruction();
	/* Parse prefix bytes */
	ParsePrefixes();
	/* Consume opcode */
	PBYTE pOpcode = AdvanceAndRep();
	/* Parse all opcode operands */
	ParseOperands(*pOpcode);
}

/*
Disassemble & replicate given bytes of machine code.
@param buffer is the buffer of machine code that'll be disassembled & replicated.
@param requiredBytes is the amount of bytes we want.
The disassembler will return the minimum size of complete instructions, which is greater than this value.
@return minimum size of complete instructions, which is greater than the required amount of bytes.
*/
SIZE_T Disassembler::Run(PBYTE buffer, SIZE_T requiredBytes)
{
	/* Initialize the disassembler */
	InitializeDisassembler();
	g_Disasm.Buffer = buffer;
	g_Disasm.RequiredBytes = requiredBytes;
	g_Disasm.Ip = buffer;

	/* Initialize the instruction size */
	SIZE_T instrBytes = 0;
	/* As long as parsed instruction size is smaller than required amount of bytes */
	while (instrBytes < requiredBytes)
	{
		/* Parse next instruction */
		ParseInstruction();
		/* Add the parseed instruction's size */
		instrBytes += g_Disasm.Instruction.Size;
	}

	/* If replication is enabeld */
	if (g_Rep.bEnabled)
		/* Update amount of written bytes */
		*g_Rep.pReplicatedAmount = g_Rep.Ip - g_Rep.Buffer;

	return instrBytes;
}
