#pragma once
#include "../defs.h"

/*
The RM field specifies a register that's in-use.
In some cases, specific registers are used to specify some other addressing method.
*/
enum RM : BYTE
{
	RM_A = 0b000,
	RM_C = 0b001,
	RM_D = 0b010,
	RM_B = 0b011,
	RM_SP = 0b100,
	RM_BP = 0b101,
	RM_SI = 0b110,
	RM_DI = 0b111,
};

/*
The Reg field specifies a register that's in use.
In some cases, specific registers are used to specify some other addressing method.
*/
enum REG : BYTE
{
	REG_A = 0b000,
	REG_C = 0b001,
	REG_D = 0b010,
	REG_B = 0b011,
	REG_SP = 0b100,
	REG_BP = 0b101,
	REG_SI = 0b110,
	REG_DI = 0b111,
};

/*
Specifies Addressing Mode.
The Effective Address is calculated differently, depending on this Mod field.
*/
enum MOD : BYTE
{
	/*
	Effective Address is stored in given register, no displacement (i.e. [EAX], [ECX]).
	Said register is specified in R/M field.
	If R/M specifies SP (100b), Effective Address is ONLY SIB.
	If R/M specifies BP (101b), Effective Address is ONLY 32-bit displacement.
	*/
	MOD_NODISP = 0b00,
	/*
	Effective Address is combination of register & 8-bit displacement (i.e. [EAX] + disp8, [ECX] + disp8).
	Said register is specified in R/M field.
	If R/M specifies SP (100b), base-register is replaced with SIB (i.e. [SIB] + disp8, not [ESP] + disp8).
	*/
	MOD_DISP8 = 0b01,
	/*
	Effective Address is combination of register & 32-bit displacement (i.e. [EAX] + disp32, [ECX] + disp32).
	Said register is specified in R/M field.
	If R/M specifies SP (100b), base-register is replaced with SIB (i.e. [SIB] + disp32, not [ESP] + disp32).
	*/
	MOD_DISP32 = 0b10,
	/*
	Effective Address is a register (i.e. EAX itself, not [EAX]).
	Said register is specified in R/M field.
	*/
	MOD_REG = 0b11,
};

/*
The ModRM byte comes after the instruction's opcode.
It specifies the addressing method, registers, e.t.c.
*/
typedef struct _MOD_REG_RM
{
	/* Least-significant 3 bits define the RM field (8 possibilities) */
	RM Rm : 3;
	/* Next 3 bits define the Reg field (8 possibilities) */
	REG Reg : 3;
	/* Most-significant 2 bits define the Mod field (4 possibilities) */
	MOD Mod : 2;
}
MOD_REG_RM, *PMOD_REG_RM;
