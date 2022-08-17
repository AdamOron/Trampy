#pragma once
#include "Operand.h"

/* The maximum amount of operands for any opcode is 3 */
#define MAX_OPERANDS 3

/*
Struct describing an opcode.
Each opcode receives some amount of operands.
*/
typedef struct _OPCODE_DESCRIPTOR
{
	USHORT OperandAmount;
	OPERAND_DESCRIPTOR Operands[MAX_OPERANDS];
}
OPCODE_DESCRIPTOR, *POPCODE_DESCRIPTOR;
