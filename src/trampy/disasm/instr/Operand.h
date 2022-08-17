#pragma once
#include "../defs.h"

/*
Each Operand has an Addressing Method attribute, as described in this enum.
An Addressing Method explains what the Operand specifies, how it should be treated, e.t.c.
*/
enum ADDRESSING_METHOD : BYTE
{
	A, B, C, D, E, F, G, H, I, J, L, M, N, O, P, Q, R, S, U, V, W, X, Y
};

/*
Each Operand has an Operand Type attribute, as described in this enum.
An Operand Type mainly defines the Operand's size.
*/
enum OPERAND_TYPE : BYTE
{
	a, b, c, d, dq, p, pd, pi, ps, q, qq, s, sd, ss, si, v, w, x, y, z
};

/*
Struct describing an Operand.
*/
typedef struct _OPERAND_DESCRIPTOR
{
	/* This Operand's Addressing Method */
	ADDRESSING_METHOD AddressingMethod;
	/* This Operand's Type */
	OPERAND_TYPE OperandType;
}
OPERAND_DESCRIPTOR, *POPERAND_DESCRIPTOR;
