#pragma once
#include "../TrampyDefs.h"

/*
Specifies Base of the Scaled Index.
This value is added as an initial offset (i.e. SIB = [Base + ...].
*/
enum class BASE : BYTE
{
	/* EAX register */
	BASE_A = 0b000,
	/* ECX register */
	BASE_C = 0b001,
	/* EDX register */
	BASE_D = 0b010,
	/* EBX register */
	BASE_B = 0b011,
	/* ESP register */
	BASE_SP = 0b100,
	/*
	If Mod specifies no displacement (00b), don't use BP, only 32-bit displacement (i.e. [SIB] + disp32).
	If Mod specifies 8/32-bit displacement (01b/10b), combine displacement with BP (i.e. [SIB] + disp8/32 + [EBP]).
	If Mod specifies a register as Effective Address (11b), SIB won't be used eitherways.
	*/
	BASE_BP = 0b101,
	/* ESI register */
	BASE_SI = 0b110,
	/* EDI register */
	BASE_DI = 0b111,
};

/*
Specifies Index relative to the Base.
This Index is added to the base offset (i.e. SIB = [Base + Index ...]).
*/
enum class INDEX : BYTE
{
	IDX_A = 0b000,
	IDX_C = 0b001,
	IDX_D = 0b010,
	IDX_B = 0b011,
	IDX_BP = 0b101,
	IDX_SI = 0b110,
	IDX_DI = 0b111,
};

/*
Specifies Scale for the Index.
This Scale is multiplied by the index value (i.e. SIB = [Base + Index * Scale]).
*/
enum SCALE : BYTE
{
	/* Scale Index by 1 (i.e. [Index * 1] */
	SCL_1 = 0b00,
	/* Scale Index by 2 (i.e. [Index * 2] */
	SCL_2 = 0b01,
	/* Scale Index by 4 (i.e. [Index * 4] */
	SCL_4 = 0b10,
	/* Scale Index by 8 (i.e. [Index * 8] */
	SCL_8 = 0b11,
};

/*
The SIB byte comes after the ModRM byte (if there is one).
It is used to specify a scaled indexed addressing mode.
*/
typedef struct _SIB
{
	/* Least-significant 3 bits specify the Base field (8 possibilities) */
	BASE Base : 3;
	/* Next 3 bits specify the Index field (8 possibilities) */
	INDEX Index : 3;
	/* Most-significant 2 bits specify the Scale (4 possibilities) */
	SCALE Scale : 2;
}
SIB, *PSIB;
