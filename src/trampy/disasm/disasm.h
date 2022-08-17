#pragma once
#include "../TrampyDefs.h"

namespace Disassembler
{
	/*
	Enable replication of machine code.
	@param repBuffer is a byte-buffer which stores the replicated code.
	@param repBufferSize is the size of the replicated code's buffer.
	*/
	void EnableReplication(
		PBYTE repBuffer,
		SIZE_T repBufferSize,
		OUT SIZE_T *pReplicatedAmount
	);
	/*
	Disables the replication.
	*/
	void DisableReplication();

	/*
	Disassemble & replicate given bytes of machine code.
	@param buffer is the buffer of machine code that'll be disassembled & replicated.
	@param requiredBytes is the amount of bytes we want.
	The disassembler will return the minimum size of complete instructions, which is greater than this value.
	@return minimum size of complete instructions, which is greater than the required amount of bytes.
	*/
	SIZE_T Run(PBYTE buffer, SIZE_T requiredBytes);
}
