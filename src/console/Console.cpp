#include "Console.h"
#include <Windows.h>
#include <stdio.h>

void CreateConsole()
{
	AllocConsole();
	AttachConsole(GetCurrentProcessId());
	(void) freopen_s((FILE **) stdout, "CON", "w", stdout);
}

void CloseConsole()
{
	FreeConsole();
}
