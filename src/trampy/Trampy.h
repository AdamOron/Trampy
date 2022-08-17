#pragma once
#include <Windows.h>

/*
Definition of the Hook's descriptor struct.
*/
typedef struct _HOOK_DESCRIPTOR
HOOK_DESCRIPTOR, *PHOOK_DESCRIPTOR;

/*
Keep all Trampy-related functions in their own namespace.
This is convenient for the user.
*/
namespace Trampy
{
	/*
	Creates a Hook desriptor.
	@param pOriginal, pointer to the original function.
	@param pHooked, pointer to the hooked function.
	@param ppTrampoline, pointer to the destination trampoline function.
	@return pointer to the newly created Hook within the Hook list.
	*/
	PHOOK_DESCRIPTOR CreateHook(LPVOID pOriginal, LPVOID pHooked, LPVOID *ppTrampoline);

	/*
	Enable the Hook, i.e. make it functional.
	@param pHook, the Hook's descriptor.
	@return TRUE if the function succeeds, FALSE if it fails.
	*/
	BOOL EnableHook(PHOOK_DESCRIPTOR pHook);
	/*
	Enable all Hooks, i.e. make them all functional.
	@return TRUE if all Hooks were enabled successfully, FALSE otherwise.
	*/
	BOOL EnableAllHooks();

	/*
	Disable the Hook, i.e. revert to original state.
	@param pHook, the Hook's descriptor.
	@return TRUE if the Hook was succesfully disabled, FALSE otherwise.
	*/
	BOOL DisableHook(PHOOK_DESCRIPTOR pHook);
	/*
	Disable all Hooks, i.e. revert to original state.
	@return TRUE if all Hooks were disabled successfully, FALSE otherwise.
	*/
	BOOL DisableAllHooks();
}
