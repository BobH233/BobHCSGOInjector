#include <Windows.h>
#include <iostream>
#include <string>

namespace HookBypass {
	void SetGamepid(DWORD pid);
	BOOL BypassCSGO_hook();
	BOOL RestoreCSGO_hook();
}