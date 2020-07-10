#include "global.h"

namespace HookBypass {
	DWORD gamepid = 0;
	HANDLE hGame = NULL;
	void SetGamepid(DWORD pid) {
		gamepid = pid;
	}
	BOOL UnhookMethod(const char* methodName, const char* dllName, PBYTE save_origin_bytes) {
		if (hGame == NULL) {
			hGame = OpenProcess(PROCESS_ALL_ACCESS,FALSE,gamepid);
			if (!hGame) return FALSE;
		}
		LPVOID oriMethodAddr = GetProcAddress(LoadLibraryA(dllName),methodName);
		if (!oriMethodAddr) return FALSE;
		PBYTE originalGameBytes[6];
		ReadProcessMemory(hGame,oriMethodAddr,originalGameBytes,sizeof(char)*6,NULL);
		memcpy_s(save_origin_bytes, sizeof(char) * 6, originalGameBytes, sizeof(char) * 6);
		PBYTE originalDllBytes[6];
		memcpy_s(originalDllBytes, sizeof(char) * 6,oriMethodAddr, sizeof(char) * 6);
		return WriteProcessMemory(hGame, oriMethodAddr, originalDllBytes, sizeof(char) * 6, NULL);
	}
	BOOL RestoreOriginalHook(const char* methodName,const char* dllName, PBYTE save_origin_bytes) {
		if (hGame == NULL) {
			hGame = OpenProcess(PROCESS_ALL_ACCESS, FALSE, gamepid);
			if (!hGame) return FALSE;
		}
		LPVOID oriMethodAddr = GetProcAddress(LoadLibraryA(dllName), methodName);
		if (!oriMethodAddr) return FALSE;
		return WriteProcessMemory(hGame, oriMethodAddr, save_origin_bytes, sizeof(char) * 6, NULL);
	}
	enum MethodNum{
		LOADLIBEXW = 1,
		VIRALLOC = 2,
		FREELIB = 3,
		LOADLIBEXA = 4,
		LOADLIBW = 5,
		LOADLIBA = 6,
		VIRALLOCEX = 7,
		LDRLOADDLL = 10,
		NTOPENFILE = 11,
		VIRPROT = 12,
		CREATPROW = 13,
		CREATPROA = 14,
		VIRPROTEX = 15,
		FREELIB_ = 16,
		LOADLIBEXA_ = 17,
		LOADLIBEXW_ = 18,
		RESUMETHREAD = 19,
	};
	BYTE originalGameBytess[30][6];
	BOOL BypassCSGO_hook() {
		BOOL res = TRUE;
		res &= UnhookMethod("LoadLibraryExW","kernel32", originalGameBytess[LOADLIBEXW]);
		res &= UnhookMethod("VirtualAlloc", "kernel32", originalGameBytess[VIRALLOC]);
		res &= UnhookMethod("FreeLibrary", "kernel32", originalGameBytess[FREELIB]);
		res &= UnhookMethod("LoadLibraryExA", "kernel32", originalGameBytess[LOADLIBEXA]);
		res &= UnhookMethod("LoadLibraryW", "kernel32", originalGameBytess[LOADLIBW]);
		res &= UnhookMethod("LoadLibraryA", "kernel32", originalGameBytess[LOADLIBA]);
		res &= UnhookMethod("VirtualAllocEx", "kernel32", originalGameBytess[VIRALLOCEX]);
		res &= UnhookMethod("LdrLoadDll", "ntdll", originalGameBytess[LDRLOADDLL]);
		res &= UnhookMethod("NtOpenFile", "ntdll", originalGameBytess[NTOPENFILE]);
		res &= UnhookMethod("VirtualProtect", "kernel32", originalGameBytess[VIRPROT]);
		res &= UnhookMethod("CreateProcessW", "kernel32", originalGameBytess[CREATPROW]);
		res &= UnhookMethod("CreateProcessA", "kernel32", originalGameBytess[CREATPROA]);
		res &= UnhookMethod("VirtualProtectEx", "kernel32", originalGameBytess[VIRPROTEX]);
		res &= UnhookMethod("FreeLibrary", "KernelBase", originalGameBytess[FREELIB_]);
		res &= UnhookMethod("LoadLibraryExA", "KernelBase", originalGameBytess[LOADLIBEXA_]);
		res &= UnhookMethod("LoadLibraryExW", "KernelBase", originalGameBytess[LOADLIBEXW_]);
		res &= UnhookMethod("ResumeThread", "KernelBase", originalGameBytess[RESUMETHREAD]);
		return res;
	}
	BOOL RestoreCSGO_hook() {
		BOOL res = TRUE;
		res &= RestoreOriginalHook("LoadLibraryExW", "kernel32", originalGameBytess[LOADLIBEXW]);
		res &= RestoreOriginalHook("VirtualAlloc", "kernel32", originalGameBytess[VIRALLOC]);
		res &= RestoreOriginalHook("FreeLibrary", "kernel32", originalGameBytess[FREELIB]);
		res &= RestoreOriginalHook("LoadLibraryExA", "kernel32", originalGameBytess[LOADLIBEXA]);
		res &= RestoreOriginalHook("LoadLibraryW", "kernel32", originalGameBytess[LOADLIBW]);
		res &= RestoreOriginalHook("LoadLibraryA", "kernel32", originalGameBytess[LOADLIBA]);
		res &= RestoreOriginalHook("VirtualAllocEx", "kernel32", originalGameBytess[VIRALLOCEX]);
		res &= RestoreOriginalHook("LdrLoadDll", "ntdll", originalGameBytess[LDRLOADDLL]);
		res &= RestoreOriginalHook("NtOpenFile", "ntdll", originalGameBytess[NTOPENFILE]);
		res &= RestoreOriginalHook("VirtualProtect", "kernel32", originalGameBytess[VIRPROT]);
		res &= RestoreOriginalHook("CreateProcessW", "kernel32", originalGameBytess[CREATPROW]);
		res &= RestoreOriginalHook("CreateProcessA", "kernel32", originalGameBytess[CREATPROA]);
		res &= RestoreOriginalHook("VirtualProtectEx", "kernel32", originalGameBytess[VIRPROTEX]);
		res &= RestoreOriginalHook("FreeLibrary", "KernelBase", originalGameBytess[FREELIB_]);
		res &= RestoreOriginalHook("LoadLibraryExA", "KernelBase", originalGameBytess[LOADLIBEXA_]);
		res &= RestoreOriginalHook("LoadLibraryExW", "KernelBase", originalGameBytess[LOADLIBEXW_]);
		res &= RestoreOriginalHook("ResumeThread", "KernelBase", originalGameBytess[RESUMETHREAD]);
		return res;
	}
}