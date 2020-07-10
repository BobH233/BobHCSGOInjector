/*
	CSGO_Bypass_Injector
	Author: BobH
	QQ: 1551608379
	Website: https://bobh.mkaliez.com/
	Time: 2020.07.10
*/
#include "global.h"

DWORD GetGamePID() {
	HWND hwGame = FindWindowA(0, "Counter-Strike: Global Offensive");
	if (!hwGame) return 0;
	DWORD ret = 0;
	GetWindowThreadProcessId(hwGame,&ret);
	return ret;
}

std::string Lpcwstr2String(LPCWSTR lps) {
	int len = WideCharToMultiByte(CP_ACP, 0, lps, -1, NULL, 0, NULL, NULL);
	if (len <= 0) {
		return "";
	}
	else {
		char* dest = new char[len];
		WideCharToMultiByte(CP_ACP, 0, lps, -1, dest, len, NULL, NULL);
		dest[len - 1] = 0;
		std::string str(dest);
		delete[] dest;
		return str;
	}
}
std::string SelectDll() {
	OPENFILENAME ofn;
	char szFile[300];
	ZeroMemory(&ofn, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = NULL;
	ofn.lpstrFile = (LPWSTR)szFile;
	ofn.lpstrFile[0] = '\0';
	LPTSTR        lpstrCustomFilter;
	DWORD         nMaxCustFilter;
	ofn.nFilterIndex = 1;
	LPTSTR        lpstrFile;
	ofn.nMaxFile = sizeof(szFile);
	ofn.lpstrFilter = L"DLL File\0*.dll";
	ofn.lpstrFileTitle = NULL;
	ofn.nMaxFileTitle = 0;
	ofn.lpstrInitialDir = NULL;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
	std::string path_image = "";
	if (GetOpenFileName(&ofn)) {
		path_image = Lpcwstr2String(ofn.lpstrFile);
		return path_image;
	}
	else {
		return "";
	}
}
void InjectDll(const char* path,DWORD pid) {
	HANDLE hGame = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
	char dllpath[MAX_PATH];
	ZeroMemory(dllpath, sizeof(dllpath));
	strcpy_s(dllpath,path);
	LPVOID allocatedMem = VirtualAllocEx(hGame, NULL, sizeof(dllpath), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(hGame, allocatedMem, dllpath, sizeof(dllpath), NULL);
	HANDLE hThread = CreateRemoteThread(hGame, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, allocatedMem, 0, 0);
	WaitForSingleObject(hThread, INFINITE);
	VirtualFreeEx(hGame, allocatedMem, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
}
int main()
{
	DWORD gamePID = GetGamePID();
	if (!gamePID) {
		MessageBoxA(0,"Can not find game!","Please launch the game!",0);
		return 0;
	}
	HookBypass::SetGamepid(gamePID);
	std::string dllpath = SelectDll();
	if (dllpath == "") {
		MessageBoxA(0, "No dll file selected!", "Please selected a dll file.", 0);
		return 0;
	}
	if (!HookBypass::BypassCSGO_hook()) {
		MessageBoxA(0,"Filed to bypass VAC hook!","Filed to bypass VAC hook!",0);
		return 0;
	}
	InjectDll(dllpath.c_str(), gamePID);
	HookBypass::RestoreCSGO_hook();
	MessageBoxA(0,"Inject Successfully!","BobHInjector",0);
	return 0;
}
