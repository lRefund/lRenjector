#ifndef INJECTOR_H
#define INJECTOR_H

#include <windows.h>
#include <string>

using namespace std;
bool LoadLibraryInject(HANDLE hProc, const wstring& dllPath);
bool InjectIntoRunningProcessLL(DWORD processId, const wstring& dllPath);
bool CreateAndInjectLL(const wstring& exePath, const wstring& dllPath, DWORD* outProcessId = nullptr);

#endif