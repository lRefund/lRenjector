/*It used to be Manual Mapping, but now it’s Load Library. You’d better create your own Manual Mapping.*/
#include "injector.h"
#include <windows.h>
#include <string>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <algorithm>

using namespace std;

bool LoadLibraryInject(HANDLE hProc, const wstring& dllPath) {
    if (!hProc || dllPath.empty()) {
        return false;
    }

    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
    if (!loadLibraryAddr) {
        return false;
    }

    size_t pathSize = (dllPath.length() + 1) * sizeof(wchar_t);
    LPVOID remoteDllPath = VirtualAllocEx(hProc, NULL, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteDllPath) {
        return false;
    }

    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProc, remoteDllPath, dllPath.c_str(), pathSize, &bytesWritten) ||
        bytesWritten != pathSize) {
        VirtualFreeEx(hProc, remoteDllPath, 0, MEM_RELEASE);
        return false;
    }

    HANDLE hRemoteThread = CreateRemoteThread(
        hProc,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)loadLibraryAddr,
        remoteDllPath,
        0,
        NULL
    );

    if (!hRemoteThread) {
        VirtualFreeEx(hProc, remoteDllPath, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(hRemoteThread, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeThread(hRemoteThread, &exitCode);

    CloseHandle(hRemoteThread);
    VirtualFreeEx(hProc, remoteDllPath, 0, MEM_RELEASE);

    if (exitCode == 0) {
        return false;
    }

    return true;
}

bool InjectIntoRunningProcessLL(DWORD processId, const wstring& dllPath) {
    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE,
        processId
    );

    if (!hProc) {
        return false;
    }

    bool result = LoadLibraryInject(hProc, dllPath);
    CloseHandle(hProc);
    return result;
}

bool CreateAndInjectLL(const wstring& exePath, const wstring& dllPath, DWORD* outProcessId) {
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    wstring commandLine = L"\"" + exePath + L"\"";

    if (!CreateProcessW(
        NULL,
        (LPWSTR)commandLine.c_str(),
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi
    )) {
        return false;
    }
    if (outProcessId) {
        *outProcessId = pi.dwProcessId;
    }

    bool result = LoadLibraryInject(pi.hProcess, dllPath);

    if (result) {
        ResumeThread(pi.hThread);
    }
    else {
        TerminateProcess(pi.hProcess, 0);
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return result;

}
