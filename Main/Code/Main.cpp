#define DISABLE_OUTPUT
#include "injector.h"

#include <stdio.h>
#include <string>
#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <commdlg.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <iphlpapi.h>
#include <intrin.h>
#include <vector>
#include <shellapi.h>
#include <winhttp.h>
#include <conio.h>
#include <chrono>
#include <random>
#include <thread>
#include <atomic>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "winhttp.lib")

using namespace std;

wstring GetDllPath(const wstring& dllName);

struct InjectorSettings {
    bool enableProcessMonitoring = true;
};

InjectorSettings g_settings;

struct GameInfo {
    wstring name;
    wstring exeName;
    wstring dllName;
    wstring path;
    bool isCustom;
    bool isConfigured;
};

vector<GameInfo> games = {
    {L"Game 1", L"Game.exe", L"Dll.dll", L"", false, false},
    {L"Game 2", L"Game.exe", L"Dll.dll", L"", false, false},
    {L"Custom Game", L"", L"", L"", true, false}
};

HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

const wstring WEBHOOK_URL = L"https://discord.com/api/webhooks/...";

atomic<bool> g_monitoringEnabled(false);
thread g_monitorThread;
atomic<bool> g_genshinRunning(false);
atomic<DWORD> g_genshinProcessId(0);
chrono::system_clock::time_point g_genshinStartTime;

wstring GetExeDirectory() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileName(NULL, exePath, MAX_PATH);
    wstring exeDir = exePath;
    size_t pos = exeDir.find_last_of(L"\\/");
    if (pos != wstring::npos) {
        return exeDir.substr(0, pos);
    }
    return L"";
}

string GetHWID() {
    string hwid;

    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 1);
    hwid += to_string(cpuInfo[0]) + to_string(cpuInfo[2]) + to_string(cpuInfo[3]);

    IP_ADAPTER_INFO adapterInfo[16];
    DWORD dwBufLen = sizeof(adapterInfo);
    if (GetAdaptersInfo(adapterInfo, &dwBufLen) == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapterInfo = adapterInfo;
        if (pAdapterInfo) {
            for (UINT i = 0; i < pAdapterInfo->AddressLength; i++) {
                char mac[3];
                sprintf_s(mac, "%.2X", pAdapterInfo->Address[i]);
                hwid += mac;
            }
        }
    }

    DWORD serialNumber;
    if (GetVolumeInformationA("C:\\", NULL, 0, &serialNumber, NULL, NULL, NULL, 0)) {
        hwid += to_string(serialNumber);
    }

    hwid.resize(32, '0');
    hwid = hwid.substr(0, 32);

    return hwid;
}

wstring GetCurrentTimestamp() {
    auto now = chrono::system_clock::now();
    auto time_t = chrono::system_clock::to_time_t(now);
    tm tm;
    localtime_s(&tm, &time_t);

    wstringstream ss;
    ss << put_time(&tm, L"%Y-%m-%d %H:%M:%S");
    return ss.str();
}

wstring FormatDuration(long long seconds) {
    long long hours = seconds / 3600;
    long long minutes = (seconds % 3600) / 60;
    long long secs = seconds % 60;

    wstringstream ss;
    if (hours > 0) {
        ss << hours << L"h ";
    }
    if (minutes > 0 || hours > 0) {
        ss << minutes << L"m ";
    }
    ss << secs << L"s";
    return ss.str();
}

wstring GetSystemInfo() {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    wstringstream ss;

    HKEY hKey;
    DWORD buildNumber = 0;
    DWORD bufSize = sizeof(DWORD);

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {

        RegQueryValueEx(hKey, L"CurrentBuildNumber", NULL, NULL,
            (LPBYTE)&buildNumber, &bufSize);
        RegCloseKey(hKey);
    }

    if (buildNumber >= 22000) {
        ss << L"Windows 11";
    }
    else if (buildNumber >= 10240) {
        ss << L"Windows 10";
    }
    else if (buildNumber >= 9600) {
        ss << L"Windows 8.1";
    }
    else if (buildNumber >= 9200) {
        ss << L"Windows 8";
    }
    else if (buildNumber >= 7600) {
        ss << L"Windows 7";
    }
    else {
        ss << L"Windows";
    }

    ss << L" (Build " << buildNumber << L")";
    ss << L" | CPU Cores: " << sysInfo.dwNumberOfProcessors;
    ss << L" | Architecture: ";

    if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
        ss << L"x64";
    else if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
        ss << L"x86";
    else if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64)
        ss << L"ARM64";
    else
        ss << L"Unknown";

    return ss.str();
}

void LoadSettings() {
    wstring settingsFile = GetExeDirectory() + L"\\settings.cfg";
    ifstream file(settingsFile);
    if (!file.is_open()) {
        return;
    }

    string line;
    while (getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;

        size_t pos = line.find('=');
        if (pos != string::npos) {
            string key = line.substr(0, pos);
            string value = line.substr(pos + 1);

            if (key == "enable_process_monitoring") {
                g_settings.enableProcessMonitoring = (value == "1" || value == "true");
            }
        }
    }
    file.close();
}

void SaveSettings() {
    wstring settingsFile = GetExeDirectory() + L"\\settings.cfg";
    ofstream file(settingsFile);
    if (!file.is_open()) return;

    file << "# lRenjector Settings" << endl;
    file << "enable_process_monitoring=" << (g_settings.enableProcessMonitoring ? "1" : "0") << endl;

    file.close();
}

bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;

    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        if (!CheckTokenMembership(NULL, adminGroup, &isAdmin)) {
            isAdmin = FALSE;
        }
        FreeSid(adminGroup);
    }

    return isAdmin == TRUE;
}

bool SendDiscordWebhook(const wstring& title, const wstring& description, const vector<pair<wstring, wstring>>& fields) {
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;

    bool success = false;

    try {
        hSession = WinHttpOpen(L"lRenjector",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);

        if (!hSession) {
            throw runtime_error("WinHttpOpen failed");
        }

        URL_COMPONENTS urlComp;
        ZeroMemory(&urlComp, sizeof(urlComp));
        urlComp.dwStructSize = sizeof(urlComp);

        wchar_t hostName[256] = { 0 };
        wchar_t urlPath[2048] = { 0 };

        urlComp.lpszHostName = hostName;
        urlComp.dwHostNameLength = (DWORD)(sizeof(hostName) / sizeof(wchar_t));
        urlComp.lpszUrlPath = urlPath;
        urlComp.dwUrlPathLength = (DWORD)(sizeof(urlPath) / sizeof(wchar_t));

        if (!WinHttpCrackUrl(WEBHOOK_URL.c_str(), (DWORD)WEBHOOK_URL.length(), 0, &urlComp)) {
            throw runtime_error("WinHttpCrackUrl failed");
        }

        hConnect = WinHttpConnect(hSession, hostName, INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hConnect) {
            throw runtime_error("WinHttpConnect failed");
        }

        hRequest = WinHttpOpenRequest(hConnect, L"POST", urlPath,
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE);
        if (!hRequest) {
            throw runtime_error("WinHttpOpenRequest failed");
        }

        wstringstream json;
        json << L"{";
        json << L"\"embeds\": [{";
        json << L"\"title\": \"" << title << L"\",";
        json << L"\"description\": \"" << description << L"\",";
        json << L"\"color\": 16711680,";
        json << L"\"timestamp\": \"" << GetCurrentTimestamp() << L"\",";
        json << L"\"fields\": [";

        for (size_t i = 0; i < fields.size(); i++) {
            json << L"{";
            json << L"\"name\": \"" << fields[i].first << L"\",";
            json << L"\"value\": \"" << fields[i].second << L"\",";
            json << L"\"inline\": true";
            json << L"}";
            if (i < fields.size() - 1) {
                json << L",";
            }
        }

        json << L"]";
        json << L"}]";
        json << L"}";

        wstring jsonStr = json.str();
        string jsonUtf8;

        int utf8Size = WideCharToMultiByte(CP_UTF8, 0, jsonStr.c_str(), -1, NULL, 0, NULL, NULL);
        if (utf8Size > 0) {
            vector<char> utf8Buffer(utf8Size);
            WideCharToMultiByte(CP_UTF8, 0, jsonStr.c_str(), -1, utf8Buffer.data(), utf8Size, NULL, NULL);
            jsonUtf8 = utf8Buffer.data();
        }

        wstring headers = L"Content-Type: application/json; charset=utf-8";

        if (!WinHttpSendRequest(hRequest,
            headers.c_str(), (DWORD)headers.length(),
            (LPVOID)jsonUtf8.c_str(), (DWORD)jsonUtf8.length(),
            (DWORD)jsonUtf8.length(), 0)) {
            throw runtime_error("WinHttpSendRequest failed");
        }

        if (!WinHttpReceiveResponse(hRequest, NULL)) {
            throw runtime_error("WinHttpReceiveResponse failed");
        }

        success = true;

    }
    catch (const exception& e) {
        success = false;
    }

    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    return success;
}

void SendStartupWebhook() {
    string hwid = GetHWID();
    wstring whwid(hwid.begin(), hwid.end());

    vector<pair<wstring, wstring>> fields = {
        {L"HWID", whwid},
        {L"System Info", GetSystemInfo()},
        {L"Admin Rights", IsRunningAsAdmin() ? L"Yes" : L"No"},
        {L"Startup Time", GetCurrentTimestamp()},
        {L"Process Monitoring", g_settings.enableProcessMonitoring ? L"Enabled" : L"Disabled"}
    };

    SendDiscordWebhook(L"Injector Started", L"Injector launched", fields);
}

void SendProcessStartWebhook(DWORD processId, const wstring& processName, const wstring& processPath) {
    string hwid = GetHWID();
    wstring whwid(hwid.begin(), hwid.end());

    vector<pair<wstring, wstring>> fields = {
        {L"Process Name", processName},
        {L"Process ID", to_wstring(processId)},
        {L"Process Path", processPath},
        {L"HWID", whwid},
        {L"Start Time", GetCurrentTimestamp()},
        {L"Monitoring Type", L"Automatic"}
    };

    SendDiscordWebhook(L"Process Started", L"Genshin Impact process has been detected", fields);
}

void SendProcessStopWebhook(DWORD processId, const wstring& processName, long long runtimeSeconds) {
    string hwid = GetHWID();
    wstring whwid(hwid.begin(), hwid.end());

    vector<pair<wstring, wstring>> fields = {
        {L"Process Name", processName},
        {L"Process ID", to_wstring(processId)},
        {L"Runtime", FormatDuration(runtimeSeconds)},
        {L"HWID", whwid},
        {L"Stop Time", GetCurrentTimestamp()},
        {L"Monitoring Type", L"Automatic"}
    };

    SendDiscordWebhook(L"Process Stopped", L"Genshin Impact process has been terminated", fields);
}

void SendInjectionStartWebhook(int gameIndex) {
    if (gameIndex < 0 || gameIndex >= (int)games.size()) return;

    string hwid = GetHWID();
    wstring whwid(hwid.begin(), hwid.end());

    vector<pair<wstring, wstring>> fields = {
        {L"Game", games[gameIndex].name},
        {L"HWID", whwid},
        {L"Injection Start Time", GetCurrentTimestamp()},
        {L"Game Path", games[gameIndex].path},
        {L"DLL Name", games[gameIndex].dllName},
        {L"Admin Rights", IsRunningAsAdmin() ? L"Yes" : L"No"}
    };

    SendDiscordWebhook(L"Injection Started", L"Injection process initiated for " + games[gameIndex].name, fields);
}

void SendInjectionProgressWebhook(int gameIndex, const wstring& step, const wstring& details = L"") {
    if (gameIndex < 0 || gameIndex >= (int)games.size()) return;

    string hwid = GetHWID();
    wstring whwid(hwid.begin(), hwid.end());

    vector<pair<wstring, wstring>> fields = {
        {L"Game", games[gameIndex].name},
        {L"Step", step},
        {L"HWID", whwid},
        {L"Time", GetCurrentTimestamp()}
    };

    if (!details.empty()) {
        fields.push_back({ L"Details", details });
    }

    SendDiscordWebhook(L"Injection Progress", L"Step: " + step, fields);
}

void SendInjectionWebhook(int gameIndex, bool success, const wstring& errorMsg, const wstring& additionalInfo) {
    if (gameIndex < 0 || gameIndex >= (int)games.size()) return;

    string hwid = GetHWID();
    wstring whwid(hwid.begin(), hwid.end());

    vector<pair<wstring, wstring>> fields = {
        {L"Game", games[gameIndex].name},
        {L"HWID", whwid},
        {L"Injection Time", GetCurrentTimestamp()},
        {L"Status", success ? L"Successful" : L"Failed"},
        {L"Game Path", games[gameIndex].path},
        {L"DLL Path", GetDllPath(games[gameIndex].dllName)},
        {L"System Info", GetSystemInfo()}
    };

    if (!success && !errorMsg.empty()) {
        fields.push_back({ L"Error", errorMsg });
    }

    if (!additionalInfo.empty()) {
        fields.push_back({ L"Additional Info", additionalInfo });
    }

    wstring title = success ? L"Injection Successful" : L"Injection Failed";
    wstring description = success ?
        L"Successfully injected " + games[gameIndex].name :
        L"Failed to inject " + games[gameIndex].name;

    SendDiscordWebhook(title, description, fields);
}

void SendHWIDWebhook() {
    string hwid = GetHWID();
    wstring whwid(hwid.begin(), hwid.end());

    vector<pair<wstring, wstring>> fields = {
        {L"HWID", whwid},
        {L"Request Time", GetCurrentTimestamp()},
        {L"System Info", GetSystemInfo()}
    };

    SendDiscordWebhook(L"HWID Requested", L"User requested their HWID", fields);
}

void SendGameSelectedWebhook(int gameIndex) {
    if (gameIndex < 0 || gameIndex >= (int)games.size()) return;

    string hwid = GetHWID();
    wstring whwid(hwid.begin(), hwid.end());

    vector<pair<wstring, wstring>> fields = {
        {L"Game", games[gameIndex].name},
        {L"HWID", whwid},
        {L"Selection Time", GetCurrentTimestamp()},
        {L"Game Path", games[gameIndex].path},
        {L"EXE Name", games[gameIndex].exeName}
    };

    SendDiscordWebhook(L"Game Selected", L"User selected a game for injection", fields);
}

void SendFileCheckWebhook(int gameIndex, const wstring& filePath, bool exists, DWORD fileSize = 0) {
    if (gameIndex < 0 || gameIndex >= (int)games.size()) return;

    string hwid = GetHWID();
    wstring whwid(hwid.begin(), hwid.end());

    vector<pair<wstring, wstring>> fields = {
        {L"Game", games[gameIndex].name},
        {L"File Path", filePath},
        {L"File Exists", exists ? L"Yes" : L"No"},
        {L"HWID", whwid},
        {L"Check Time", GetCurrentTimestamp()}
    };

    if (exists && fileSize > 0) {
        wstringstream sizeStr;
        sizeStr << fileSize << L" bytes";
        fields.push_back({ L"File Size", sizeStr.str() });
    }

    SendDiscordWebhook(L"File Check", L"File existence check: " + filePath, fields);
}

void SendProcessCreationWebhook(int gameIndex, DWORD processId, bool success, const wstring& errorMsg = L"") {
    if (gameIndex < 0 || gameIndex >= (int)games.size()) return;

    string hwid = GetHWID();
    wstring whwid(hwid.begin(), hwid.end());

    vector<pair<wstring, wstring>> fields = {
        {L"Game", games[gameIndex].name},
        {L"Process ID", to_wstring(processId)},
        {L"Success", success ? L"Yes" : L"No"},
        {L"HWID", whwid},
        {L"Time", GetCurrentTimestamp()},
        {L"Game Path", games[gameIndex].path}
    };

    if (!success && !errorMsg.empty()) {
        fields.push_back({ L"Error", errorMsg });
    }

    SendDiscordWebhook(L"Process Creation", L"Process creation attempt for " + games[gameIndex].name, fields);
}

void SendSettingsChangedWebhook(const wstring& settingName, const wstring& oldValue, const wstring& newValue) {
    string hwid = GetHWID();
    wstring whwid(hwid.begin(), hwid.end());

    vector<pair<wstring, wstring>> fields = {
        {L"Setting", settingName},
        {L"Old Value", oldValue},
        {L"New Value", newValue},
        {L"HWID", whwid},
        {L"Change Time", GetCurrentTimestamp()}
    };

    SendDiscordWebhook(L"Settings Changed", L"User changed application settings", fields);
}

bool IsProcessRunning(const wstring& processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &pe)) {
        CloseHandle(hSnapshot);
        return false;
    }

    bool found = false;
    do {
        if (_wcsicmp(pe.szExeFile, processName.c_str()) == 0) {
            found = true;
            g_genshinProcessId = pe.th32ProcessID;
            break;
        }
    } while (Process32NextW(hSnapshot, &pe));

    CloseHandle(hSnapshot);
    return found;
}

wstring GetProcessPath(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess) {
        wchar_t path[MAX_PATH];
        DWORD pathSize = MAX_PATH;
        if (QueryFullProcessImageNameW(hProcess, 0, path, &pathSize)) {
            CloseHandle(hProcess);
            return wstring(path);
        }
        CloseHandle(hProcess);
    }
    return L"Unknown";
}

wstring GetLastErrorString() {
    DWORD error = GetLastError();
    if (error == 0) {
        return L"No error";
    }

    LPWSTR buffer = nullptr;
    DWORD size = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&buffer,
        0,
        NULL);

    if (size == 0 || buffer == nullptr) {
        return L"Unknown error";
    }

    wstring message(buffer);
    LocalFree(buffer);
    return message;
}

void MonitorGenshinProcess() {
    bool wasRunning = false;
    chrono::system_clock::time_point startTime;

    while (g_monitoringEnabled) {
        bool isRunning = IsProcessRunning(L"GenshinImpact.exe");

        if (isRunning && !wasRunning) {
            startTime = chrono::system_clock::now();
            g_genshinStartTime = startTime;
            g_genshinRunning = true;

            wstring processPath = GetProcessPath(g_genshinProcessId);
            SendProcessStartWebhook(g_genshinProcessId, L"GenshinImpact.exe", processPath);

            wasRunning = true;
        }
        else if (!isRunning && wasRunning) {
            g_genshinRunning = false;
            auto endTime = chrono::system_clock::now();
            auto duration = endTime - startTime;
            auto runtimeSeconds = chrono::duration_cast<chrono::seconds>(duration).count();

            SendProcessStopWebhook(g_genshinProcessId, L"GenshinImpact.exe", runtimeSeconds);

            wasRunning = false;
            g_genshinProcessId = 0;
        }

        this_thread::sleep_for(chrono::seconds(2));
    }
}

void StartProcessMonitoring() {
    if (g_settings.enableProcessMonitoring && !g_monitoringEnabled) {
        g_monitoringEnabled = true;
        g_monitorThread = thread(MonitorGenshinProcess);
    }
}

void StopProcessMonitoring() {
    if (g_monitoringEnabled) {
        g_monitoringEnabled = false;
        if (g_monitorThread.joinable()) {
            g_monitorThread.join();
        }
    }
}

void RestartAsAdmin() {
    wchar_t modulePath[MAX_PATH];
    GetModuleFileName(NULL, modulePath, MAX_PATH);

    SHELLEXECUTEINFO shellInfo = { 0 };
    shellInfo.cbSize = sizeof(SHELLEXECUTEINFO);
    shellInfo.lpVerb = L"runas";
    shellInfo.lpFile = modulePath;
    shellInfo.nShow = SW_SHOWNORMAL;

    ShellExecuteEx(&shellInfo);
    exit(0);
}

void ClearScreen() {
    system("cls");
}

void SetCursorPosition(int x, int y) {
    COORD coord = { (SHORT)x, (SHORT)y };
    SetConsoleCursorPosition(hConsole, coord);
}

void PrintCentered(const wstring& text, int line) {
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hConsole, &csbi);
    int center = (csbi.srWindow.Right - csbi.srWindow.Left + 1) / 2;
    int textLength = (int)text.length();
    SetCursorPosition(center - textLength / 2, line);
    wcout << text;
}

void PrintLeft(const wstring& text, int line, int indent = 2) {
    SetCursorPosition(indent, line);
    wcout << text;
}

void PrintStatus(const wstring& status, bool success = true) {
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hConsole, &csbi);
    int currentLine = csbi.dwCursorPosition.Y;

    SetCursorPosition(2, currentLine);
    wcout << wstring(60, L' ');

    SetCursorPosition(2, currentLine);
    if (success) {
        SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);
        wcout << L"[+] " << status;
    }
    else {
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
        wcout << L"[-] " << status;
    }
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

wstring GetDllPath(const wstring& dllName) {
    if (dllName.find(L':') != wstring::npos || dllName.find(L"\\\\") == 0) {
        return dllName;
    }

    wstring dllDir = GetExeDirectory() + L"\\Dll\\";
    CreateDirectory(dllDir.c_str(), NULL);
    return dllDir + dllName;
}

void UpdateGameConfigurationStatus() {
    for (auto& game : games) {
        if (game.isCustom) {
            game.isConfigured = !game.path.empty() && GetFileAttributes(game.path.c_str()) != INVALID_FILE_ATTRIBUTES;
        }
        else {
            wstring dllPath = GetDllPath(game.dllName);
            game.isConfigured = !game.path.empty() &&
                GetFileAttributes(game.path.c_str()) != INVALID_FILE_ATTRIBUTES &&
                GetFileAttributes(dllPath.c_str()) != INVALID_FILE_ATTRIBUTES;
        }
    }
}

void LoadGamePaths() {
    wstring settingsFile = GetExeDirectory() + L"\\settings.cfg";
    ifstream file(settingsFile);
    if (!file.is_open()) {
        return;
    }

    string line;
    while (getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;

        if (line.find("game_") == 0) {
            size_t pos = line.find('=');
            if (pos != string::npos) {
                string key = line.substr(0, pos);
                string value = line.substr(pos + 1);

                if (key.find("game_") == 0) {
                    size_t underscore = key.find('_', 5);
                    if (underscore != string::npos) {
                        string gameNumStr = key.substr(5, underscore - 5);
                        string field = key.substr(underscore + 1);

                        try {
                            int gameIndex = stoi(gameNumStr);
                            if (gameIndex >= 0 && gameIndex < (int)games.size()) {
                                wstring wvalue(value.begin(), value.end());

                                if (field == "path") {
                                    games[gameIndex].path = wvalue;
                                }
                                else if (field == "exeName" && games[gameIndex].isCustom) {
                                    games[gameIndex].exeName = wvalue;
                                }
                                else if (field == "dllName" && games[gameIndex].isCustom) {
                                    games[gameIndex].dllName = wvalue;
                                }
                            }
                        }
                        catch (...) {
                        }
                    }
                }
            }
        }
    }
    file.close();
    UpdateGameConfigurationStatus();
}

void SaveGamePaths() {
    wstring settingsFile = GetExeDirectory() + L"\\settings.cfg";

    vector<string> lines;
    ifstream infile(settingsFile);
    if (infile.is_open()) {
        string line;
        while (getline(infile, line)) {
            if (line.find("game_") != 0) {
                lines.push_back(line);
            }
        }
        infile.close();
    }

    ofstream file(settingsFile);
    if (!file.is_open()) return;

    for (const auto& line : lines) {
        file << line << endl;
    }

    file << "# Game configurations" << endl;
    for (int i = 0; i < (int)games.size(); i++) {
        if (!games[i].path.empty()) {
            string pathStr(games[i].path.begin(), games[i].path.end());
            file << "game_" << i << "_path=" << pathStr << endl;

            if (games[i].isCustom) {
                string exeNameStr(games[i].exeName.begin(), games[i].exeName.end());
                string dllNameStr(games[i].dllName.begin(), games[i].dllName.end());
                file << "game_" << i << "_exeName=" << exeNameStr << endl;
                file << "game_" << i << "_dllName=" << dllNameStr << endl;
            }
        }
    }

    file.close();
    UpdateGameConfigurationStatus();
}

void ShowInjectionProgress(int gameIndex) {
    if (gameIndex < 0 || gameIndex >= (int)games.size()) return;

    ClearScreen();
    PrintCentered(L"INJECTION (LoadLibrary)", 2);

    if (!games[gameIndex].isConfigured) {
        PrintStatus(L"Game is not configured!", false);
        PrintLeft(L"Please configure the game before injecting.", 5);
        PrintLeft(L"Press any key to continue...", 7);
        _getwch();
        return;
    }

    wstring dllPath = GetDllPath(games[gameIndex].dllName);
    bool dllExists = false;
    DWORD fileSize = 0;
    WIN32_FILE_ATTRIBUTE_DATA fileInfo;

    if (GetFileAttributesEx(dllPath.c_str(), GetFileExInfoStandard, &fileInfo)) {
        dllExists = true;
        fileSize = fileInfo.nFileSizeLow;
    }

    SendInjectionStartWebhook(gameIndex);
    SendFileCheckWebhook(gameIndex, dllPath, dllExists, fileSize);

    if (!dllExists) {
        PrintStatus(L"DLL file not found!", false);
        PrintLeft(L"Path: " + dllPath, 5);
        PrintLeft(L"Press any key to continue...", 7);
        SendInjectionWebhook(gameIndex, false, L"DLL file not found", L"Path: " + dllPath);
        _getwch();
        return;
    }

    TOKEN_PRIVILEGES priv = { 0 };
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        priv.PrivilegeCount = 1;
        priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid)) {
            AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);
        }
        CloseHandle(hToken);
    }

    int line = 4;
    PrintLeft(L"Starting suspended process...", line);
    SendInjectionProgressWebhook(gameIndex, L"Creating suspended process");

    DWORD processId = 0;
    bool injected = CreateAndInjectLL(games[gameIndex].path, dllPath, &processId);
    SendProcessCreationWebhook(gameIndex, processId, injected, injected ? L"" : GetLastErrorString());

    if (injected) {
        PrintStatus(L"Injection via LoadLibrary succeeded", true);
        SendInjectionProgressWebhook(gameIndex, L"LoadLibrary injection completed", L"Process ID: " + to_wstring(processId));
        SendInjectionWebhook(gameIndex, true, L"", L"Process ID: " + to_wstring(processId) + L", DLL Size: " + to_wstring(fileSize));

        line += 3;
        PrintLeft(L"Process resumed. The game should start momentarily.", line);
        PrintLeft(L"Returning to main menu in 3 seconds...", line + 2);
        for (int i = 3; i > 0; i--) {
            SetCursorPosition(2, line + 3);
            wcout << L"Returning in " << i << L"..." << wstring(10, L' ');
            Sleep(1000);
        }
    }
    else {
        PrintStatus(L"Injection failed!", false);
        PrintLeft(L"Error: " + GetLastErrorString(), line + 2);
        SendInjectionProgressWebhook(gameIndex, L"LoadLibrary injection failed", L"Process ID: " + to_wstring(processId));
        SendInjectionWebhook(gameIndex, false, L"LoadLibrary injection failed", L"Process ID: " + to_wstring(processId));
        PrintLeft(L"Press any key to continue...", line + 4);
        _getwch();
    }
}

void ShowInjectionMenu() {
    ClearScreen();
    PrintCentered(L"START INJECTION", 2);

    int line = 4;
    vector<int> availableGames;

    for (int i = 0; i < (int)games.size(); i++) {
        if (games[i].isConfigured) {
            wstring menuItem = to_wstring(availableGames.size() + 1) + L". " + games[i].name;
            if (games[i].isCustom) {
                menuItem += L" (" + games[i].exeName + L")";
            }
            PrintLeft(menuItem, line++);
            availableGames.push_back(i);
        }
    }

    if (availableGames.empty()) {
        PrintLeft(L"No games configured! Please select games first.", 6);
        PrintLeft(L"Press any key to continue...", 8);
        _getwch();
        return;
    }

    PrintLeft(L"0. Back", line + 1);
    SetCursorPosition(2, line + 3);
    wcout << L"Select game to inject: ";

    wchar_t choice = _getwch();
    if (choice == L'0') return;

    int selected = choice - L'1';
    if (selected >= 0 && selected < (int)availableGames.size()) {
        int gameIndex = availableGames[selected];
        ShowInjectionProgress(gameIndex);
    }
}

void CopyToClipboard(const string& text) {
    if (OpenClipboard(NULL)) {
        EmptyClipboard();
        HGLOBAL hGlobal = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
        if (hGlobal) {
            memcpy(GlobalLock(hGlobal), text.c_str(), text.size() + 1);
            GlobalUnlock(hGlobal);
            SetClipboardData(CF_TEXT, hGlobal);
        }
        CloseClipboard();
    }
}

void ShowMainMenu() {
    ClearScreen();
    PrintCentered(L"lRenjector", 2);
    PrintLeft(L"1. Select Game", 4);
    PrintLeft(L"2. Start Injection", 5);
    PrintLeft(L"3. Settings", 6);
    PrintLeft(L"4. Show HWID", 7);
    PrintLeft(L"0. Exit", 9);

    SetCursorPosition(2, 11);
    wcout << L"Select option: ";
}

bool SelectExeFile(wchar_t* filePath, int bufferSize, const wstring& expectedExe = L"") {
    OPENFILENAME ofn;
    ZeroMemory(&ofn, sizeof(ofn));

    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFile = filePath;
    ofn.lpstrFile[0] = '\0';
    ofn.nMaxFile = bufferSize;
    ofn.lpstrFilter = L"Executable Files\0*.exe\0All Files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileName(&ofn)) {
        if (expectedExe.empty()) {
            return true;
        }

        wstring selectedFile = filePath;
        wstring fileName = selectedFile.substr(selectedFile.find_last_of(L"\\/") + 1);
        return (_wcsicmp(fileName.c_str(), expectedExe.c_str()) == 0);
    }
    return false;
}

bool SelectDllFile(wchar_t* filePath, int bufferSize) {
    OPENFILENAME ofn;
    ZeroMemory(&ofn, sizeof(ofn));

    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFile = filePath;
    ofn.lpstrFile[0] = '\0';
    ofn.nMaxFile = bufferSize;
    ofn.lpstrFilter = L"DLL Files\0*.dll\0All Files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    return GetOpenFileName(&ofn);
}

void ConfigureCustomGame(int gameIndex) {
    ClearScreen();
    PrintCentered(L"Configure custom game", 2);

    PrintLeft(L"Select game executable file", 4);
    PrintLeft(L"Press any key to open file dialog...", 6);
    _getwch();

    wchar_t filePath[MAX_PATH] = L"";
    if (!SelectExeFile(filePath, MAX_PATH)) {
        PrintStatus(L"No file selected!", false);
        PrintLeft(L"Press any key to continue...", 10);
        _getwch();
        return;
    }

    games[gameIndex].path = filePath;

    wstring fileName = filePath;
    size_t lastSlash = fileName.find_last_of(L"\\/");
    if (lastSlash != wstring::npos) {
        games[gameIndex].exeName = fileName.substr(lastSlash + 1);
    }
    else {
        games[gameIndex].exeName = fileName;
    }

    ClearScreen();
    PrintCentered(L"Configure custom game", 2);
    PrintLeft(L"Select DLL file", 4);
    PrintLeft(L"Press any key to open file dialog...", 6);
    _getwch();

    wchar_t dllPath[MAX_PATH] = L"";
    if (SelectDllFile(dllPath, MAX_PATH)) {
        games[gameIndex].dllName = dllPath;

        SaveGamePaths();
        UpdateGameConfigurationStatus();

        ClearScreen();
        PrintCentered(L"Success", 2);
        PrintStatus(L"Custom game configured successfully!", true);
        PrintLeft(L"Game Path: " + games[gameIndex].path, 6);
        PrintLeft(L"EXE Name: " + games[gameIndex].exeName, 7);
        PrintLeft(L"DLL Path: " + games[gameIndex].dllName, 8);
        PrintLeft(L"Press any key to continue...", 11);

        SendGameSelectedWebhook(gameIndex);
        _getwch();
    }
    else {
        ClearScreen();
        PrintStatus(L"No DLL file selected!", false);
        PrintLeft(L"Press any key to continue...", 8);
        _getwch();
    }
}

void SelectGame() {
    while (true) {
        ClearScreen();
        PrintCentered(L"Selet game", 2);

        int line = 4;
        for (int i = 0; i < (int)games.size(); i++) {
            wstring status = games[i].isConfigured ? L" [Configured]" : L" [Not configured]";
            if (games[i].isCustom && games[i].isConfigured) {
                status = L" [" + games[i].exeName + L"]";
            }
            wstring menuItem = to_wstring(i + 1) + L". " + games[i].name + status;
            PrintLeft(menuItem, line++);
        }

        PrintLeft(L"0. Back", line + 1);
        SetCursorPosition(2, line + 3);
        wcout << L"Select game: ";

        wchar_t choice = _getwch();
        if (choice == L'0') return;

        int gameIndex = -1;
        if (choice == L'1') gameIndex = 0;
        else if (choice == L'2') gameIndex = 1;
        else if (choice == L'3') gameIndex = 2;
        else continue;

        if (games[gameIndex].isCustom) {
            ConfigureCustomGame(gameIndex);
            continue;
        }

        ClearScreen();
        PrintCentered(L"Select " + games[gameIndex].exeName, 2);
        PrintLeft(L"Please select " + games[gameIndex].exeName + L" in the file dialog", 4);
        PrintLeft(L"Press any key to open file dialog...", 6);
        _getwch();

        wchar_t filePath[MAX_PATH] = L"";

        if (SelectExeFile(filePath, MAX_PATH, games[gameIndex].exeName)) {
            games[gameIndex].path = filePath;

            wstring dllPath = GetDllPath(games[gameIndex].dllName);
            if (GetFileAttributes(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
                ClearScreen();
                PrintCentered(L"Warning", 2);
                PrintStatus(L"DLL file not found: Dll\\" + games[gameIndex].dllName, false);
                PrintLeft(L"Please make sure the DLL file is in the Dll folder", 6);
                PrintLeft(L"Press any key to continue...", 8);
                _getwch();
            }

            SaveGamePaths();
            UpdateGameConfigurationStatus();

            ClearScreen();
            PrintCentered(L"Success", 2);
            PrintStatus(L"Game path saved successfully!", true);
            PrintLeft(L"Path: " + wstring(filePath), 6);
            PrintLeft(L"DLL: Dll\\" + games[gameIndex].dllName, 7);
            PrintLeft(L"Press any key to continue...", 9);

            SendGameSelectedWebhook(gameIndex);
            _getwch();
        }
        else {
            ClearScreen();
            PrintCentered(L"Error", 2);
            PrintStatus(L"Invalid file selected!", false);
            PrintLeft(L"Please select " + games[gameIndex].exeName, 6);
            PrintLeft(L"Press any key to try again...", 8);
            _getwch();
        }
    }
}

void ShowSettingsMenu() {
    while (true) {
        ClearScreen();
        PrintCentered(L"Setings", 2);

        PrintLeft(L"1. Process Monitoring: " + wstring(g_settings.enableProcessMonitoring ? L"Enabled" : L"Disabled"), 4);

        PrintLeft(L"0. Back", 7);
        SetCursorPosition(2, 9);
        wcout << L"Select option: ";

        wchar_t choice = _getwch();

        switch (choice) {
        case L'1':
        {
            bool oldValue = g_settings.enableProcessMonitoring;
            g_settings.enableProcessMonitoring = !g_settings.enableProcessMonitoring;
            SaveSettings();

            if (g_settings.enableProcessMonitoring) {
                StartProcessMonitoring();
                PrintStatus(L"Process monitoring enabled", true);
                SendSettingsChangedWebhook(L"Process Monitoring", L"Disabled", L"Enabled");
            }
            else {
                StopProcessMonitoring();
                PrintStatus(L"Process monitoring disabled", true);
                SendSettingsChangedWebhook(L"Process Monitoring", L"Enabled", L"Disabled");
            }
            Sleep(1500);
        }
        break;
        case L'0':
            return;
        default:
            break;
        }
    }
}


void ShowHWID() {
    ClearScreen();
    PrintCentered(L"HWID", 2);

    string hwid = GetHWID();
    wstring whwid(hwid.begin(), hwid.end());

    PrintLeft(L"HWID: " + whwid, 4);
    CopyToClipboard(hwid);
    PrintStatus(L"HWID copied to clipboard!", true);

    SendHWIDWebhook();

    PrintLeft(L"Press any key to return...", 8);
    _getwch();
}

int wmain(int argc, wchar_t* argv[], wchar_t* envp[]) {
    if (!IsRunningAsAdmin()) {
        RestartAsAdmin();
        return 0;
    }

    LoadSettings();
    LoadGamePaths();

    if (g_settings.enableProcessMonitoring) {
        StartProcessMonitoring();
    }

    SendStartupWebhook();

    while (true) {
        ShowMainMenu();
        wchar_t choice = _getwch();

        switch (choice) {
        case L'1':
            SelectGame();
            break;
        case L'2':
            ShowInjectionMenu();
            break;
        case L'3':
            ShowSettingsMenu();
            break;
        case L'4':
            ShowHWID();
            break;
        case L'0':
            StopProcessMonitoring();
            return 0;
        default:
            break;
        }
    }

    return 0;

}
