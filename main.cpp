#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <iostream>
#include <string>
#include <TlHelp32.h>
#include <cwchar>
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <stdexcept>
#include <sddl.h>
#include <thread>
#include <chrono>
#include <vector>
#include <psapi.h>
#include <memoryapi.h>
#include <iomanip>
#include <ctime>
#include <sstream>
#include <cstring>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

#define FOREGROUND_YELLOW (FOREGROUND_RED | FOREGROUND_GREEN)
#define FOREGROUND_CYAN (FOREGROUND_GREEN | FOREGROUND_BLUE)
#define FOREGROUND_WHITE (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)

const std::string INJECTOR_VERSION = "1.2";
const std::vector<std::wstring> SUPPORTED_GAMES = {
    L"cs2.exe", L"csgo.exe", L"RustClient.exe", L"gmod.exe"};

namespace Logger
{
    static bool VerboseEnabled = false;

    std::string GetTimestamp()
    {
        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&in_time_t), "%H:%M:%S");
        return ss.str();
    }

    void SetVerbose(bool v) { VerboseEnabled = v; }

    void Log(const std::string &message, int color = FOREGROUND_WHITE)
    {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        std::cout << "[" << GetTimestamp() << "] ";
        SetConsoleTextAttribute(hConsole, color | FOREGROUND_INTENSITY);
        std::cout << message << std::endl;
        SetConsoleTextAttribute(hConsole, FOREGROUND_WHITE);
    }

    void Debug(const std::string &message)
    {
        if (VerboseEnabled)
            Log("[DBG] " + message, FOREGROUND_WHITE);
    }
    void Success(const std::string &message) { Log("[+] " + message, FOREGROUND_GREEN); }
    void Info(const std::string &message) { Log("[*] " + message, FOREGROUND_CYAN); }
    void Warn(const std::string &message) { Log("[!] " + message, FOREGROUND_YELLOW); }
    void Error(const std::string &message) { Log("[-] " + message, FOREGROUND_RED); }

    std::string AddrToString(void *ptr)
    {
        std::ostringstream ss;
        ss << "0x" << std::hex << (uintptr_t)ptr << std::dec;
        return ss.str();
    }
}

namespace ArchUtils
{
    enum Arch
    {
        x86,
        x64,
        Unknown
    };

    Arch GetProcessArchitecture(HANDLE hProcess)
    {
        BOOL isWow64 = FALSE;
        if (!IsWow64Process(hProcess, &isWow64))
            return Unknown;
        SYSTEM_INFO sysInfo;
        GetNativeSystemInfo(&sysInfo);
        if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
            return isWow64 ? x86 : x64;
        return x86;
    }

    Arch GetDllArchitecture(const std::string &dllPath)
    {
        std::ifstream file(dllPath, std::ios::binary);
        if (!file)
            return Unknown;
        IMAGE_DOS_HEADER dosHeader;
        file.read(reinterpret_cast<char *>(&dosHeader), sizeof(IMAGE_DOS_HEADER));
        if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
            return Unknown;
        file.seekg(dosHeader.e_lfanew, std::ios::beg);
        IMAGE_NT_HEADERS ntHeaders;
        file.read(reinterpret_cast<char *>(&ntHeaders), sizeof(IMAGE_NT_HEADERS));
        if (ntHeaders.Signature != IMAGE_NT_SIGNATURE)
            return Unknown;
        if (ntHeaders.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
            return x64;
        if (ntHeaders.FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
            return x86;
        return Unknown;
    }

    std::string ArchToString(Arch arch)
    {
        if (arch == x86)
            return "x32 (i386)";
        if (arch == x64)
            return "x64 (AMD64)";
        return "Unknown";
    }
}

namespace Helper
{
    static void PrintBanner()
    {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::cout << "--- AnarchyInjector v" << INJECTOR_VERSION << " ---" << std::endl;
        SetConsoleTextAttribute(hConsole, FOREGROUND_WHITE);
        Logger::Info("Skeet Compatibility Mode Active");
        std::cout << "----------------------------------------------" << std::endl;
    }

    static bool IsElevated()
    {
        BOOL fIsElevated = FALSE;
        HANDLE hToken = NULL;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        {
            TOKEN_ELEVATION elevation;
            DWORD dwSize;
            if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize))
                fIsElevated = elevation.TokenIsElevated;
            CloseHandle(hToken);
        }
        return fIsElevated;
    }

    static std::wstring ToWide(const std::string &str) { return std::wstring(str.begin(), str.end()); }

    static bool CheckInsecureFlag(HANDLE hProcess)
    {
        PROCESS_BASIC_INFORMATION pbi;
        if (NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL) != 0)
            return false;

        PEB peb;
        if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL))
            return false;

        RTL_USER_PROCESS_PARAMETERS params;
        if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &params, sizeof(params), NULL))
            return false;

        std::wstring cmdLine(params.CommandLine.Length / sizeof(wchar_t), L'\0');
        if (!ReadProcessMemory(hProcess, params.CommandLine.Buffer, &cmdLine[0], params.CommandLine.Length, NULL))
            return false;

        return (cmdLine.find(L"-insecure") != std::wstring::npos);
    }
}

namespace HookBypass
{
    BYTE originalBytes[20][6];

    BOOL UnhookMethod(HANDLE hProcess, const char *methodName, const wchar_t *dllName, int index)
    {
        HMODULE hModule = GetModuleHandleW(dllName);
        if (!hModule)
            hModule = LoadLibraryW(dllName);
        if (!hModule)
            return FALSE;

        LPVOID funcAddr = GetProcAddress(hModule, methodName);
        if (!funcAddr)
            return FALSE;

        ReadProcessMemory(hProcess, funcAddr, originalBytes[index], 6, NULL);
        BYTE cleanBytes[6];
        memcpy(cleanBytes, funcAddr, 6);

        SIZE_T bytesWritten = 0;
        return WriteProcessMemory(hProcess, funcAddr, cleanBytes, 6, &bytesWritten);
    }

    void RestoreMethod(HANDLE hProcess, const char *methodName, const wchar_t *dllName, int index)
    {
        HMODULE hModule = GetModuleHandleW(dllName);
        if (!hModule)
            return;
        LPVOID funcAddr = GetProcAddress(hModule, methodName);
        if (funcAddr)
            WriteProcessMemory(hProcess, funcAddr, originalBytes[index], 6, NULL);
    }

    static BOOL ApplyVACBypass(HANDLE hProc)
    {
        Logger::Info("Applying VAC hook bypass...");
        UnhookMethod(hProc, "LoadLibraryExW", L"kernel32", 0);
        UnhookMethod(hProc, "VirtualAlloc", L"kernel32", 1);
        UnhookMethod(hProc, "LdrLoadDll", L"ntdll", 10);
        return TRUE;
    }

    static void RestoreVACBypass(HANDLE hProc)
    {
        RestoreMethod(hProc, "LoadLibraryExW", L"kernel32", 0);
        RestoreMethod(hProc, "VirtualAlloc", L"kernel32", 1);
        RestoreMethod(hProc, "LdrLoadDll", L"ntdll", 10);
        Logger::Success("VAC hooks restored.");
    }
}

namespace Injection
{
    LPVOID ntOpenFile = GetProcAddress(LoadLibraryW(L"ntdll"), "NtOpenFile");

    bool Inject(HANDLE hProcess, const std::string &dllPath, const std::wstring &targetName)
    {
        std::filesystem::path p(dllPath);
        std::string dllName = p.filename().string();
        std::string absDllPath = std::filesystem::absolute(p).string();

        ArchUtils::Arch procArch = ArchUtils::GetProcessArchitecture(hProcess);
        ArchUtils::Arch dllArch = ArchUtils::GetDllArchitecture(absDllPath);

        Logger::Info("Process Arch: " + ArchUtils::ArchToString(procArch));
        Logger::Info("DLL Arch:     " + ArchUtils::ArchToString(dllArch));

        if (procArch != dllArch && procArch != ArchUtils::Unknown && dllArch != ArchUtils::Unknown)
        {
            Logger::Error("Architecture Mismatch! Incompatible DLL.");
            return false;
        }

        if (dllName == "skeet.dll")
        {
            Logger::Warn("Skeet-specific injection parameters detected.");

            if (ntOpenFile)
            {
                char bytes[5];
                memcpy(bytes, ntOpenFile, 5);
                WriteProcessMemory(hProcess, ntOpenFile, bytes, 5, NULL);
                Logger::Info("NtOpenFile bypass applied.");
            }

            Logger::Info("Allocating skeet memory regions (Preferred: 0x43310000)...");
            LPVOID alloc1 = VirtualAllocEx(hProcess, (LPVOID)0x43310000, 0x2FC000u, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            LPVOID alloc2 = VirtualAllocEx(hProcess, 0, 0x1000u, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

            LPVOID pathAlloc = VirtualAllocEx(hProcess, nullptr, absDllPath.size() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!pathAlloc)
                return false;

            if (!WriteProcessMemory(hProcess, pathAlloc, absDllPath.c_str(), absDllPath.size() + 1, nullptr))
            {
                VirtualFreeEx(hProcess, pathAlloc, 0, MEM_RELEASE);
                return false;
            }

            HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"), pathAlloc, 0, nullptr);
            if (hThread)
            {
                WaitForSingleObject(hThread, INFINITE);
                CloseHandle(hThread);
                return true;
            }
            return false;
        }
        else
        {
            LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, absDllPath.size() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!remoteMem)
                return false;

            WriteProcessMemory(hProcess, remoteMem, absDllPath.c_str(), absDllPath.size() + 1, NULL);
            HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, remoteMem, 0, NULL);

            if (hThread)
            {
                WaitForSingleObject(hThread, INFINITE);
                CloseHandle(hThread);
                VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
                return true;
            }
            return false;
        }
    }
}

namespace ProcessManager
{
    HANDLE GetProcess(const std::wstring &name, DWORD &outPid)
    {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
            return NULL;
        PROCESSENTRY32W entry;
        entry.dwSize = sizeof(entry);
        if (Process32FirstW(snapshot, &entry))
        {
            do
            {
                if (_wcsicmp(entry.szExeFile, name.c_str()) == 0)
                {
                    outPid = entry.th32ProcessID;
                    CloseHandle(snapshot);
                    return OpenProcess(PROCESS_ALL_ACCESS, FALSE, outPid);
                }
            } while (Process32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);
        return NULL;
    }
}

int main(int argc, char *argv[])
{
    Helper::PrintBanner();

    if (argc < 2)
    {
        Logger::Error("Usage: AnarchyInjector.exe <dll_path>");
        system("pause");
        return 1;
    }

    std::string dllPath = argv[argc - 1];
    std::string targetInput = (argc == 3) ? argv[1] : "";

    DWORD pid = 0;
    HANDLE hProc = nullptr;
    std::wstring targetName;

    if (targetInput.empty())
    {
        Logger::Info("Scanning for games...");
        while (!hProc)
        {
            for (const auto &game : SUPPORTED_GAMES)
            {
                hProc = ProcessManager::GetProcess(game, pid);
                if (hProc)
                {
                    targetName = game;
                    break;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }
    else
    {
        targetName = Helper::ToWide(targetInput);
        hProc = ProcessManager::GetProcess(targetName, pid);
    }

    if (!hProc)
        return 1;
    Logger::Success("Target Found: (PID: " + std::to_string(pid) + ")");

    if (targetName == L"csgo.exe" || targetName == L"cs2.exe")
    {
        if (!Helper::CheckInsecureFlag(hProc))
        {
            Logger::Warn("CSGO/CS2 is running WITHOUT -insecure!");
            std::cout << "[?] Risk of VAC ban. Continue? (y/n): ";
            char choice;
            std::cin >> choice;
            if (choice != 'y' && choice != 'Y')
            {
                CloseHandle(hProc);
                return 0;
            }
        }
        else
        {
            Logger::Success("Security Check: -insecure detected.");
        }
    }

    HookBypass::ApplyVACBypass(hProc);
    if (Injection::Inject(hProc, dllPath, targetName))
    {
        Logger::Success("Injection Finished.");
    }
    else
    {
        Logger::Error("Injection Failed.");
    }
    HookBypass::RestoreVACBypass(hProc);

    CloseHandle(hProc);
    std::this_thread::sleep_for(std::chrono::seconds(3));
    return 0;
}