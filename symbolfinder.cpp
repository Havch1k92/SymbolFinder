#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include "symbolfinder.hpp"

#ifdef UNICODE
#	define STRCMP(a, b) wcscmp(a, b)
#	define SF_CHAR wchar_t
#else
#	define STRCMP(a, b) strcmp(a, b)
#	define SF_CHAR char
#endif

HMODULE GetRemoteModuleHandle(void* proc, const SF_CHAR* moduleName)
{
	constexpr size_t modulesSize = 64;
	auto cleanup = [] (HMODULE* m) {
		delete[] m;
		return nullptr;
	};

	SF_CHAR buffer[256] = { 0 };
	HMODULE* modules = new HMODULE[modulesSize];
	DWORD moduleCount = 0;

	if (!proc)
		return cleanup(modules);

	if (!EnumProcessModulesEx(proc, modules, sizeof modules, &moduleCount, LIST_MODULES_ALL))
		return cleanup(modules);

	moduleCount /= sizeof HMODULE;

	if (moduleCount > modulesSize)
	{
		delete[] modules;
		modules = new HMODULE[moduleCount];

		if (!EnumProcessModulesEx(proc, modules, sizeof modules, &moduleCount, LIST_MODULES_ALL))
			return cleanup(modules);

		moduleCount /= sizeof HMODULE;
	}

	for (size_t i = 0; i < moduleCount; ++i)
	{
		GetModuleBaseName(proc, modules[i], buffer, sizeof buffer);
		if (STRCMP(moduleName, buffer) == 0)
		{
			HMODULE res = modules[i];
			delete[] modules;

			return res;
		}
	}

	return cleanup(modules);;
}

SymbolFinder::SymbolFinder() : process{ GetCurrentProcess() } { }
SymbolFinder::SymbolFinder(void* proc) : process{ proc } { }
SymbolFinder::SymbolFinder(const SF_CHAR* procName)
{
	PROCESSENTRY32 procInfo;
	procInfo.dwSize = sizeof procInfo;

	void* procSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (!procSnapshot || procSnapshot == INVALID_HANDLE_VALUE)
		return;

	Process32First(procSnapshot, &procInfo);
	if (!STRCMP(procName, procInfo.szExeFile) == 0)
	{
		this->process = OpenProcess(PROCESS_ALL_ACCESS, false, procInfo.th32ProcessID);
		CloseHandle(procSnapshot);

		return;
	}

	while (Process32Next(procSnapshot, &procInfo))
	{
		if (STRCMP(procName, procInfo.szExeFile) == 0)
		{
			this->process = OpenProcess(PROCESS_ALL_ACCESS, false, procInfo.th32ProcessID);
			CloseHandle(procSnapshot);

			return;
		}
	}

	CloseHandle(procSnapshot);
}

SymbolFinder::~SymbolFinder()
{
	if (this->process && this->process != GetCurrentProcess())
		CloseHandle(this->process);
}

void* SymbolFinder::FindPattern(const SF_CHAR* moduleName, SymbolSig sig, size_t length)
{
	MODULEINFO minfo = { nullptr, 0, nullptr };
	HMODULE handle = this->process == GetCurrentProcess() ? GetModuleHandle(moduleName) : GetRemoteModuleHandle(this->process, moduleName);
	if (!handle)
		return nullptr;

	GetModuleInformation(this->process, handle, &minfo, sizeof minfo);

	if (minfo.SizeOfImage == 0)
		return nullptr;

	char* buffer = new char[minfo.SizeOfImage];
	SIZE_T bytesRead = 0;
	if (!ReadProcessMemory(this->process, minfo.lpBaseOfDll, buffer, minfo.SizeOfImage, &bytesRead) || bytesRead != minfo.SizeOfImage)
	{
		delete[] buffer;
		return nullptr;
	}

	bool found = true;
	for (size_t offset = 0; offset < minfo.SizeOfImage - length; ++offset, found = true)
	{
		for (size_t i = 0; i < length; ++i)
		{
			if (*(sig.Mask + i) != '?' && *(sig.Body + i) != *(buffer + offset + i))
			{
				found = false;
				break;
			}
		}

		if (found)
		{
			delete[] buffer;
			return (BYTE*)minfo.lpBaseOfDll + offset;
		}
	}

	delete[] buffer;

	return nullptr;
}

#undef STRCMP
#undef SF_CHAR
