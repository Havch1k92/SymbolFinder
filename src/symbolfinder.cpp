#include <Windows.h>
#include <tchar.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <memory>

#include "symbolfinder.hpp"

void CloseHandleWrapper(void* handle)
{
	if (handle && handle != INVALID_HANDLE_VALUE)
		CloseHandle(handle);
}

HMODULE GetRemoteModuleHandle(void* proc, const _TCHAR* moduleName)
{
	constexpr size_t kModulesSize = 64;

	if (!proc)
		return 0;

	_TCHAR buffer[256] = { 0 };
	std::unique_ptr modules = std::make_unique<HMODULE[]>(kModulesSize);
	DWORD moduleCount = 0;

	if (!EnumProcessModulesEx(proc, modules.get(), kModulesSize * sizeof HMODULE, &moduleCount, LIST_MODULES_ALL))
		return 0;

	moduleCount /= sizeof HMODULE;

	if (moduleCount > kModulesSize)
	{
		modules = std::make_unique<HMODULE[]>(moduleCount);
		if (!EnumProcessModulesEx(proc, modules.get(), sizeof modules, &moduleCount, LIST_MODULES_ALL))
			return 0;

		moduleCount /= sizeof HMODULE;
	}

	for (size_t i = 0; i < moduleCount; ++i)
	{
		GetModuleBaseName(proc, modules[i], buffer, (DWORD)std::size(buffer));
		if (_tcscmp(moduleName, buffer) == 0)
			return modules[i];
	}

	return 0;
}

SymbolFinder::SymbolFinder() : proc{ GetCurrentProcess() } { }
SymbolFinder::SymbolFinder(void* proc) : proc{ proc } { }
SymbolFinder::SymbolFinder(const _TCHAR* procName)
{
	PROCESSENTRY32 procInfo;
	procInfo.dwSize = sizeof procInfo;

	std::unique_ptr<void, decltype(&CloseHandleWrapper)> procSnapshot{ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0), &CloseHandleWrapper };
	if (!procSnapshot || procSnapshot.get() == INVALID_HANDLE_VALUE)
		return;

	Process32First(procSnapshot.get(), &procInfo);

	auto findAndAssignProcHandle = [](const _TCHAR* procName, const PROCESSENTRY32& procInfo, void* const procSnapshot, void*& proc) {
		if (_tcscmp(procName, procInfo.szExeFile) != 0)
			return false;

		proc = OpenProcess(PROCESS_ALL_ACCESS, false, procInfo.th32ProcessID);

		return true;
	};

	if (findAndAssignProcHandle(procName, procInfo, procSnapshot.get(), proc))
		return;

	while (Process32Next(procSnapshot.get(), &procInfo))
		if (findAndAssignProcHandle(procName, procInfo, procSnapshot.get(), proc))
			return;
}

SymbolFinder::~SymbolFinder()
{
	if (proc && proc != GetCurrentProcess())
		CloseHandle(proc);
}

inline bool CompareSig(char* const data, const SymbolData& symbolData)
{
	const char* signature = symbolData.Signature();
	const char* mask = symbolData.Mask();
	size_t len = symbolData.Length();

	for (size_t i = 0; i < len; ++i)
		if (mask[i] != '?' && signature[i] != data[i])
			return false;

	return true;
}

void* SymbolFinder::FindPattern(HMODULE module, const SymbolData& data)
{
	if (!proc)
		return nullptr;

	MODULEINFO mInfo = { nullptr, 0, nullptr };
	GetModuleInformation(proc, module, &mInfo, sizeof mInfo);

	if (mInfo.SizeOfImage == 0)
		return nullptr;

	std::unique_ptr buffer = std::make_unique<char[]>(mInfo.SizeOfImage);
	SIZE_T bytesRead = 0;
	if (!ReadProcessMemory(proc, mInfo.lpBaseOfDll, buffer.get(), mInfo.SizeOfImage, &bytesRead) || bytesRead != mInfo.SizeOfImage)
		return nullptr;

	for (auto&& [found, offset] = std::pair(true, size_t(0)); offset < mInfo.SizeOfImage - data.Length(); ++offset, found = true)
		if (CompareSig(buffer.get() + offset, data))
			return (std::byte*)mInfo.lpBaseOfDll + offset;

	return nullptr;
}

void* SymbolFinder::FindPattern(const SymbolData& data) { return FindPattern(GetModuleHandle(nullptr), data); }

void* SymbolFinder::FindPattern(const _TCHAR* moduleName, const SymbolData& data)
{
	HMODULE module = proc == GetCurrentProcess() ?
		GetModuleHandle(moduleName) : GetRemoteModuleHandle(proc, moduleName);
	if (!module)
		return nullptr;

	return FindPattern(module, data);
}
