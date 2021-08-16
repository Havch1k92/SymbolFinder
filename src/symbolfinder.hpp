#ifndef SYMBOLFINDER_HPP
#define SYMBOLFINDER_HPP

#include <tchar.h>
#include <wtypes.h>

struct SymDescriptor
{
	const char* Signature;
	const char* Mask;
};

// Supports remote process scanning and unicode characters
class SymbolFinder
{
public:
	// Uses current process
	SymbolFinder();
	SymbolFinder(void* proc);
	SymbolFinder(const _TCHAR* procName);

	~SymbolFinder();

	// Uses current module
	void* FindPattern(SymDescriptor desc, size_t length);
	void* FindPattern(const _TCHAR* moduleName, SymDescriptor desc, size_t length);

private:
	void* proc = nullptr;

	void* FindPattern(HMODULE module, SymDescriptor desc, size_t length);
};

#endif // SYMBOLFINDER_HPP
