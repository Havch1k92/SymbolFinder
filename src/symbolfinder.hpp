#ifndef SYMBOLFINDER_HPP
#define SYMBOLFINDER_HPP

#include <tchar.h>
#include <wtypes.h>

template<size_t N>
struct SymDescriptor
{
	const char(&Signature)[N];
	const char(&Mask)[N];
};

class SymbolData
{
public:
	template<size_t N>
	SymbolData(SymDescriptor<N> desc) :
		signature{ desc.Signature },
		mask{ desc.Mask },
		length{ N - 1 }
	{ }

	SymbolData(const char* signature, const char* mask, size_t length) :
		signature{ signature },
		mask{ mask },
		length{ length }
	{ }

	inline const char* const Signature() const { return signature; }
	inline const char* const Mask() const { return mask; }
	inline size_t Length() const { return length; }
private:
	const char* signature;
	const char* mask;
	size_t length;
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
	void* FindPattern(const SymbolData& desc);
	void* FindPattern(const _TCHAR* moduleName, const SymbolData& data);

private:
	void* proc = nullptr;

	void* FindPattern(HMODULE module, const SymbolData& data);
};

#endif // SYMBOLFINDER_HPP
