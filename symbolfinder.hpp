#ifndef SYMBOLFINDER_HPP
#define SYMBOLFINDER_HPP

#ifdef UNICODE
#	define SF_CHAR wchar_t
#else
#	define SF_CHAR char
#endif

struct SymbolSig
{
	const char* Body;
	const char* Mask;
};

// Supports remote process scanning and unicode characters
class SymbolFinder
{
public:
	// Uses current process
	SymbolFinder();
	SymbolFinder(void* proc);
	SymbolFinder(const SF_CHAR* procName);

	~SymbolFinder();

	void* FindPattern(const SF_CHAR* moduleName, SymbolSig sig, size_t length);

private:
	void* process = nullptr;
};

#undef SF_CHAR

#endif // SYMBOLFINDER_HPP
