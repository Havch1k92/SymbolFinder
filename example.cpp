#include <iostream>
#include "symbolfinder.hpp"

using DoEnginePostProcessingFn = void(*)(int x, int y, int w, int h, bool flashlightIsOn, bool postVGui);
DoEnginePostProcessingFn DoEnginePostProcessing;

constexpr SymbolSig g_DoEnginePostProcessingSig = {
	.Body = "\x55\x8B\xEC\x8B\x0D\x00\x00\x00\x00\x81\xEC\x00\x00\x00\x00\x8B\x01\x56\xFF\x90\x00"
	"\x00\x00\x00\x8B\xF0\x85\xF6\x74\x06\x8B\x06\x8B\xCE\xFF\x10\xA1\x00\x00\x00\x00",
	.Mask = "xxxxx????xx????xxxxx????xxxxxxxxxxxxx????"
};

int main()
{
	SymbolFinder scanner; // Uses current process (default ctor)
	
	DoEnginePostProcessing = (DoEnginePostProcessingFn)scanner.FindPattern(L"client.dll", g_DoEnginePostProcessingSig, 41); // 41 is length of the signature
	if (!DoEnginePostProcessing)
	{
		std::wcout << L"DoEnginePostProcessing signature is outdated!\n";
		return 0;
	}
	
	std::wcout << L"Address of DoEnginePostProcessing: " << DoEnginePostProcessing << std::endl;
}
