#define SCYLLA_NO_X64

#include <windows.h>
#include "Scylla++.h"
#include "stdint.h"

const wchar_t PLUGIN_NAME[] = L"ReversingLabs Protector [RLP]";

class ScyllaRLP : public ScyllaPlugin
{
	virtual ULONG_PTR resolveImport(ULONG_PTR, ULONG_PTR, ScyllaStatus&);
};

ULONG_PTR ScyllaRLP::resolveImport(ULONG_PTR ImportTableAddressPointer, ULONG_PTR InvalidApiAddress, ScyllaStatus& Status)
{
	const uint8_t PUSH_DW = 0x68;
	const uint8_t ADD_DW_ESP[] = {0x81, 0x04, 0x24};

	static const uint8_t pattern[] =
	{
		PUSH_DW, 1, 1, 1, 1,
		ADD_DW_ESP[0], ADD_DW_ESP[1], ADD_DW_ESP[2], 2, 2, 2, 2
		//RETN??
	};
	static const char mask[] = "X????XXX????";

	const size_t offs_x = 1;
	const size_t off_y = 8;

	/*
	PUSH X
	ADD [ESP], Y
	; [ESP] = API
	*/

	if(!validMemory(InvalidApiAddress, sizeof(pattern)))
	{
		log("Invalid memory address\r\n");
		Status = SCYLLA_STATUS_IMPORT_RESOLVING_FAILED;
		return NULL;
	}

	const uint8_t* bPtr = reinterpret_cast<const uint8_t*>(InvalidApiAddress);

	if(findPattern(bPtr, sizeof(pattern), pattern, sizeof(pattern), mask))
	{
		uint32_t X = *reinterpret_cast<const uint32_t*>(bPtr+offs_x);
		uint32_t Y = *reinterpret_cast<const uint32_t*>(bPtr+off_y);
		return (X + Y);
	}

	log("Unsupported opcode found\r\n");
	Status = SCYLLA_STATUS_UNSUPPORTED_PROTECTION;
	return NULL;
}

ScyllaRLP plugin;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch(fdwReason) 
	{ 
	case DLL_PROCESS_ATTACH:
		plugin.log("DLL attached - Injection successful\r\n");
		if(plugin.valid())
		{
			plugin.log("Open mapping successful\r\n");
			plugin.resolveAllImports();
			plugin.cleanUp();
		}
		break;

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;

	case DLL_PROCESS_DETACH:
		plugin.log("DLL successfully detached\r\n");
		break;
	}

	return TRUE;
}

extern "C" __declspec(dllexport) wchar_t* __cdecl ScyllaPluginNameW()
{
	return const_cast<wchar_t*>(PLUGIN_NAME);
}
