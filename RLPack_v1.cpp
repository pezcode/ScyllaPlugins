#define SCYLLA_NO_X64

#include <windows.h>
#include <cstring>
#include "Scylla++.h"
#include "stdint.h"

const wchar_t PLUGIN_NAME[] = L"RLPack v1.x";

class ScyllaRLP : public ScyllaPlugin
{
	virtual ULONG_PTR resolveImport(ULONG_PTR, ULONG_PTR, ScyllaStatus&);
};

ULONG_PTR ScyllaRLP::resolveImport(ULONG_PTR ImportTableAddressPointer, ULONG_PTR InvalidApiAddress, ScyllaStatus& Status)
{
	const uint8_t OPC_PUSH_DW = 0x68;
	const uint8_t OPC_ADD_DW_ESP[] = {0x81, 0x04, 0x24};

	/*
	 * PUSH X
	 * ADD [ESP], Y
	 * ; [ESP] = API
	 */

	if(!validMemory(InvalidApiAddress, sizeof(OPC_PUSH_DW) + sizeof(uint32_t) + sizeof(OPC_ADD_DW_ESP) + sizeof(uint32_t)))
	{
		log("Invalid memory address\r\n");
		Status = SCYLLA_STATUS_UNKNOWN_ERROR;
		return NULL;
	}

	const uint8_t* bPtr = reinterpret_cast<const uint8_t*>(InvalidApiAddress);

	if(*bPtr == OPC_PUSH_DW)
	{
		bPtr++;
		uint32_t X = *reinterpret_cast<const uint32_t*>(bPtr);
		bPtr += sizeof(uint32_t);
		if(!memcmp(bPtr, OPC_ADD_DW_ESP, sizeof(OPC_ADD_DW_ESP)))
		{
			bPtr += sizeof(OPC_ADD_DW_ESP);
			uint32_t Y = *reinterpret_cast<const uint32_t*>(bPtr);
			return (X + Y);
		}
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
