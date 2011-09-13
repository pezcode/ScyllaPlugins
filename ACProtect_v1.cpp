#define SCYLLA_NO_X64

#include <windows.h>
#include <cstring>
#include "Scylla++.h"
#include "stdint.h"

const wchar_t PLUGIN_NAME[] = L"ACProtect v1.x"; // (checked with 1.0.9, 1.3.2, 1.3.5, 1.4.1)

class ScyllaACProtect : public ScyllaPlugin
{
	virtual ULONG_PTR resolveImport(ULONG_PTR, ULONG_PTR, ScyllaStatus&);
};

ULONG_PTR ScyllaACProtect::resolveImport(ULONG_PTR ImportTableAddressPointer, ULONG_PTR InvalidApiAddress, ScyllaStatus& Status)
{
	const uint8_t OPC_PUSH_DW = 0x68;
	const uint8_t OPC_XOR_DW_ESP[] = {0x81, 0x34, 0x24};
	const uint8_t OPC_RETN = 0xC3;

	/*
	 * PUSH X
	 * XOR [ESP], Y
	 * RETN ; -> API
	 */

	if(!validMemory(InvalidApiAddress, sizeof(OPC_PUSH_DW) + sizeof(uint32_t) + sizeof(OPC_XOR_DW_ESP) + sizeof(uint32_t)))
	{
		log("Invalid memory address\r\n");
		Status = SCYLLA_STATUS_IMPORT_RESOLVING_FAILED;
		return NULL;
	}

	const uint8_t* bPtr = reinterpret_cast<const uint8_t*>(InvalidApiAddress);

	if(*bPtr == OPC_PUSH_DW)
	{
		bPtr++;
		uint32_t X = *reinterpret_cast<const uint32_t*>(bPtr);
		bPtr += sizeof(uint32_t);
		if(!memcmp(bPtr, OPC_XOR_DW_ESP, sizeof(OPC_XOR_DW_ESP)))
		{
			bPtr += sizeof(OPC_XOR_DW_ESP);
			uint32_t Y = *reinterpret_cast<const uint32_t*>(bPtr);
			bPtr += sizeof(uint32_t);
			if(*bPtr == OPC_RETN)
			{
				return (X ^ Y);
			}
		}
	}

	log("Unsupported opcode found\r\n");
	Status = SCYLLA_STATUS_UNSUPPORTED_PROTECTION;
	return NULL;
}

ScyllaACProtect plugin;

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
