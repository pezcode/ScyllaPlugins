#define SCYLLA_NO_X64

#include <windows.h>
#include "Scylla++.h"
#include "stdint.h"

const wchar_t PLUGIN_NAME[] = L"PECompact v2.x";

class ScyllaPEC2 : public ScyllaPlugin
{
	virtual ULONG_PTR resolveImport(ULONG_PTR, ULONG_PTR, ScyllaStatus&);
};

ULONG_PTR ScyllaPEC2::resolveImport(ULONG_PTR ImportTableAddressPointer, ULONG_PTR InvalidApiAddress, ScyllaStatus& Status)
{
	/*
	 * MOV EAX, API
	 * JMP EAX
	 */

	const uint8_t OPC_MOV_EAX = 0xB8;
	const uint16_t OPC_JMP_EAX = 0xE0FF;

	if(!validMemory(InvalidApiAddress, sizeof(OPC_MOV_EAX) + sizeof(uint32_t) + sizeof(OPC_JMP_EAX)))
	{
		log("Invalid memory address\r\n");
		Status = SCYLLA_STATUS_IMPORT_RESOLVING_FAILED;
		return NULL;
	}

	const uint8_t* bPtr = reinterpret_cast<const uint8_t*>(InvalidApiAddress);

	if(*bPtr == OPC_MOV_EAX)
	{
		bPtr++;
		bPtr += sizeof(uint32_t);
		if(*reinterpret_cast<const uint16_t*>(bPtr) == OPC_JMP_EAX)
		{
			return *reinterpret_cast<const uint32_t*>(InvalidApiAddress+1);
		}
	}

	log("Unsupported opcode found\r\n");
	Status = SCYLLA_STATUS_UNSUPPORTED_PROTECTION;
	return NULL;
}

ScyllaPEC2 plugin;

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
