#define SCYLLA_NO_X64

#include <windows.h>
#include <cstring>
#include "Scylla++.h"
#include "stdint.h"

const wchar_t PLUGIN_NAME[] = L"Krypton"; // 0.2, 0.3, 0.5

class ScyllaKrypton : public ScyllaPlugin
{
	virtual ULONG_PTR resolveImport(ULONG_PTR, ULONG_PTR, ScyllaStatus&);
};

ULONG_PTR ScyllaKrypton::resolveImport(ULONG_PTR ImportTableAddressPointer, ULONG_PTR InvalidApiAddress, ScyllaStatus& Status)
{
	const uint16_t OPC_ADD_DW = 0x0581;
	const uint16_t OPC_SUB_DW = 0x2D81;
	const uint16_t OPC_XOR_DW = 0x3581;
	const uint8_t OPC_MOV_EAX_DW = 0xA1;
	const uint16_t OPC_JMP_EAX = 0xE0FF;

	/*
	ADD DWORD [X], Y   ; XOR
	MOV EAX, DWORD [X]
	SUB DWORD [X], Y   ; XOR
	JMP EAX
	*/

	const size_t REDIR_SIZE = 2 * (sizeof(OPC_ADD_DW) + sizeof(uint32_t)) + sizeof(OPC_MOV_EAX_DW) + sizeof(uint32_t) + sizeof(OPC_JMP_EAX);

	if(!validMemory(InvalidApiAddress, REDIR_SIZE))
	{
		log("Invalid memory address\r\n");
		Status = SCYLLA_STATUS_IMPORT_RESOLVING_FAILED;
		return NULL;
	}

	const uint8_t* bPtr = reinterpret_cast<const uint8_t*>(InvalidApiAddress);

	if(bPtr[0] == OPC_JMP_SHRT && bPtr[1] == 0x01)
	{
		if(bPtr[3] == OPC_PUSHAD)
		{
			if(*reinterpret_cast<const uint16_t*>(bPtr+4) == OPC_RDTSC)
			{
				bPtr += 0x34 - 1;
				if(bPtr[0] == OPC_PUSH && bPtr[8] == OPC_RETN)
				{
					return *reinterpret_cast<const ULONG_PTR*>(InvalidApiAddress+0x34);
				}
			}
		}
	}

	log("Unsupported opcode found\r\n");
	Status = SCYLLA_STATUS_UNSUPPORTED_PROTECTION;
	return NULL;
}

ScyllaKrypton plugin;

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
