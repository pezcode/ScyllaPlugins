#define SCYLLA_NO_X64

#include <windows.h>
#include <cstring>
#include "Scylla++.h"
#include "stdint.h"

const wchar_t PLUGIN_NAME[] = L"Alex Protector"; // 1.02b

class ScyllaAlexProtector : public ScyllaPlugin
{
	virtual ULONG_PTR resolveImport(ULONG_PTR, ULONG_PTR, ScyllaStatus&);
};

ULONG_PTR ScyllaAlexProtector::resolveImport(ULONG_PTR ImportTableAddressPointer, ULONG_PTR InvalidApiAddress, ScyllaStatus& Status)
{
	const uint8_t OPC_JMP_SHRT = 0xEB;
	const uint8_t OPC_PUSHAD = 0x60;
	const uint16_t OPC_RDTSC = 0x310F;
	const uint8_t OPC_PUSH = 0x68;
	const uint8_t OPC_RETN = 0xC3;

	/*
	JMP +1
	<junk>
	PUSHAD
	RDTSC
	JMP +1
	<junk>
	MOV EBX, EAX
	JMP +1
	<junk>
	MOV ECX, EDX
	RDTSC
	SUB EAX, EBX
	SBB EDX, ECX
	JMP +1
	<junk>
	RDTSC
	ADD EAX, EBX
	ADC EDX, ECX
	RDTSC
	JMP +1
	<junk>
	SUB EAX, EBX
	JMP +1
	<junk>
	SBB EDX, ECX
	TEST EDX, EDX
	JNZ +Dh
	POPAD
	JMP +1
	<junk>
	PUSH API ; offset of API = 0x34 from start
	JMP +1
	<junk>
	RETN
	*/

	if(!validMemory(InvalidApiAddress, 0x34 + sizeof(ULONG_PTR) + 4))
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

ScyllaAlexProtector plugin;

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
