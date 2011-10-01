#define SCYLLA_NO_X64

#include <windows.h>
#include "Scylla++.h"
#include <cstdint>

// tested

const wchar_t PLUGIN_NAME[] = L"Alex Protector"; // 1.02b

class ScyllaAlexProtector : public ScyllaPlugin
{
	virtual ULONG_PTR resolveImport(ULONG_PTR, ULONG_PTR, ScyllaStatus&);
};

ULONG_PTR ScyllaAlexProtector::resolveImport(ULONG_PTR ImportTableAddressPointer, ULONG_PTR InvalidApiAddress, ScyllaStatus& Status)
{
	const uint8_t JMP_SHRT = 0xEB;
	const uint8_t PUSHAD = 0x60;
	const uint8_t RDTSC[] = {0x0F, 0x31};
	const uint8_t PUSH = 0x68;
	const uint8_t RETN = 0xC3;

	static const uint8_t pattern[] =
	{
		JMP_SHRT, 0x01,
		0,
		PUSHAD,
		RDTSC[0], RDTSC[1],
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		PUSH, 1, 1, 1, 1,
		0, 0, 0,
		RETN
	};
	static const char mask[] = "XX?XXX?????????????????????????????????????????????X???????X";

	const size_t offs_api = 0x34;

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

	if(!validMemory(InvalidApiAddress, sizeof(pattern)))
	{
		log("Invalid memory address\r\n");
		Status = SCYLLA_STATUS_IMPORT_RESOLVING_FAILED;
		return NULL;
	}

	const uint8_t* bPtr = reinterpret_cast<const uint8_t*>(InvalidApiAddress);

	if(findPattern(bPtr, sizeof(pattern), pattern, sizeof(pattern), mask))
	{
		return *reinterpret_cast<const uint32_t*>(bPtr+offs_api);
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
