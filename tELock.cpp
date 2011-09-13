#define SCYLLA_NO_X64

#include <windows.h>
#include <cstring>
#include "Scylla++.h"
#include "stdint.h"

const wchar_t PLUGIN_NAME[] = L"tELock < 0.95"; // 0.51, 0.80, 0.85
//0.6 - 0.71 crash, repack!

/*
0.51 - 0.85:
JMP DWORD [X] ; -> API

0.90/0.92a:

PUSH DWORD [X] ; 0x35FF = FF 35 XXXXXXXXX
<2-3 bytes junk> ; test xl/xh, yyh
RETN
<junk byte if only 2 junk bytes before RETN>

0.95/0.96:

;WTF

code...
MOV EAX, X
JMP DWORD [EAX] [+ NOP] ; also PUSH DWORD [EAX] + RETN

0.98:

code...
MOV EAX, X
INC EAX
PUSH DWORD [EAX] ; JMP [EAX] too?
RETN

0.99:

random instr involving EAX
mov eax, X
EB 02 ; 02 ??
add eax, X
mov eax, [eax]
xor eax, Y
nop
nop ; ??
push eax
retn
*/

class ScyllaTELock : public ScyllaPlugin
{
	virtual ULONG_PTR resolveImport(ULONG_PTR, ULONG_PTR, ScyllaStatus&);
};

ULONG_PTR ScyllaTELock::resolveImport(ULONG_PTR ImportTableAddressPointer, ULONG_PTR InvalidApiAddress, ScyllaStatus& Status)
{
	const uint16_t OPC_JMP_DW = 0x25FF;
	const uint16_t OPC_PUSH_DW = 0x35FF;
	const uint8_t OPC_RETN = 0x3C;

	/*
	 * JMP [X] ; -> API
	 */

	if(!validMemory(InvalidApiAddress, sizeof(OPC_JMP_DW) + sizeof(uint32_t)))
	{
		log("Invalid memory address\r\n");
		Status = SCYLLA_STATUS_IMPORT_RESOLVING_FAILED;
		return NULL;
	}

	const uint16_t* wPtr = reinterpret_cast<const uint16_t*>(InvalidApiAddress);

	if(*wPtr == OPC_JMP_DW)
	{
		wPtr++;
		uint32_t offset = *reinterpret_cast<const uint32_t*>(wPtr);
		if(validMemory(offset, sizeof(ULONG_PTR)))
		{
			return *reinterpret_cast<const ULONG_PTR*>(offset);
		}
	}
	else if(*wPtr == OPC_PUSH_DW)
	{
		wPtr++;
		const uint8_t* bPtr = reinterpret_cast<const uint8_t*>(wPtr);
		bPtr += sizeof(uint32_t);
		if(validMemory(reinterpret_cast<ULONG_PTR>(bPtr), 3 + sizeof(OPC_RETN)))
		{
			if(bPtr[2] == OPC_RETN || bPtr[3] == OPC_RETN)
			{
				uint32_t offset = *reinterpret_cast<const uint32_t*>(wPtr);
				if(validMemory(offset, sizeof(ULONG_PTR)))
				{
					return *reinterpret_cast<const ULONG_PTR*>(offset);
				}
			}
		}
	}

	log("Unsupported opcode found\r\n");
	Status = SCYLLA_STATUS_UNSUPPORTED_PROTECTION;
	return NULL;
}

ScyllaTELock plugin;

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
