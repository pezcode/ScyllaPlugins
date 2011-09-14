#define SCYLLA_NO_X64

#define NOMINMAX

#include <windows.h>
#include <algorithm>
#include "Scylla++.h"
#include "stdint.h"

const wchar_t PLUGIN_NAME[] = L"tELock < 0.98"; // 0.51, 0.80, 0.85
//0.6 - 0.71 crash, repack!

class ScyllaTELock : public ScyllaPlugin
{
	virtual ULONG_PTR resolveImport(ULONG_PTR, ULONG_PTR, ScyllaStatus&);
	ULONG_PTR fixType1(ULONG_PTR InvalidApiAddress);
	ULONG_PTR fixType2(ULONG_PTR InvalidApiAddress);
	ULONG_PTR fixType3(ULONG_PTR InvalidApiAddress);
	ULONG_PTR fixType4(ULONG_PTR InvalidApiAddress);
	ULONG_PTR fixType5(ULONG_PTR InvalidApiAddress);
};

//0.51 - 0.85
ULONG_PTR ScyllaTELock::fixType1(ULONG_PTR InvalidApiAddress)
{
	const uint8_t JMP_DW[] = {0xFF, 0x25};

	static const uint8_t pattern[] =
	{
		JMP_DW[0], JMP_DW[1], 1, 1, 1, 1
	};
	static const char mask[] = "XX????";

	const size_t offs_x = 2;

	/*
	JMP [X]
	*/

	const uint8_t* bPtr = reinterpret_cast<const uint8_t*>(InvalidApiAddress);

	if(validMemory(InvalidApiAddress, sizeof(pattern)))
	{
		if(findPattern(bPtr, sizeof(pattern), pattern, sizeof(pattern), mask))
		{
			uint32_t X = *reinterpret_cast<const uint32_t*>(bPtr+offs_x);
			if(validMemory(X, sizeof(ULONG_PTR)))
			{
				return *reinterpret_cast<const ULONG_PTR*>(X);
			}
		}
	}

	return NULL;
}

//0.90 - 0.92
ULONG_PTR ScyllaTELock::fixType2(ULONG_PTR InvalidApiAddress)
{	
	const uint8_t PUSH_DW[] = {0xFF, 0x35};
	const uint8_t RETN = 0x3C;

	static const uint8_t pattern[] =
	{
		PUSH_DW[0], PUSH_DW[1], 1, 1, 1, 1,
		0, 0, 0, 0
	};
	static const char mask[] = "XX????????";

	const size_t offs_x = 2;
	const size_t offs_retn_1 = 8;
	const size_t offs_retn_2 = 9;

	/*
	PUSH DWORD [X]
	<2-3 bytes junk>
	RETN
	<1 byte junk if only 2 before RETN>
	*/

	const uint8_t* bPtr = reinterpret_cast<const uint8_t*>(InvalidApiAddress);

	if(validMemory(InvalidApiAddress, sizeof(pattern)))
	{
		if(findPattern(bPtr, sizeof(pattern), pattern, sizeof(pattern), mask))
		{
			if(bPtr[offs_retn_1] == RETN || bPtr[offs_retn_2] == RETN)
			{
				uint32_t X = *reinterpret_cast<const uint32_t*>(bPtr+offs_x);
				if(validMemory(X, sizeof(ULONG_PTR)))
				{
					return *reinterpret_cast<const ULONG_PTR*>(X);
				}
			}
		}
	}

	return NULL;
}

//0.95 - 0.96
ULONG_PTR ScyllaTELock::fixType3(ULONG_PTR InvalidApiAddress)
{
	const uint8_t MOV_EAX = 0xB8;
	const uint8_t JMP_DW_EAX[] = {0xFF, 0x20};
	const uint8_t PUSH_DW_EAX[] = {0xFF, 0x30};
	const uint8_t RETN = 0x3C;

	static const uint8_t pattern_1[] =
	{
		MOV_EAX, 1, 1, 1, 1,
		JMP_DW_EAX[0], JMP_DW_EAX[1]
	};
	static const uint8_t pattern_2[] =
	{
		MOV_EAX, 1, 1, 1, 1,
		PUSH_DW_EAX[0], PUSH_DW_EAX[1],
		RETN
	};

	static const char mask[] = "X????XXX";

	const size_t offs_x = 1;

	const size_t MAX_BYTES = 35;

	/*
	<code>
	MOV EAX, X
	JMP DWORD [EAX] ; or PUSH DWORD [EAX] + RETN
	*/

	const uint8_t* bPtr = reinterpret_cast<const uint8_t*>(InvalidApiAddress);

	if(validMemory(InvalidApiAddress, MAX_BYTES + std::max(sizeof(pattern_1), sizeof(pattern_2))))
	{
		const uint8_t* found;
		if((found = findPattern(bPtr, MAX_BYTES + sizeof(pattern_1), pattern_1, sizeof(pattern_1), mask)) ||
		   (found = findPattern(bPtr, MAX_BYTES + sizeof(pattern_2), pattern_2, sizeof(pattern_2), mask)))
		{
			uint32_t X = *reinterpret_cast<const uint32_t*>(found+offs_x);
			if(validMemory(X, sizeof(ULONG_PTR)))
			{
				return *reinterpret_cast<const ULONG_PTR*>(X);
			}
		}
	}

	return NULL;
}

//0.98
ULONG_PTR ScyllaTELock::fixType4(ULONG_PTR InvalidApiAddress)
{
	const uint8_t MOV_EAX = 0xB8;
	const uint8_t INC_EAX = 0x40;
	const uint8_t PUSH_DW_EAX[] = {0xFF, 0x30};
	const uint8_t RETN = 0x3C;

	static const uint8_t pattern[] =
	{
		MOV_EAX, 1, 1, 1, 1,
		INC_EAX,
		PUSH_DW_EAX[0], PUSH_DW_EAX[1],
		RETN
	};

	static const char mask[] = "X????XXXX";

	const size_t offs_x = 1;

	const size_t MAX_BYTES = 35;

	/*
	<code>
	MOV EAX, X
	INC EAX
	PUSH DWORD [EAX]
	RETN
	*/

	const uint8_t* bPtr = reinterpret_cast<const uint8_t*>(InvalidApiAddress);

	if(validMemory(InvalidApiAddress, MAX_BYTES + sizeof(pattern)))
	{
		const uint8_t* found = findPattern(bPtr, MAX_BYTES + sizeof(pattern), pattern, sizeof(pattern), mask);
		if(found)
		{
			uint32_t X = *reinterpret_cast<const uint32_t*>(found+offs_x);
			X++;
			if(validMemory(X, sizeof(ULONG_PTR)))
			{
				return *reinterpret_cast<const ULONG_PTR*>(X);
			}
		}
	}

	return NULL;
}

//0.99
ULONG_PTR ScyllaTELock::fixType5(ULONG_PTR InvalidApiAddress)
{
	return NULL;

	const uint8_t MOV_EAX = 0xB8;
	const uint8_t INC_EAX = 0x40;
	const uint8_t PUSH_DW_EAX[] = {0xFF, 0x30};
	const uint8_t RETN = 0x3C;

	static const uint8_t pattern[] =
	{
		MOV_EAX, 1, 1, 1, 1,
		INC_EAX,
		PUSH_DW_EAX[0], PUSH_DW_EAX[1],
		RETN
	};

	static const char mask[] = "X????XXXX";

	const size_t offs_x = 1;

	const size_t MAX_BYTES = 35;

	/*
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

	const uint8_t* bPtr = reinterpret_cast<const uint8_t*>(InvalidApiAddress);

	if(validMemory(InvalidApiAddress, MAX_BYTES + sizeof(pattern)))
	{
		const uint8_t* found = findPattern(bPtr, MAX_BYTES + sizeof(pattern), pattern, sizeof(pattern), mask);
		if(found)
		{
			uint32_t X = *reinterpret_cast<const uint32_t*>(found+offs_x);
			if(validMemory(X, sizeof(ULONG_PTR)))
			{
				return *reinterpret_cast<const ULONG_PTR*>(X);
			}
		}
	}

	return NULL;
}

ULONG_PTR ScyllaTELock::resolveImport(ULONG_PTR ImportTableAddressPointer, ULONG_PTR InvalidApiAddress, ScyllaStatus& Status)
{
	if(!validMemory(InvalidApiAddress, 1))
	{
		log("Invalid memory address\r\n");
		Status = SCYLLA_STATUS_IMPORT_RESOLVING_FAILED;
		return NULL;
	}

	ULONG_PTR resolved;

	if((resolved = fixType1(InvalidApiAddress)) ||
	   (resolved = fixType2(InvalidApiAddress)) ||
	   (resolved = fixType3(InvalidApiAddress)) ||
	   (resolved = fixType4(InvalidApiAddress)) ||
	   (resolved = fixType5(InvalidApiAddress)))
	{
		return resolved;
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
