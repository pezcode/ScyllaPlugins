#define SCYLLA_NO_X64

#include <windows.h>
#include "Scylla++.h"
#include <cstdint>

// tested

const wchar_t PLUGIN_NAME[] = L"Krypton"; // 0.2, 0.3, 0.5

class ScyllaKrypton : public ScyllaPlugin
{
	virtual ULONG_PTR resolveImport(ULONG_PTR, ULONG_PTR, ScyllaStatus&);
};

ULONG_PTR ScyllaKrypton::resolveImport(ULONG_PTR ImportTableAddressPointer, ULONG_PTR InvalidApiAddress, ScyllaStatus& Status)
{
	const uint8_t XXX_DW[] = {0x81, 0 /*type*/};
	const uint8_t MOV_EAX_DW = 0xA1;
	const uint8_t JMP_EAX[] = {0xFF, 0xE0};

	const uint8_t TYPE_ADD = 0x05;
	const uint8_t TYPE_SUB = 0x2D;
	const uint8_t TYPE_XOR = 0x35;

	static const uint8_t pattern[] =
	{
		XXX_DW[0], 0, 1, 1, 1, 1, 2, 2, 2, 2,
		MOV_EAX_DW, 1, 1, 1, 1,
		XXX_DW[0], 0, 1, 1, 1, 1, 2, 2, 2, 2,
		JMP_EAX[0], JMP_EAX[1]
	};
	static const char mask[] = "X?????????X????X?????????XX";

	const size_t offs_type_1 = 1;
	const size_t offs_type_2 = 16;
	const size_t offs_x_1 = 2;
	const size_t offs_x_2 = 11;
	const size_t offs_x_3 = 17;
	const size_t offs_y_1 = 6;
	const size_t offs_y_2 = 21;

	/*
	ADD DWORD [X], Y   ; XOR
	MOV EAX, DWORD [X]
	SUB DWORD [X], Y   ; XOR
	JMP EAX
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
		uint32_t X1 = *reinterpret_cast<const uint32_t*>(bPtr+offs_x_1);
		uint32_t X2 = *reinterpret_cast<const uint32_t*>(bPtr+offs_x_2);
		uint32_t X3 = *reinterpret_cast<const uint32_t*>(bPtr+offs_x_3);

		uint32_t Y1 = *reinterpret_cast<const uint32_t*>(bPtr+offs_y_1);
		uint32_t Y2 = *reinterpret_cast<const uint32_t*>(bPtr+offs_y_2);

		if(X1 == X2 && X2 == X3 && Y1 == Y2)
		{
			if(validMemory(X1, sizeof(ULONG_PTR)))
			{
				ULONG_PTR VAL_X = *reinterpret_cast<const ULONG_PTR*>(X1);

				uint8_t type1 = bPtr[offs_type_1];
				uint8_t type2 = bPtr[offs_type_2];

				if(type1 == TYPE_ADD && type2 == TYPE_SUB) {
					return VAL_X + Y1;
				} else if(type1 == TYPE_XOR && type2 == TYPE_XOR) {
					return VAL_X ^ Y1;
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
