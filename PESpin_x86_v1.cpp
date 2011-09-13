#define SCYLLA_NO_X64

#include <windows.h>
#include "Scylla++.h"
#include "stdint.h"
#include "distorm.h"
#include <vector>

const wchar_t PLUGIN_NAME[] = L"PESpin v1.x"; // tested with <= 1.33

class ScyllaPESpin : public ScyllaPlugin
{
	virtual ULONG_PTR resolveImport(ULONG_PTR, ULONG_PTR, ScyllaStatus&);
};

template<typename T> const uint8_t* follow_jump(const uint8_t* buf)
{
	buf += *reinterpret_cast<const T*>(buf+sizeof(uint8_t));
	buf += sizeof(uint8_t) + sizeof(T);
	return buf;
}

std::vector<_DecodedInst> disasm(const void* buffer, size_t size)
{
	const size_t MAX_INSTRUCTIONS = 100; // min is 15
	std::vector<_DecodedInst> decodedInstructions(MAX_INSTRUCTIONS);
	unsigned int decodedInstructionsCount = 0;

	_DecodeResult res = distorm_decode(0, reinterpret_cast<const unsigned char*>(buffer), size, Decode32Bits, &decodedInstructions.front(), MAX_INSTRUCTIONS, &decodedInstructionsCount);
	decodedInstructions.resize(decodedInstructionsCount);
	return decodedInstructions;
}

ULONG_PTR ScyllaPESpin::resolveImport(ULONG_PTR ImportTableAddressPointer, ULONG_PTR InvalidApiAddress, ScyllaStatus& Status)
{
	const uint8_t OPC_JMP_SHRT = 0xEB;
	const uint16_t OPC_JMP_LONG = 0xE9;

	const size_t MAX_BYTES = 40;

	/*
	 * //JMP LONG x_ // optional
	 * x_:
	 * JMP SHORT y_
	 * <junk byte>
	 * y_:
	 * <original>
	 * <API>
	 * <instructions>
	 * <...>
	 * JMP SHORT z_1:
	 * <junk>
	 * z_2:
	 * JMP LONG API+skipped_instructions
	 * z_1:
	 * JMP SHORT z_2:
	 */

	if(!validMemory(InvalidApiAddress, sizeof(OPC_JMP_SHRT) + sizeof(int8_t)))
	{
		log("Invalid memory address\r\n");
		Status = SCYLLA_STATUS_IMPORT_RESOLVING_FAILED;
		return NULL;
	}

	const uint8_t* bPtr = reinterpret_cast<const uint8_t*>(InvalidApiAddress);

	/*
	// Private version?
	if(*bPtr == OPC_JMP_LONG)
	{
		bPtr = follow_jump<int32_t>(bPtr);
	}
	*/

	if(bPtr[0] == OPC_JMP_SHRT && bPtr[1] == 0x01) // JMP +1
	{
		bPtr = follow_jump<int8_t>(bPtr);

		if(validMemory(reinterpret_cast<ULONG_PTR>(bPtr), MAX_BYTES))
		{
			size_t skipped = 0;
			bool found = false;
			std::vector<_DecodedInst> instructions = disasm(bPtr, MAX_BYTES);
			for(size_t i = 0; i < instructions.size(); i++)
			{
				if(bPtr[0] == OPC_JMP_SHRT && bPtr[1] == 0x07) // JMP +7
				{
					found = true;
					break;
				}
				skipped += instructions[i].size;
				bPtr += instructions[i].size;
			}

			if(found)
			{
				bPtr = follow_jump<int8_t>(bPtr);
				if(bPtr[0] == OPC_JMP_SHRT && bPtr[1] == 0xF8) // JMP -8
				{
					bPtr = follow_jump<int8_t>(bPtr);
					if(*bPtr == OPC_JMP_LONG) // JMP API
					{
						bPtr = follow_jump<int32_t>(bPtr);
						ULONG_PTR resolved = reinterpret_cast<ULONG_PTR>(bPtr);
						return resolved - skipped;
					}
				}
			}
		}
	}

	log("Unsupported opcode found\r\n");
	Status = SCYLLA_STATUS_UNSUPPORTED_PROTECTION;
	return NULL;
}

ScyllaPESpin plugin;

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
