#define SCYLLA_NO_X64

#include <windows.h>
#include "Scylla++.h"

#define PLUGIN_NAME "PE123" //???

class ScyllaPE123 : public ScyllaPlugin
{
public:
	virtual ~ScyllaPE123() { }

	virtual ULONG_PTR resolveImport(ULONG_PTR, ULONG_PTR, ScyllaStatus&);
};

ULONG_PTR ScyllaPE123::resolveImport(ULONG_PTR ImportTableAddressPointer, ULONG_PTR InvalidApiAddress, ScyllaStatus& Status)
{
	//PECompact example
	//01BF01FF     B8 45128275         MOV EAX,kernel32.GetModuleHandleA
	//01BF0204   - FFE0                JMP EAX

	const BYTE OPC_MOV_EAX = 0xB8;
	const WORD OPC_JMP_EAX = 0xE0FF;

	if(*reinterpret_cast<const BYTE*>(InvalidApiAddress) == OPC_MOV_EAX) //is it pe compact?
	{
		if(*reinterpret_cast<const WORD*>(InvalidApiAddress+1+sizeof(ULONG_PTR)) == OPC_JMP_EAX)
		{
			//return right value
			return *reinterpret_cast<const ULONG_PTR*>(InvalidApiAddress+1);
		}
	}

	log("Unsupported opcode found\r\n");
	Status = SCYLLA_STATUS_UNSUPPORTED_PROTECTION;
	return NULL;
}

ScyllaPE123 plugin;

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

#ifdef UNICODE
DllExport wchar_t * __cdecl ScyllaPluginNameW()
{
	return TEXT(PLUGIN_NAME);
}
#else
DllExport char * __cdecl ScyllaPluginNameA()
{
	return PLUGIN_NAME;
}
#endif
