#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <cstring>
#include <cassert>

#if (defined(_M_X64) || defined(__amd64__))
	#if defined(SCYLLA_NO_X64)
		#error Unsupported architecture
	#endif
#else
	#if defined(SCYLLA_NO_X86)
		#error Unsupported architecture
	#endif
#endif

namespace scylla
{
#include "ScyllaPlugin.h"
}

class ScyllaPlugin
{
public:

	typedef BYTE ScyllaStatus;

	ScyllaPlugin(const wchar_t* logFile = L"logfile_scylla_plugin.txt") : valid_(false), hMapFile_(NULL), lpViewOfFile_(NULL), scyllaExchange(NULL), scyllaImports(NULL)
	{
		assert(logFile != NULL);

		initLog(logFile);

		hMapFile_ = OpenFileMappingA(FILE_MAP_ALL_ACCESS, 0, scylla::FILE_MAPPING_NAME);
		if(hMapFile_)
		{
			lpViewOfFile_ = MapViewOfFile(hMapFile_, FILE_MAP_ALL_ACCESS,	0, 0, 0);
			if(lpViewOfFile_)
			{
				scyllaExchange = reinterpret_cast<scylla::SCYLLA_EXCHANGE*>(lpViewOfFile_);
				scyllaImports = reinterpret_cast<scylla::UNRESOLVED_IMPORT*>(reinterpret_cast<char*>(lpViewOfFile_) + scyllaExchange->offsetUnresolvedImportsArray);
				valid_ = true;
				scyllaExchange->status = SCYLLA_STATUS_SUCCESS;
			}
		}
	}

	~ScyllaPlugin() { cleanUp(); }

	bool valid() const { return valid_; }

	void cleanUp()
	{
		if(lpViewOfFile_)
			UnmapViewOfFile(lpViewOfFile_);
		if(hMapFile_)
			CloseHandle(hMapFile_);
	}

	virtual void resolveAllImports()
	{
		if(!valid())
			return;

		scyllaExchange->status = SCYLLA_STATUS_UNKNOWN_ERROR; // in case we crash

		ScyllaStatus newStatus = SCYLLA_STATUS_SUCCESS;

		for(ULONG_PTR i = 0; i < scyllaExchange->numberOfUnresolvedImports; i++)
		{
			ScyllaStatus tempStatus = SCYLLA_STATUS_SUCCESS;
			ULONG_PTR resolved = resolveImport(scyllaImports[i].ImportTableAddressPointer, scyllaImports[i].InvalidApiAddress, tempStatus);
			if(tempStatus == SCYLLA_STATUS_SUCCESS)
			{
				scyllaImports[i].InvalidApiAddress = resolved;
			}
			else
			{
				newStatus = tempStatus;
				if(tempStatus == SCYLLA_STATUS_UNKNOWN_ERROR) // abort
					break;
			}
		}

		scyllaExchange->status = newStatus;
	}

	bool log(const char* text)
	{
		assert(text != NULL);

		bool success = false;
		if(logFile_[0])
		{
			//open log file for writing
			HANDLE hFile = CreateFileW(logFile_, GENERIC_WRITE, 0, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
			if(hFile != INVALID_HANDLE_VALUE)
			{
				DWORD lpNumberOfBytesWritten = 0;
				SetFilePointer(hFile, 0, 0, FILE_END);
				success = WriteFile(hFile, text, strlen(text), &lpNumberOfBytesWritten, 0) == TRUE;		
				CloseHandle(hFile);
			}
		}
		return success;
	}

protected:

	// Implement this in your plugin
	// It's called for every invalid API, return value is the valid API
	// Set Status in case of failure:
	// - SCYLLA_STATUS_IMPORT_RESOLVING_FAILED: InvalidApiAddress is not valid memory (check before reading from it!)
	// - SCYLLA_STATUS_UNSUPPORTED_PROTECTION: Unrecognized protection (duh)
	// - SCYLLA_STATUS_UNKNOWN_ERROR: fatal error (aborts whole plugin!)
	virtual ULONG_PTR resolveImport(ULONG_PTR ImportTableAddressPointer, ULONG_PTR InvalidApiAddress, ScyllaStatus& Status) = 0;

	bool validMemory(ULONG_PTR addr, size_t size)
	{
		return FALSE == IsBadReadPtr(reinterpret_cast<const void*>(addr), size);
	}

	const BYTE* findPattern(const BYTE* buffer, size_t buffer_size, const BYTE* pattern, size_t pattern_size, const char* mask)
	{
		assert(pattern_size <= buffer_size);
		assert(!mask || strlen(mask) >= pattern_size);

		const BYTE* found = NULL;

		for(size_t i = 0; i < (buffer_size-pattern_size+1) && !found; i++)
		{
			found = buffer+i;
			for(size_t j = 0; j < pattern_size; j++)
			{
				bool ignore = (mask && mask[j] == '?');
				if(!ignore && pattern[j] != found[j])
				{
					found = 0;
					break;
				}
			}
		}

		return found;
	}

	scylla::SCYLLA_EXCHANGE* scyllaExchange;
	scylla::UNRESOLVED_IMPORT* scyllaImports;

	bool valid_;

private:

	bool initLog(const wchar_t* file)
	{
		assert(file != NULL);

		//get full path of exe
		if(GetModuleFileNameW(NULL, logFile_, _countof(logFile_)))
		{
			//remove the exe file name from full path
			wchar_t* found = wcsrchr(logFile_, L'\\');
			if(found)
				*(found+1) = L'\0';
			//append log file name to path
			wcscat_s(logFile_, file);
			// Clear file
			HANDLE hFile = CreateFileW(logFile_, GENERIC_WRITE, 0, 0, TRUNCATE_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
			if(hFile != INVALID_HANDLE_VALUE)
				CloseHandle(hFile);
			return true;
		}
		return false;
	}

	HANDLE hMapFile_;
	LPVOID lpViewOfFile_;
	wchar_t logFile_[MAX_PATH];
};
