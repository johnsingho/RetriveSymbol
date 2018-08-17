#include <cstdio>
#include <Windows.h>

#define DBGHELP_TRANSLATE_TCHAR
#include <DbgHelp.h>
#include <tchar.h>
#include <cstring>
#include <cstdlib>

// Link with the dbghelp import library
#pragma comment(lib, "dbghelp.lib")

const TCHAR* FMT_MS_SYMPATH = _T("srv*%s*https://msdl.microsoft.com/download/symbols");

static
bool ReadPEHeader(const TCHAR* fileName, DWORD* pdateStamp, DWORD* pnImageSize)
{
	HANDLE hExecutable = CreateFile(fileName, GENERIC_READ, FILE_SHARE_READ, 
									NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hExecutable == INVALID_HANDLE_VALUE) {
		return false;
	};

	HANDLE hExecutableMapping = CreateFileMapping(hExecutable, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hExecutableMapping == 0) {
		CloseHandle(hExecutable);
		return false;
	}

	LPVOID pMappedBase = MapViewOfFile(hExecutableMapping, FILE_MAP_READ, 0, 0, 0);
	if (pMappedBase == 0) {
		CloseHandle(hExecutableMapping);
		CloseHandle(hExecutable);
		return false;
	}

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pMappedBase;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD)dosHeader + (DWORD)dosHeader->e_lfanew);
	*pdateStamp = ntHeader->FileHeader.TimeDateStamp;
	*pnImageSize = ntHeader->OptionalHeader.SizeOfImage;

	///////////////////////////////////////
	CloseHandle(hExecutableMapping);
	CloseHandle(hExecutable);
	return true;
}

int _tmain(int argc, _Pre_readable_size_(argc) TCHAR* argv[])
{
	// Tell dbghelp to print diagnostics to the debugger output.
	SymSetOptions(SYMOPT_DEBUG);

	// Initialize dbghelp
	//const HANDLE fakeProcess = reinterpret_cast<const HANDLE>(1);
	//const HANDLE fakeProcess = GetCurrentProcess();
	const HANDLE fakeProcess = reinterpret_cast<const HANDLE>(rand());
	const BOOL initResult = SymInitialize(fakeProcess, NULL, FALSE);
	if (initResult == FALSE)
	{
		_tprintf_s(_T("SymInitialize failed!! Error: %u\n"), ::GetLastError());
		return -1;
	}


	TCHAR *symbolPath = NULL;
	size_t len = 0;
	errno_t err = _tdupenv_s(&symbolPath, &len, _T("_NT_SYMBOL_PATH"));
	if (0 == err && (symbolPath && symbolPath[0])) {
	   _tprintf_s(_T("_NT_SYMBOL_PATH=%s\n"), symbolPath);	   
   }     
   else {
	   TCHAR msSymPath[1024];
	   TCHAR szTemp[512] = { 0 };
	   GetModuleFileName(NULL, szTemp, _countof(szTemp));
	   TCHAR* pLastSlash = _tcsrchr(szTemp, _T('\\'));
	   if (pLastSlash) {
		   *pLastSlash = NULL;
	   }
	   //!test
	   _tcscpy_s(szTemp, _T("d:\\temp"));
	   _stprintf_s(msSymPath, FMT_MS_SYMPATH, szTemp);
	   _tputenv_s(_T("_NT_SYMBOL_PATH"), msSymPath);
	   _tprintf_s(_T("_NT_SYMBOL_PATH is not set. Use default.\n\n"));
   }     
   free(symbolPath);


   if (argc < 2)
   {
       _tprintf_s(_T("Error: insufficient arguments.\n"));
       _tprintf_s(_T("Usage: %s peName\n"), argv[0]);
       _tprintf_s(_T("Example: %s c:\\Windows\\SysWOW64\\ntdll.dll\n"), argv[0]);
       return 0;
   }

   PCTSTR const fileName = argv[1];
   DWORD dateStamp = 0;
   DWORD nImageSize = 0;
   DWORD flags = SSRVOPT_DWORDPTR/* | SYMOPT_INCLUDE_32BIT_MODULES*/;

   PCTSTR const ext = _tcsrchr(fileName, _T('.'));
   if (!ext)
   {
     _tprintf_s(_T("No extension found on %s. Fatal error.\n"), fileName);
     return -1;
   }

   if (!ReadPEHeader(fileName, &dateStamp, &nImageSize)) {
	   _tprintf_s(_T("Read file error: %s\n"), fileName);
	   return -2;
   }
   _tprintf_s(_T("Looking for PE file %s, DateStamp:%X, ImageSize:%X.\n"), fileName, dateStamp, nImageSize);

   TCHAR filePath[MAX_PATH+1] = {0};
   DWORD three = 0;

   if (SymFindFileInPath(fakeProcess, NULL, fileName, &dateStamp, nImageSize, three, flags, filePath, NULL, NULL))
   {
       _tprintf_s(_T("Found file - placed it in %s.\n"), filePath);
   }
   else
   {
       _tprintf_s(_T("Error: symbols not found - error %u. \n"
               "Are dbghelp.dll and symsrv.dll in the same directory as this executable?\n"),
               GetLastError());
       _tprintf_s(_T("Note that symbol server lookups sometimes fail randomly. "
              "May need again.\n"));
   }

   const BOOL cleanupResult = SymCleanup(fakeProcess);
   if (cleanupResult == FALSE)
   {
      _tprintf_s(_T("SymCleanup failed!! Error: %u\n"), ::GetLastError());
   }

   return 0;
}
