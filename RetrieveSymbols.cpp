#include <cstdio>
#include <Windows.h>
#include <tchar.h>
#include <cstring>
#include <cstdlib>
#include <string>

#ifdef _UNICODE
typedef  std::wstring tstring;
#define DBGHELP_TRANSLATE_TCHAR
#else
typedef  std::string tstring;
#endif

#include <DbgHelp.h>
// Link with the dbghelp import library
#pragma comment(lib, "dbghelp.lib")


const TCHAR* FMT_MS_SYMPATH = _T("SRV*%s*https://msdl.microsoft.com/download/symbols");

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

static 
bool DecodeArgs(TCHAR* const argv[], void** ppID, DWORD* pTwo, DWORD* pflag)
{
	PCTSTR const fileName = argv[3];
	tstring gTextArg = argv[1];
	PCTSTR const dateStampText = argv[1];
	PCTSTR const ageText = argv[2];
	PCTSTR const sizeText = argv[2];

	// Parse the GUID and age from the text
	static GUID g = {};
	static DWORD dateStamp = 0;
	DWORD age = 0;	
	DWORD size = 0;

	// Settings for SymFindFileInPath
	void* id = nullptr;
	DWORD flags = 0;
	DWORD two = 0;

	PCTSTR const ext = _tcsrchr(fileName, _T('.'));
	if (!ext)
	{
		_tprintf_s(_T("No extension found on %s. Fatal error.\n"), fileName);
		return false;
	}

	if (_tcsicmp(ext, _T(".pdb")) == 0)
	{
		tstring gText;
		// Scan the GUID argument and remove all non-hex characters. This allows
		// passing GUIDs with '-', '{', and '}' characters.
		for (auto c : gTextArg)
		{
			if (isxdigit(static_cast<unsigned char>(c)))
			{
				gText.push_back(c);
			}
		}
		if (gText.size() != 32)
		{
			_tprintf_s(_T("Error: PDB GUIDs must be exactly 32 characters"
				          " (%s was stripped to %s).\n"), gTextArg.c_str(), gText.c_str());
			return false;
		}

		int count = _stscanf_s(gText.substr(0, 8).c_str(), _T("%x"), &g.Data1);
		DWORD temp;
		count += _stscanf_s(gText.substr(8, 4).c_str(), _T("%x"), &temp);
		g.Data2 = (unsigned short)temp;
		count += _stscanf_s(gText.substr(12, 4).c_str(), _T("%x"), &temp);
		g.Data3 = (unsigned short)temp;
		for (auto i = 0; i < ARRAYSIZE(g.Data4); ++i)
		{
			count += _stscanf_s(gText.substr(16 + i * 2, 2).c_str(), _T("%x"), &temp);
			g.Data4[i] = (unsigned char)temp;
		}
		count += _stscanf_s(ageText, _T("%x"), &age);

		if (count != 12)
		{
			_tprintf_s(_T("Error: couldn't parse the PDB GUID/age string. Sorry.\n"));
			return false;
		}
		flags = SSRVOPT_GUIDPTR;
		id = &g;
		two = age;
		_tprintf_s(_T("Looking for PDB file %s %s %s.\n"), gText.c_str(), ageText, fileName);
	}
	else
	{
		if (_tcslen(dateStampText) != 8)
			_tprintf_s(_T("Warning!!! The datestamp (%s) is not eight characters long. "
						  "This is usually wrong.\n"), dateStampText);
		int count = _stscanf_s(dateStampText, _T("%x"), &dateStamp);
		count += _stscanf_s(sizeText, _T("%x"), &size);
		flags = SSRVOPT_DWORDPTR;
		id = &dateStamp;
		two = size;
		_tprintf_s(_T("Looking for PE file %s %X %X.\n"), fileName, dateStamp, two);
	}
	
	*ppID = id;
	*pTwo = two;
	*pflag = flags;

	return true;
}

static 
const TCHAR* MakeDownFileName(const TCHAR* filePath) {
	static TCHAR szFileName[256] = { 0 };
	const TCHAR* pPos = _tcsrchr(filePath, _T('\\'));
	pPos = pPos ? pPos + 1 : filePath;
	_tcscpy_s(szFileName, pPos);
	//TCHAR* pLast = _tcsrchr(szFileName, _T('.'));
	//if (pLast) {
	//	const TCHAR* EXT_PDB = _T(".pdb");
	//	int nCopy = _tcslen(EXT_PDB) + 1;
	//	_tcscpy_s(pLast, nCopy, EXT_PDB);
	//}
	return szFileName;
}


BOOL CALLBACK SymCallback(HANDLE process,
	ULONG action,
	ULONG64 data,
	ULONG64 context)
{
	switch (action) {
		case CBA_EVENT: 
		{
			IMAGEHLP_CBA_EVENT *cba_event = reinterpret_cast<IMAGEHLP_CBA_EVENT *>(data);
			_tprintf(_T("%s"), (PCTSTR)cba_event->desc);
			return TRUE;
		}
		break;
	};

	return FALSE;
}

BOOL CALLBACK SymFindFileInPathCB(
	_In_ PCTSTR fileName,
	_In_ PVOID  context
) 
{
	_tprintf_s(_T("get symbol: %s\n"), fileName);
	return FALSE; //找到一个就不继续了
}


/////////////////////////////////////////////////////////////////

// Uncomment this line to test with known-good parameters.
//#define TESTING

int _tmain(int argc, _Pre_readable_size_(argc) TCHAR* argv[])
{
	if (2 != argc && 4 != argc)
	{
		_tprintf_s(_T("符号文件下载器 (by john)\n"));
		_tprintf_s(_T("Error: insufficient arguments.\n"));
		_tprintf_s(_T("Usage: %s peName\n"), argv[0]);
		_tprintf_s(_T("\tExample: %s c:\\Windows\\SysWOW64\\ntdll.dll\n"), argv[0]);
		_tprintf_s(_T("Usage: %s guid age pdbname\n"), argv[0]);
		_tprintf_s(_T("Usage: %s dateStamp size pename\n"), argv[0]);
		_tprintf_s(_T("\tExample: %s 6720c31f4ac24f3ab0243e0641a4412f 1 chrome_child.dll.pdb\n"), argv[0]);
		_tprintf_s(_T("\tExample: %s 4802A0D7 95000 crypt32.dll\n"), argv[0]);
		return 0;
	}

	// Tell dbghelp to print diagnostics to the debugger output.
	DWORD dwOpt = SymGetOptions();
	dwOpt = dwOpt | SYMOPT_DEBUG | SYMOPT_SECURE | SYMOPT_CASE_INSENSITIVE
		          | SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_EXACT_SYMBOLS;
	SymSetOptions(dwOpt);

	// Initialize dbghelp
	//const HANDLE fakeProcess = reinterpret_cast<const HANDLE>(1);
	const HANDLE fakeProcess = GetCurrentProcess();
	//const HANDLE fakeProcess = reinterpret_cast<const HANDLE>(rand());

	TCHAR *symbolPath = NULL;
	TCHAR msSymPath[1024] = { 0 };
	size_t len = 0;
	errno_t err = _tdupenv_s(&symbolPath, &len, _T("_NT_SYMBOL_PATH"));
	if (0 == err && (symbolPath && symbolPath[0])) {
		_tprintf_s(_T("_NT_SYMBOL_PATH=%s\n"), symbolPath);
		_tcscpy_s(msSymPath, symbolPath);
	}
	else {
		TCHAR szTemp[512] = { 0 };
		GetModuleFileName(NULL, szTemp, _countof(szTemp));
		TCHAR* pLastSlash = _tcsrchr(szTemp, _T('\\'));
		if (pLastSlash) {
			*pLastSlash = NULL;
		}

		//_tcscpy_s(szTemp, _T("d:\\temp"));
		_stprintf_s(msSymPath, FMT_MS_SYMPATH, szTemp);
		_tputenv_s(_T("_NT_SYMBOL_PATH"), msSymPath);
		_tprintf_s(_T("_NT_SYMBOL_PATH is not set. Use default.\n\n"));
	}
	free(symbolPath);
	
	const BOOL initResult = SymInitialize(fakeProcess, msSymPath, FALSE);
	if (initResult == FALSE)
	{
		_tprintf_s(_T("SymInitialize failed!! Error: %u\n"), ::GetLastError());
		return -1;
	}

   //SymFindFileInPath is annotated_Out_writes_(MAX_PATH + 1)
   //thus, passing less than (MAX_PATH+1) is an overrun!
   //The documentation says the buffer needs to be MAX_PATH - hurray for
   //consistency - but better safe than owned.
   TCHAR filePath[MAX_PATH + 1] = { 0 };
   const TCHAR* fileName = NULL;
   DWORD dateStamp = 0;
   void* pID = NULL;
   DWORD two = 0;
   DWORD flags = 0;
   
   if (2 == argc) {
	   fileName = argv[1];
	   if (!ReadPEHeader(fileName, &dateStamp, &two)) {
		   _tprintf_s(_T("Read file error: %s\n"), fileName);
		   return -2;
	   }
	   fileName = MakeDownFileName(argv[1]);
	   flags = SSRVOPT_DWORDPTR;
	   pID = &dateStamp;
	   _tprintf_s(_T("Looking for PE file %s, DateStamp:%X, ImageSize:%X.\n"), fileName, dateStamp, two);
   }
   else if(4==argc) {
	   fileName = MakeDownFileName(argv[3]);
	   if (!DecodeArgs(argv, &pID, &two, &flags)) {
		   _tprintf_s(_T("Parameters wrong!"));
		   return -3;
	   }
   }

   if (!SymRegisterCallback64(fakeProcess, SymCallback, NULL))
   {
	   _tprintf_s(_T("Failed to SymRegisterCallback64()!"));
   }

   DWORD three = 0;
   if (SymFindFileInPath(fakeProcess, NULL, fileName, pID, two, three, flags, filePath, SymFindFileInPathCB, NULL))
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
