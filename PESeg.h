#pragma once
#include <list>

template <class Ptr>
inline Ptr *PtrFromRva(void *base, ptrdiff_t offset)
{
	return reinterpret_cast<Ptr *>(static_cast<char *>(base) + offset);
}

// CodeView header
struct CV_HEADER
{
	DWORD CvSignature; // NBxx
	LONG  Offset;      // Always 0 for NB10
};

// CodeView NB10 debug information of a PDB 2.00 file (VS 6)
struct CV_INFO_PDB20
{
	CV_HEADER  Header;
	DWORD      Signature;
	DWORD      Age;
	BYTE       PdbFileName[1];
};

// CodeView RSDS debug information of a PDB 7.00 file
struct CV_INFO_PDB70
{
	DWORD      CvSignature;
	GUID       Signature;
	DWORD      Age;
	BYTE       PdbFileName[1];
};

// Retrieve the NT image header of an executable via the legacy DOS header.
static
IMAGE_NT_HEADERS *
GetNtHeader(void *fileMemory)
{
	IMAGE_DOS_HEADER *dosHeader = static_cast<PIMAGE_DOS_HEADER>(fileMemory);
	// Check DOS header consistency
	if (IsBadReadPtr(dosHeader, sizeof(IMAGE_DOS_HEADER))
		|| dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return 0;
	}
	// Retrieve NT header
	IMAGE_NT_HEADERS *ntHeaders = PtrFromRva<IMAGE_NT_HEADERS>(dosHeader, dosHeader->e_lfanew);
	if (IsBadReadPtr(ntHeaders, sizeof(ntHeaders->Signature))
		|| ntHeaders->Signature != IMAGE_NT_SIGNATURE
		|| IsBadReadPtr(&ntHeaders->FileHeader, sizeof(IMAGE_FILE_HEADER)))
	{
		return 0;
	}
	// Check magic
	const WORD magic = ntHeaders->OptionalHeader.Magic;
	if (magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC && magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		return 0;
	}

	// Check section headers
	IMAGE_SECTION_HEADER *sectionHeaders = IMAGE_FIRST_SECTION(ntHeaders);
	if (IsBadReadPtr(sectionHeaders, ntHeaders->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)))
	{
		return 0;
	}
	return ntHeaders;
}

// Find the COFF section an RVA belongs to and convert to file offset
static
bool
GetFileOffsetFromRVA(IMAGE_NT_HEADERS *ntHeaders, DWORD rva, DWORD *fileOffset)
{
	IMAGE_SECTION_HEADER *sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, sectionHeader++)
	{
		const DWORD sectionSize = sectionHeader->Misc.VirtualSize ?
			sectionHeader->Misc.VirtualSize : sectionHeader->SizeOfRawData;
		if ((rva >= sectionHeader->VirtualAddress) && (rva < sectionHeader->VirtualAddress + sectionSize))
		{
			const DWORD diff = sectionHeader->VirtualAddress - sectionHeader->PointerToRawData;
			*fileOffset = rva - diff;
			return true;
		}
	}
	return false;
}


// Retrieve debug directory and number of entries
static
bool GetDebugDirectory(IMAGE_NT_HEADERS *ntHeaders, void *fileMemory, IMAGE_DEBUG_DIRECTORY **debugDir, int *count)
{
	DWORD debugDirRva = 0;
	DWORD debugDirSize;
	*debugDir = 0;
	*count = 0;

	// Find the virtual address
	const bool is64Bit = ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
	if (is64Bit)
	{
		auto optionalHeader64 = reinterpret_cast<IMAGE_OPTIONAL_HEADER64 *>(&(ntHeaders->OptionalHeader));
		debugDirRva = optionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
		debugDirSize = optionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
	}
	else
	{
		auto optionalHeader32 = reinterpret_cast<IMAGE_OPTIONAL_HEADER32 *>(&(ntHeaders->OptionalHeader));
		debugDirRva = optionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
		debugDirSize = optionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
	}

	if (debugDirSize == 0)
		return true;
	// Look up in file
	DWORD debugDirOffset;
	if (!GetFileOffsetFromRVA(ntHeaders, debugDirRva, &debugDirOffset))
	{
		return false;
	}
	*debugDir = PtrFromRva<IMAGE_DEBUG_DIRECTORY>(fileMemory, debugDirOffset);
	if (IsBadReadPtr(*debugDir, debugDirSize) || debugDirSize < sizeof(IMAGE_DEBUG_DIRECTORY))
	{
		return false;
	}

	//与上等价
	//DWORD nSize = 0;
	//IMAGE_DEBUG_DIRECTORY* pDebugDic = (IMAGE_DEBUG_DIRECTORY*)ImageDirectoryEntryToDataEx(fileMemory, FALSE, IMAGE_DIRECTORY_ENTRY_DEBUG, &nSize, NULL);
	//if (!pDebugDic) {
	//	return false;
	//}
	//*debugDir = pDebugDic;

	*count = debugDirSize / sizeof(IMAGE_DEBUG_DIRECTORY);
	return debugDir;
}

// Return the PDB file of a Code View debug section
static
bool GetPDBFileOfCodeViewSection(void *debugInfo, DWORD size, char *pstrPDBFile, GUID *gSign, DWORD *pAge)
{
	static const DWORD CV_SIGNATURE_NB10 = 0x3031424e; // '01BN';
	static const DWORD CV_SIGNATURE_RSDS = 0x53445352; // 'SDSR';
	if (IsBadReadPtr(debugInfo, size) || size < sizeof(DWORD))
		return false;

	const DWORD cvSignature = *static_cast<DWORD *>(debugInfo);
	if (cvSignature == CV_SIGNATURE_NB10)
	{
		CV_INFO_PDB20 *cvInfo = static_cast<CV_INFO_PDB20 *>(debugInfo);
		if (IsBadReadPtr(debugInfo, sizeof(CV_INFO_PDB20)))
			return false;
		CHAR *pdbFileName = reinterpret_cast<CHAR *>(cvInfo->PdbFileName);
		if (IsBadStringPtrA(pdbFileName, UINT_MAX))
			return false;
		strcpy_s(pstrPDBFile, MAX_PATH, pdbFileName);
		return true;
	}
	if (cvSignature == CV_SIGNATURE_RSDS)
	{
		CV_INFO_PDB70 *cvInfo = static_cast<CV_INFO_PDB70 *>(debugInfo);
		if (IsBadReadPtr(debugInfo, sizeof(CV_INFO_PDB70)))
			return false;
		CHAR *pdbFileName = reinterpret_cast<CHAR *>(cvInfo->PdbFileName);
		if (IsBadStringPtrA(pdbFileName, UINT_MAX))
			return false;
		strcpy_s(pstrPDBFile, MAX_PATH, pdbFileName);
		*gSign = cvInfo->Signature;
		*pAge = cvInfo->Age;
		return true;
	}
	return false;
}

typedef struct _MyPdbFile
{
	char szPdb[MAX_PATH];
	GUID gSign;
	DWORD nAge;
} MyPdbFile;


// Collect all PDB files of all debug sections
static
void CollectPDBfiles(void *fileMemory, IMAGE_DEBUG_DIRECTORY *directoryBase, int count, std::list<MyPdbFile> &pdbFiles)
{
	for (int i = 0; i < count; i++, directoryBase++)
		if (directoryBase->Type == IMAGE_DEBUG_TYPE_CODEVIEW)
		{
			MyPdbFile pdbFile = { 0 };
			if (GetPDBFileOfCodeViewSection(static_cast<char *>(fileMemory) + directoryBase->PointerToRawData,
				directoryBase->SizeOfData, pdbFile.szPdb, &pdbFile.gSign, &pdbFile.nAge))
			{
				pdbFiles.push_back(pdbFile);
			}
		}
}


bool GetPDBFiles(PVOID pMappedBasee, std::list<MyPdbFile> &pdbFiles)
{
	bool success = false;

	do
	{
		IMAGE_NT_HEADERS *ntHeaders = GetNtHeader(pMappedBasee);
		if (!ntHeaders)
			break;

		int debugSectionCount;
		IMAGE_DEBUG_DIRECTORY *debugDir;
		if (!GetDebugDirectory(ntHeaders, pMappedBasee, &debugDir, &debugSectionCount))
			return false;
		if (debugSectionCount)
			CollectPDBfiles(pMappedBasee, debugDir, debugSectionCount, pdbFiles);
		success = true;
	} while (false);

	return success;
}
