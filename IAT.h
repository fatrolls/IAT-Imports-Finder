#include <psapi.h> //GetModuleInformation IAT
#include <tlhelp32.h> //MODULEENTRY32 IAT
#include <shlwapi.h> //PathFindFileName IAT
#include <DbgHelp.h> //detours, GetImports, PE information BaseAddressStart/End etc.
#include <unordered_set> //std::unordered_set<DWORD>
#include <unordered_map> //std::map
#include <string>
#include <algorithm>
#include <iterator>
#include <vector>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib") //GetModuleInformation IAT
#pragma comment(lib, "Shlwapi.lib") //PathFindFileName IAT

struct IAT_Module_Info
{
	DWORD ImageBase;
	DWORD ImageSize;
	BYTE* EntryPoint;
	char DllName[256];
	char DllFileName[1000];
};

static std::list<IAT_Module_Info> gs_ModuleList;

struct IAT_Import_Information
{
	DWORD IATAddress;
	char IATModuleName[256];
	char IATFunctionName[256];
};

static std::list<IAT_Import_Information> listOfIATImports;


BOOL SnapShotModules(DWORD dwPID)
{
	BOOL           bRet = TRUE;

	// Get all modules for this process:
	std::vector<HMODULE> hModules;
	const HMODULE hSelf = GetModuleHandle(NULL);
	{
		DWORD nModules;
		EnumProcessModules(GetCurrentProcess(), NULL, 0, &nModules);
		hModules.resize(nModules);
		EnumProcessModules(GetCurrentProcess(), &hModules[0], nModules, &nModules);
	}

	if (!hSelf)
	{
		//myprintf("Invalid Process Handle\n");
		return FALSE;
	}
	
	gs_ModuleList.clear();

	IAT_Module_Info modulefullInfo = { 0 };
	MODULEINFO modinfo = { 0 };
	char moduleName[256] = { 0 };
	char moduleFileName[1000] = { 0 };

	char myProcessFilePath[1000] = { 0 };
	GetModuleFileNameExA(GetCurrentProcess(), NULL, myProcessFilePath, 1000);
	LPCSTR MyProcessFileName = PathFindFileName(myProcessFilePath);
	for (auto hModule : hModules) {
		if (hModule == hSelf)
			continue;

		GetModuleInformation(GetCurrentProcess(), hModule, &modinfo, sizeof(modinfo));
		GetModuleBaseName(GetCurrentProcess(), hModule, moduleName, sizeof(moduleName) / sizeof(char));
		GetModuleFileName(hModule, moduleFileName, sizeof(moduleFileName) / sizeof(char));
		if (_strcmpi(moduleName, MyProcessFileName) == 0) continue;
		strcpy(modulefullInfo.DllName, moduleName);
		modulefullInfo.ImageSize = modinfo.SizeOfImage;
		modulefullInfo.ImageBase = (DWORD)modinfo.lpBaseOfDll;
		modulefullInfo.EntryPoint = (BYTE*)modinfo.EntryPoint;
		strcpy(modulefullInfo.DllFileName, moduleFileName);
		gs_ModuleList.push_back(modulefullInfo);
	}

	return TRUE;
}

/************************************************************************/
/*
Function : Retrieve API info by its addr and the module it belongs to
Params   : pBuf points to the image mapped to our space*/
/************************************************************************/
void GetAPIInfo(DWORD ptrAPI, const IAT_Module_Info *iat_module_info, DWORD ptrAPIObfuscated = NULL)
{
	//try to load the dll into our space
	HMODULE hDll = NULL;
	if (iat_module_info)
		hDll = GetModuleHandle(iat_module_info->DllName);
	if(!hDll)
		hDll = LoadLibrary(iat_module_info->DllFileName);
	if (!hDll)
		return;
	//now ask for info from Export
	PIMAGE_DOS_HEADER pDOSHDR = (PIMAGE_DOS_HEADER)hDll;
	PIMAGE_NT_HEADERS pNTHDR = (PIMAGE_NT_HEADERS)((BYTE *)pDOSHDR + pDOSHDR->e_lfanew);
	if (pNTHDR->OptionalHeader.NumberOfRvaAndSizes < IMAGE_DIRECTORY_ENTRY_EXPORT + 1)
		return;
	PIMAGE_EXPORT_DIRECTORY pExpDIR = (PIMAGE_EXPORT_DIRECTORY)
		((BYTE *)pDOSHDR
			+ pNTHDR->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	DWORD dwFunctions = pExpDIR->NumberOfFunctions;
	DWORD *ptrAddrFunc = (DWORD *)((BYTE *)pDOSHDR + pExpDIR->AddressOfFunctions);
	DWORD i = 0;

	//get index by address
	for (i = 0; i < dwFunctions; i++)
	{
		if (ptrAPIObfuscated && ((DWORD)pDOSHDR + ptrAddrFunc[i]) == ptrAPIObfuscated)
			break;
		if (!ptrAPIObfuscated && ((DWORD)pDOSHDR + ptrAddrFunc[i]) == *(DWORD*)ptrAPI)
			break;
	}

	//not match
	if (i == dwFunctions)
		return;

	//get name and ordinal
	DWORD dwNames = pExpDIR->NumberOfNames;
	DWORD *pNames = (DWORD *)((BYTE *)pDOSHDR + pExpDIR->AddressOfNames);
	WORD *pNameOrd = (WORD *)((BYTE *)pDOSHDR + pExpDIR->AddressOfNameOrdinals);
	DWORD j = 0;
	char *pszName = NULL;
	SIZE_T nLen = 0;
	//myprintf("hhhhh\n");
	for (j = 0; j < dwNames; j++)
	{
		if (pNameOrd[j] == i)
		{
			pszName = (char *)pDOSHDR + pNames[j];
			nLen = strlen(pszName);
			/*myprintf("%X\t%04X\t%s\n",
				*(DWORD *)ptrAPI,
				j,
				pszName
			);*/

			//Save information
			IAT_Import_Information iat_found = { 0 };
			iat_found.IATAddress = ptrAPI;
			strcpy(iat_found.IATFunctionName, pszName);
			strcpy(iat_found.IATModuleName, iat_module_info->DllName);
			listOfIATImports.push_back(iat_found);
			/*
			if(ptrAPIObfuscated)
				myprintf("Added Obfuscated %X %X, %s -> %s\n", ptrAPI, ptrAPIObfuscated, iat_module_info->DllName, pszName);
			else
				myprintf("Added %X %X, %s -> %s\n", ptrAPI, *(DWORD*)ptrAPI, iat_module_info->DllName, pszName);
			*/
		}
	}
}

/************************************************************************/
/*
Function : rebuild Import Info according to IAT
Params   : ptrIAT point to the page where IAT in
ppBuf [IN/OUT] is the memory space for the exe, may be updated
dwImageSize is the exe's image size                                                                  */
/************************************************************************/
void FixImport(DWORD dwPID, DWORD ptrIAT, DWORD ptrIATEnd, DWORD dwImageSize)
{
	if (gs_ModuleList.size() == 0) {
		//myprintf("No Modules loaded, can't fix anything\n");
		return;
	}

	//now verify every DWORD item is a valid FuncPtr with some dll.
	//we need to snapshot the process.
	std::list<IAT_Module_Info>::iterator it;
	IAT_Module_Info iat_module_info;
	//myprintf("ptrIAT = %X ptrIATEnd = %X\n", ptrIAT, ptrIATEnd);

	DWORD ptrIndex = ptrIAT;
	DWORD dwModBase = NULL;  //利用局部性原理，减少比较
	DWORD dwModSize = NULL;
	DWORD dwModHit = NULL;

	DWORD test = 0;

	while (TRUE)
	{
		//thz should always continue, even if BadPtr or invalid funcptr
		//myprintf("ptrIndex = %X\n", ptrIndex);
		if (ptrIndex <= ptrIATEnd
			&& (IsBadReadPtr((const void *)ptrIndex, sizeof(DWORD))
			|| IsBadReadPtr((const void *)*(DWORD *)ptrIndex, sizeof(DWORD))))
		{
			ptrIndex += sizeof(DWORD);
			continue;
		}

		//now we may end, be careful
		if (ptrIndex > ptrIATEnd
			&& (IsBadReadPtr((const void *)ptrIndex, sizeof(DWORD)) || *(DWORD*)ptrIndex == NULL)
			&& (IsBadReadPtr((const void *)(ptrIndex + sizeof(DWORD)), sizeof(DWORD)) || *(DWORD*)(ptrIndex + sizeof(DWORD)) == NULL))
		{
			break;
		}

		if (ptrIndex > ptrIATEnd
			&& (IsBadReadPtr((const void *)ptrIndex, sizeof(DWORD))
			|| IsBadReadPtr((const void *)*(DWORD *)ptrIndex, sizeof(DWORD)))
			)
		{
			ptrIndex += sizeof(DWORD);
			continue;
		}

		//////////////////////////////////////////////////////////////////////////
		//whether in a module range
		dwModHit = NULL;

		//局部性原理，减少遍历
		if (*(DWORD *)ptrIndex >= dwModBase
			&& *(DWORD *)ptrIndex < dwModBase + dwModSize)
		{
			dwModHit = dwModBase;
		}

		//have to loop every module
		if (dwModHit == NULL)
		{
			for (it = gs_ModuleList.begin(); it != gs_ModuleList.end(); it++)
			{
				iat_module_info = *it;
				dwModBase = (DWORD)iat_module_info.ImageBase;
				dwModSize = (DWORD)iat_module_info.ImageSize;

				if (*(DWORD *)ptrIndex >= dwModBase
					&& *(DWORD *)ptrIndex < dwModBase + dwModSize)
				{
					//myprintf("ptrIndex %X %X, Mod: %X, Size: %X\n", *(DWORD *)ptrIndex, ptrIndex, dwModBase, dwModSize);
					//myprintf("Module: %s\n", iat_module_info.DllName);
					break;
				}
				memset(&iat_module_info, 0, sizeof(IAT_Module_Info));
			}//end for(
		}//end if(NULL == 

		if (iat_module_info.ImageBase == 0 && iat_module_info.ImageSize == 0) {
			bool passDone = false;
			bool ptrIndexInc = false;
			bool Found = false;
			IAT_Module_Info iat_module_info_temp;

			DWORD deObfuscatedAddress = *(DWORD*)ptrIndex;
			retryPass:
			//myprintf("Check = %X %X %X\n", deObfuscatedAddress, (BYTE)deObfuscatedAddress, *(BYTE*)deObfuscatedAddress);

			for (it = gs_ModuleList.begin(); it != gs_ModuleList.end(); it++)
			{
				iat_module_info_temp = *it;
				dwModBase = (DWORD)iat_module_info_temp.ImageBase;
				dwModSize = (DWORD)iat_module_info_temp.ImageSize;

				if (deObfuscatedAddress >= dwModBase
					&& deObfuscatedAddress < dwModBase + dwModSize)
				{
					//myprintf("ptrIndex %X %X, Mod: %X, Size: %X\n", deObfuscatedAddress, ptrIndex, dwModBase, dwModSize);
					//myprintf("Module: %s\n", iat_module_info.DllName);
					Found = true;
					break;
				}
			}

			if (Found) {
				//myprintf("Found Check = %X\n", deObfuscatedAddress);
				GetAPIInfo(ptrIndex, &iat_module_info_temp, deObfuscatedAddress);
				ptrIndex += sizeof(DWORD);
				continue;
			} else if (!passDone) {
				passDone = true;
				if (!IsBadReadPtr((const void *)deObfuscatedAddress, sizeof(DWORD)) && *(BYTE*)deObfuscatedAddress == 0xE9) //JMP relative
					deObfuscatedAddress = (*(DWORD*)(deObfuscatedAddress + 1)) + deObfuscatedAddress + 5;
				else if (!IsBadReadPtr((const void *)deObfuscatedAddress, sizeof(DWORD)) && *(BYTE*)deObfuscatedAddress == 0x68 && *(BYTE*)(deObfuscatedAddress + 5) == 0xC3) { //PUSH
					//myprintf("PUSH = %X %X +5[%X]\n", deObfuscatedAddress, *(DWORD*)(deObfuscatedAddress + 1), *(BYTE*)(deObfuscatedAddress + 5));
					deObfuscatedAddress = *(DWORD*)(deObfuscatedAddress + 1);
				} else if (!IsBadReadPtr((const void *)deObfuscatedAddress, sizeof(DWORD)) && *(BYTE*)deObfuscatedAddress == 0xA1 && *(BYTE*)(deObfuscatedAddress + 5) == 0xC3) { //A1 MOV EAX, [XXXXXX]
					//myprintf("A1 = %X %X +5[%X]\n", deObfuscatedAddress, *(DWORD*)(deObfuscatedAddress + 1), *(BYTE*)(deObfuscatedAddress + 5));
					deObfuscatedAddress = *(DWORD*)(deObfuscatedAddress + 1);
				} else if (!IsBadReadPtr((const void *)deObfuscatedAddress, sizeof(DWORD)) && *(BYTE*)deObfuscatedAddress == 0xFF && *(BYTE*)(deObfuscatedAddress + 1) == 0x35 && *(BYTE*)(deObfuscatedAddress + 6) == 0x58) { //push [XXXXXX]
					//myprintf("PUSH2 = %X %X\n", deObfuscatedAddress, *(DWORD*)(deObfuscatedAddress + 2));
					deObfuscatedAddress = *(DWORD*)(deObfuscatedAddress + 2);
				} else if (!ptrIndexInc && (BYTE)deObfuscatedAddress == 0xC8) { //enter (invalid opcode)
					//myprintf("invalid 0xC8 = %X %X %X\n", ptrIndex, deObfuscatedAddress, (DWORD*)deObfuscatedAddress);
					if (!IsBadReadPtr((const void *)ptrIndex, sizeof(DWORD))) {
						int inc = insn_len((void*)ptrIndex);
						deObfuscatedAddress += *(DWORD*)(ptrIndex + insn_len((void*)ptrIndex));
						ptrIndexInc = true;
						//myprintf("invalid 0xC8 = %X %X %X\n", ptrIndex, deObfuscatedAddress, (DWORD*)deObfuscatedAddress);
						if (inc > 0)
							passDone = false;
					} else {
						ptrIndex += sizeof(DWORD);
						continue;
					}
				}

				goto retryPass;
			}

			//myprintf("not found import :(\n");
			ptrIndex += sizeof(DWORD);
			continue;
		}

		//now *ptrIndex in dwModBase
		//now retrieve API info (Hint, name) from the module's export
		//myprintf("ptrIndex %X %X, Mod: %X, Size: %X\n", *(DWORD *)ptrIndex, ptrIndex, dwModBase, dwModSize);
		GetAPIInfo(ptrIndex, &iat_module_info);
		ptrIndex += sizeof(DWORD);
	}
}

/************************************************************************/
/*
Function : Get AddressOfEntryPoint  (or Original Entry Point)
Params   : lpAddr is the Base where the exe mapped into
Return   : OEP (RVA)             */
/************************************************************************/
DWORD GetOEP(LPVOID lpAddr)
{
	PIMAGE_DOS_HEADER pDOSHDR = (PIMAGE_DOS_HEADER)lpAddr;
	PIMAGE_NT_HEADERS pNTHDR = (PIMAGE_NT_HEADERS)((unsigned char *)pDOSHDR + pDOSHDR->e_lfanew);
	return pNTHDR->OptionalHeader.AddressOfEntryPoint;
}

/************************************************************************/
/*
Function : Retrieve a process's Import Info only by IAT
Param    : lpAddr is the address the exe mapped into (within our space)
ptrIATEnd [out] used to receive the 1st IAT we found (FF25 XXXX, FF15YYYY)
Return   : the beginning of the page where IAT in
Search for FF25 XXXX,  or FF15 yyyy
HelloWorld.exe
004001E0 > .  EA07D577      DD USER32.MessageBoxA
004001E4      00000000      DD 00000000
004001E8 >/$  6A 00         PUSH 0                                   ; /Style = MB_OK|MB_APPLMODAL
004001EA  |.  6A 00         PUSH 0                                   ; |Title = NULL
004001EC  |.  6A 00         PUSH 0                                   ; |Text = NULL
004001EE  |.  6A 00         PUSH 0                                   ; |hOwner = NULL
004001F0  |.  E8 01000000   CALL <JMP.&USER32.MessageBoxA>           ; \MessageBoxA
004001F5  \.  C3            RETN
004001F6   $- FF25 E0014000 JMP DWORD PTR DS:[<&USER32.MessageBoxA>] ;  USER32.MessageBoxA
Notepad.exe
0100740B   .  FF15 38130001      CALL DWORD PTR DS:[<&msvcrt.__set_app_ty>;  msvcrt.__set_app_type
MSPaint.exe
1000CA65    8B35 58D10110   MOV ESI,DWORD PTR DS:[<&KERNEL32.LCMapSt>; kernel32.LCMapStringW
*/
/************************************************************************/

/*
Need to check all of these
– 8B0D MOV ECX,[ADDRESS]
– 8B15 MOV EDX,[ADDRESS]
– 8B1D MOV EBX,[ADDRESS]
– 8B25 MOV ESP,[ADDRESS]
– 8B2D MOV EBP,[ADDRESS]
– 8B35 MOV ESI,[ADDRESS]
– 8B3D MOV EDI,[ADDRESS]
– A1 MOV EAX,[ADDRESS]
- FF15 CALL [ADDRESS]
– FF25 JMP [ADDRESS]
– FF35 PUSH [ADDRESS]
*/

DWORD SearchIAT(LPVOID lpAddr, DWORD dwImageSize, DWORD pImageBase, DWORD dwMaxIATImageSize, DWORD *ptrIATEnd)
{
	DWORD pImageSectionStart = 0;
	DWORD instruction_length;
	DWORD *ptrFuncAddr = NULL;     //like xxx in JMP DWORD PTR DS:[XXXX]
	DWORD ptrFuncAddrHighest = NULL;
	DWORD dwOEP = NULL;
	BYTE *pCode = NULL;
	DWORD i = NULL;
	WORD  wJMP = 0x25FF;
	WORD  wCALL = 0x15FF;

	dwOEP = GetOEP(lpAddr);
	i = dwOEP;
	pCode = (BYTE *)((BYTE *)lpAddr + dwOEP);

	// get the location of the module's IMAGE_NT_HEADERS structure
	IMAGE_NT_HEADERS *pNtHdr = ImageNtHeader(lpAddr);
	// section table immediately follows the IMAGE_NT_HEADERS
	IMAGE_SECTION_HEADER *pSectionHdr = (IMAGE_SECTION_HEADER *)(pNtHdr + 1);

	bool got = false;
	for (int scn = 0; scn < pNtHdr->FileHeader.NumberOfSections; ++scn)
	{
		char *name = (char*)pSectionHdr->Name;
		DWORD SectionStart = (DWORD)lpAddr + pSectionHdr->VirtualAddress;
		DWORD SectionEnd = (DWORD)lpAddr + pSectionHdr->VirtualAddress + pSectionHdr->Misc.VirtualSize - 1;

		if (got) {
			pImageSectionStart = SectionStart;
			break;
		}

		if (SectionStart == pImageBase + dwOEP && SectionEnd < dwImageSize) {
			got = true;
			//next one is imports.
			++pSectionHdr;
			continue;
		}
		++pSectionHdr;
	}

	if (!pImageSectionStart)
		pImageSectionStart = dwImageSize;

	//myprintf("Found OEP at %X, ImageSize = %X,%X\n", dwOEP, dwImageSize, pImageSectionStart);

	//search for FF 25 XXXX, FF 15 YYYY from OEP, had better use Disasm engine 
	//but we just do it simply
	while (i < pImageSectionStart)
	{
		if (memcmp(pCode, &wJMP, sizeof(WORD))
			&& memcmp(pCode, &wCALL, sizeof(WORD)))
		{
			//
			instruction_length = insn_len(pCode);
			pCode += instruction_length;
			i += instruction_length;
			continue;
		}

		//check illegal, *ptrFuncAddr > pImageBase  && *ptrFuncAddr <= pImageBase + dwImageSize
		ptrFuncAddr = (DWORD *)(pCode + sizeof(WORD));
		if (*ptrFuncAddr < (DWORD)pImageBase || *ptrFuncAddr >= (DWORD)pImageBase + dwImageSize)
		{
			instruction_length = insn_len(pCode);
			pCode += instruction_length;
			i += instruction_length;
			continue;
		}

		//need to fix relocation
		*(DWORD *)ptrFuncAddr = (long)lpAddr + *(long *)ptrFuncAddr - (long)pImageBase;
		//now found one item that may belongs to IAT
		ptrFuncAddr = (DWORD *)*ptrFuncAddr;

		if ((DWORD)ptrFuncAddr > ptrFuncAddrHighest) {
			ptrFuncAddrHighest = (DWORD)ptrFuncAddr;
			//myprintf("highest = %X\n", ptrFuncAddrHighest);
		}

		//recheck illegal, 
		//for system dlls, what about user dlls? well, whatever, there must be system dlls
		//what if we found IAT for system dlls, so we found the user dlls.
		//What if the IAT tables are not continous????????
		if (*ptrFuncAddr < dwMaxIATImageSize)
		{
			instruction_length = insn_len(pCode);
			pCode += instruction_length;
			i += instruction_length;
			continue;
		}
		break;
	}

	//now it seems ptrFuncAddr points some item in IAT, 
	//make ptrFuncAddr point to the beginning of the page
	//we use 0xFFFEFFFF, because ptrFuncAddr is the memory addr we allocated, not by loadlibrary
	*ptrIATEnd = (DWORD)ptrFuncAddrHighest;
	ptrFuncAddr = (DWORD*)(((DWORD)ptrFuncAddr & 0xFFFFF000)
		+ ((DWORD)lpAddr & 0x0FFF)
		);
	return (DWORD)ptrFuncAddr;

	//return NULL;
}

unsigned long Get_Import_Address(char* DLL, char* Library, char* Import, int ordinal = -1)
{
	HMODULE mhLoadedDLL = NULL;
	do
	{
		if (!DLL)
			mhLoadedDLL = GetModuleHandle(NULL);
		else
			mhLoadedDLL = GetModuleHandle(DLL);
		Sleep(100);
	} while (!mhLoadedDLL);

	MODULEINFO modinfo;
	GetModuleInformation(GetCurrentProcess(), mhLoadedDLL, &modinfo, sizeof(MODULEINFO));
	DWORD ModuleSize = (unsigned long)modinfo.SizeOfImage;

	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)mhLoadedDLL;
	PIMAGE_NT_HEADERS NtHeader;
	PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor;
	UINT Index = 0;


	NtHeader = (PIMAGE_NT_HEADERS)(((PBYTE)DosHeader) + DosHeader->e_lfanew);
	if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
		return 0;

	ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(((PBYTE)DosHeader) + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	if (mhLoadedDLL) {
		ULONG Sz;
		ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToDataEx(mhLoadedDLL, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &Sz, nullptr);
	}

	__try {
		//
		// Iterate over import descriptors/DLLs.
		//
		for (Index = 0; (ImportDescriptor[Index].Characteristics != 0 || ImportDescriptor[Index].Name); Index++) {
			PSTR dllName = (PSTR)(((PBYTE)DosHeader) + ImportDescriptor[Index].Name);

			if (_strcmpi(dllName, Library) == 0) {
				// This the DLL we are after.
				PIMAGE_THUNK_DATA Thunk;
				PIMAGE_THUNK_DATA OrigThunk;

				Thunk = (PIMAGE_THUNK_DATA)(((PBYTE)DosHeader) + ImportDescriptor[Index].FirstThunk);
				OrigThunk = (PIMAGE_THUNK_DATA)(((PBYTE)DosHeader) + ImportDescriptor[Index].OriginalFirstThunk);

				//Reset
				Thunk = (PIMAGE_THUNK_DATA)(((PBYTE)DosHeader) + ImportDescriptor[Index].FirstThunk);
				OrigThunk = (PIMAGE_THUNK_DATA)(((PBYTE)DosHeader) + ImportDescriptor[Index].OriginalFirstThunk);

				for (; OrigThunk->u1.Function != NULL; OrigThunk++, Thunk++)
				{
					if (ordinal != -1) {
						if ((OrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) && IMAGE_ORDINAL(OrigThunk->u1.Ordinal) == ordinal) //send ordinal
							return (DWORD)Thunk; //Address of import returns.
					}

					if (OrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) { // Ordinal import - we can handle named imports only, so skip it.
						continue;
					}

					PIMAGE_IMPORT_BY_NAME importt = (PIMAGE_IMPORT_BY_NAME)(((PBYTE)DosHeader) + OrigThunk->u1.AddressOfData);

					if (_strcmpi(Import, (char*)importt->Name) == 0) {
						return (DWORD)Thunk; //Address of import returns.
					}
				}

				//First get all modules loaded, so you can find the maximum ImageBase+ImageSize for IAT Max Size calculation.
				if (gs_ModuleList.size() == 0) {
					BOOL bRet = SnapShotModules((DWORD)GetCurrentProcess());
					if (!bRet)
					{
						//myprintf("Failed to get Modules\n");
						return 0;
					}
				}

				DWORD dwMaxIATImageSize = 0x70000000;
				if (gs_ModuleList.size() > 0) {
					auto max_it = std::max_element(gs_ModuleList.begin(), gs_ModuleList.end(), [](const IAT_Module_Info& l, const IAT_Module_Info& h) {
						return l.ImageBase < h.ImageBase;
					});

					if (max_it->ImageBase > 0)
						dwMaxIATImageSize = (DWORD)max_it->ImageBase + max_it->ImageSize;

					//myprintf("Highest Imported DLL = %X %s\n", max_it->ImageBase, max_it->DllName);
				}
				//now we do more, retrieve the Page where IAT in
				DWORD ptrIATEnd = NULL;
				DWORD ptrIAT = SearchIAT(mhLoadedDLL, ModuleSize, NtHeader->OptionalHeader.ImageBase, dwMaxIATImageSize, &ptrIATEnd);

				//myprintf("Rebuilding IAT,Found IAT in page %X, IAT End %X\n", ptrIAT, ptrIATEnd);
				if (listOfIATImports.size() == 0)
					FixImport((DWORD)GetCurrentProcess(), ptrIAT, ptrIATEnd, ModuleSize);

				if (listOfIATImports.size() > 0) {
					std::list<IAT_Import_Information>::iterator i;
					for (i = listOfIATImports.begin();
						i != listOfIATImports.end();
						i++)
					{
						myprintf("Module: %s Import: %s Address: %X\n", i->IATModuleName, i->IATFunctionName, i->IATAddress);
					}
					
					
					auto match = std::find_if(listOfIATImports.cbegin(), listOfIATImports.cend(), [Library, Import](const IAT_Import_Information& s) {
						return _strcmpi(s.IATModuleName, Library) == 0 && _strcmpi(s.IATFunctionName, Import) == 0;
					});
					if (match != listOfIATImports.cend()) {
						//myprintf("Found IAT = %X, %s %s\n", match->IATAddress, match->IATModuleName, match->IATFunctionName);
						return match->IATAddress;
					}
				} else {
					//myprintf("Couldn't find module %s, import %s\n", Library, Import);
					return 0;
				}
			}
		}
	}
	__except (1) {
		myprintf(XorStr("Exception hit parsing imports\n"));
	}
	return 0;
}
