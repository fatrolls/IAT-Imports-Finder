Usage:

    #include "IAT.h"
    
    //Search for all of these imports.. if all found.. stop searching.. to speed up waiting for all imports to finish
    IAT_TO_IMPORT["timeGetTime"] = FALSE;
    IAT_TO_IMPORT["GetTickCount"] = FALSE;
    IAT_TO_IMPORT["QueryPerformanceCounter"] = FALSE;
    
    DWORD GetTickCountx = Get_Import_Address(NULL, "kernel32.dll", "GetTickCount");
    if(GetTickCountx) {
        DWORD old_rights, new_rights = PAGE_READWRITE; //PAGE_EXECUTE_READWRITE
        if (!VirtualProtect((LPVOID)GetTickCountx , 4, new_rights, &old_rights))
            return 0;
        *(DWORD*)(GetTickCountx) = (DWORD)(NewTickCount);
        VirtualProtect((LPVOID)GetTickCountx , 4, old_rights, &new_rights);
    }
