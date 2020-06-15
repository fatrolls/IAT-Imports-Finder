Usage:

    DWORD GetTickCountx = Get_Import_Address(NULL, "kernel32.dll", "GetTickCount");
    if(GetTickCountx) {
        if (!VirtualProtect((LPVOID)GetTickCountx , 4, new_rights, &old_rights))
            return 0;
        *(DWORD*)(GetTickCountx) = (DWORD)(NewTickCount);
        VirtualProtect((LPVOID)GetTickCountx , 4, old_rights, &new_rights);
    }
