// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "Hooking.h"
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		if(logme != NULL)
		{
			fclose(logme);
		}
		if(readfile_hHook != NULL)
			free(readfile_hHook);
		if(writefile_hHook != NULL)
			free(writefile_hHook);
	//	if(writefile_hHook != NULL)
	//		free(VirtualAlloc_hHook);
		if(WinExec_hHook != NULL)
			free(WinExec_hHook);
		if(SetFilePointer_hHook != NULL)
			free(SetFilePointer_hHook);
		if(CreateFile_hHook != NULL)
			free(CreateFile_hHook);
		if(GetFileSize_hHook != NULL)
			free(GetFileSize_hHook);
		if(GetTempPath_hHook != NULL)
			free(GetTempPath_hHook);
		if(CloseHandle_hHook != NULL)
			free(CloseHandle_hHook);
		if(CreateFileMapping_hHook != NULL)
			free(CreateFileMapping_hHook);
		if(MapViewOfFile_hHook != NULL)
			free(MapViewOfFile_hHook);
		if(RegOpenKeyEx_hHook != NULL)
			free(RegOpenKeyEx_hHook);
		if(RegQueryValueEx_hHook != NULL)
			free(RegQueryValueEx_hHook);
		//if(VirtualProtect_hHook != NULL)
		//	free(VirtualProtect_hHook);
		if(GetFileAttributes_hHook != NULL)
			free(GetFileAttributes_hHook);
		if(GetCurrentProcess_hHook != NULL)
			free(GetCurrentProcess_hHook);
		if(WSAStartup_hHook != NULL)
			free(WSAStartup_hHook);
		if(bind_hHook != NULL)
			free(bind_hHook);
		if(connect_hHook != NULL)
			free(connect_hHook);
		if(gethostbyname_hHook != NULL)
			free(gethostbyname_hHook);
		break;
	}
	return TRUE;
}

