#include <windows.h>
#include <winsock2.h>
#include "easyhook.h"
#include <stdio.h>
#include <stdlib.h>
#include <Psapi.h> 
#include <string.h>

#ifdef HOOKING_EXPORTS
#define HOOKING_API __declspec(dllexport)
#else
#define HOOKING_API __declspec(dllimport)
#endif

FILE * logme;
int tolduser;
HOOK_TRACE_INFO * readfile_hHook;
HOOK_TRACE_INFO * writefile_hHook;
//HOOK_TRACE_INFO * VirtualAlloc_hHook;
HOOK_TRACE_INFO * WinExec_hHook;
HOOK_TRACE_INFO * SetFilePointer_hHook;
HOOK_TRACE_INFO * CreateFile_hHook;
HOOK_TRACE_INFO * GetFileSize_hHook;
HOOK_TRACE_INFO * GetTempPath_hHook;
HOOK_TRACE_INFO * CloseHandle_hHook;
HOOK_TRACE_INFO * CreateFileMapping_hHook;
HOOK_TRACE_INFO * MapViewOfFile_hHook;
HOOK_TRACE_INFO * RegOpenKeyEx_hHook;
HOOK_TRACE_INFO * RegQueryValueEx_hHook;
//HOOK_TRACE_INFO * VirtualProtect_hHook;
HOOK_TRACE_INFO * GetFileAttributes_hHook;
HOOK_TRACE_INFO * GetCurrentProcess_hHook;
HOOK_TRACE_INFO * WSAStartup_hHook;
HOOK_TRACE_INFO * bind_hHook;
HOOK_TRACE_INFO * connect_hHook;
HOOK_TRACE_INFO * gethostbyname_hHook;

void WriteResultLine(unsigned int retvalue, unsigned short callerbytes, unsigned short protect, unsigned int balloc, unsigned int baddr);
extern HOOKING_API void NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* InRemoteInfo);
void InstallThisHook(char * lib, char * APIName,PVOID hook_handler,HOOK_TRACE_INFO * hHook,int addr);
void FindAndWriteFindings();