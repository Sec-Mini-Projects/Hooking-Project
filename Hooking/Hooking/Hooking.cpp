//Created by: Sec-Mini-Projects (2013) under the MIT License - See "LICENSE" for Details.
//Description: Using the open source EasyHook library, this DLL adds hooks to common API calls and checks whether the function was called by shellcode or not.
//Usage: None, this DLL is injected into the process via the "Hooking Parent" project.

#include "stdafx.h"
#include "Hooking.h"

#define MAX_FNAME 40

void WriteResultLine(unsigned int retvalue, unsigned short callerbytes, unsigned short protect, unsigned int balloc, unsigned int baddr, char * module_name)
{

	char * temp = (char *)calloc(100,sizeof(char));
	unsigned int len_module = strlen(module_name);
	if(strstr(module_name,".") == NULL || len_module < 4 || (protect > 0x20 || protect < 0x10))
	{
		sprintf(temp,"Ret value is: %x, Mod name is %s, length is %u\n",retvalue,module_name,len_module);
		fputs (temp,logme);
		fflush(logme);
		if(tolduser == 0)
		{
			tolduser = 1;
			MessageBox(NULL,"Dude where's my debugger?","Attach debugger now",(UINT)NULL);
		}
	}
	free (temp);
}
	

BOOL WINAPI WriteFile_hook(
  _In_         HANDLE hFile,
  _In_         LPCVOID lpBuffer,
  _In_         DWORD nNumberOfBytesToWrite,
  _Out_opt_    LPDWORD lpNumberOfBytesWritten,
  _Inout_opt_  LPOVERLAPPED lpOverlapped
)
{
	FindAndWriteFindings();
	return WriteFile(hFile,lpBuffer,nNumberOfBytesToWrite,lpNumberOfBytesWritten,lpOverlapped);
}

LPVOID WINAPI VirtualAlloc_hook(
  _In_opt_  LPVOID lpAddress,
  _In_      SIZE_T dwSize,
  _In_      DWORD flAllocationType,
  _In_      DWORD flProtect
)
{
	FindAndWriteFindings();
	return VirtualAlloc(lpAddress,dwSize,flAllocationType,flProtect);
}

UINT WINAPI WinExec_hook(
  _In_  LPCSTR lpCmdLine,
  _In_  UINT uCmdShow
)
{
	FindAndWriteFindings();
	return WinExec(lpCmdLine,uCmdShow);
}

BOOL WINAPI ReadFile_hook(
  _In_         HANDLE hFile,
  _Out_        LPVOID lpBuffer,
  _In_         DWORD nNumberOfBytesToRead,
  _Out_opt_    LPDWORD lpNumberOfBytesRead,
  _Inout_opt_  LPOVERLAPPED lpOverlapped
)
{
	FindAndWriteFindings();
	return ReadFile(hFile,lpBuffer,nNumberOfBytesToRead,lpNumberOfBytesRead,lpOverlapped);
}

DWORD WINAPI SetFilePointer_hook(
  _In_         HANDLE hFile,
  _In_         LONG lDistanceToMove,
  _Inout_opt_  PLONG lpDistanceToMoveHigh,
  _In_         DWORD dwMoveMethod
)
{
	FindAndWriteFindings();
	return SetFilePointer(hFile,lDistanceToMove,lpDistanceToMoveHigh,dwMoveMethod);
}



HANDLE WINAPI CreateFile_hook(
  _In_      LPCTSTR lpFileName,
  _In_      DWORD dwDesiredAccess,
  _In_      DWORD dwShareMode,
  _In_opt_  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  _In_      DWORD dwCreationDisposition,
  _In_      DWORD dwFlagsAndAttributes,
  _In_opt_  HANDLE hTemplateFile
)
{
	FindAndWriteFindings();
	return CreateFile(lpFileName,dwDesiredAccess,dwShareMode,lpSecurityAttributes,dwCreationDisposition,dwFlagsAndAttributes,hTemplateFile);
}


DWORD WINAPI GetFileSize_hook(
  _In_       HANDLE hFile,
  _Out_opt_  LPDWORD lpFileSizeHigh
)
{
	FindAndWriteFindings();
	return GetFileSize(hFile,lpFileSizeHigh);
}

DWORD WINAPI GetTempPath_hook(
  _In_   DWORD nBufferLength,
  _Out_  LPTSTR lpBuffer
)
{
	FindAndWriteFindings();
	return GetTempPath(nBufferLength,lpBuffer);
}

BOOL WINAPI CloseHandle_hook(
  _In_  HANDLE hObject
)
{
	FindAndWriteFindings();
	return CloseHandle(hObject);
}

HANDLE WINAPI CreateFileMapping_hook(
  _In_      HANDLE hFile,
  _In_opt_  LPSECURITY_ATTRIBUTES lpAttributes,
  _In_      DWORD flProtect,
  _In_      DWORD dwMaximumSizeHigh,
  _In_      DWORD dwMaximumSizeLow,
  _In_opt_  LPCTSTR lpName
)
{
	FindAndWriteFindings();
	return CreateFileMapping(hFile,lpAttributes,flProtect,dwMaximumSizeHigh,dwMaximumSizeLow,lpName);
}

LPVOID WINAPI MapViewOfFile_hook(
  _In_  HANDLE hFileMappingObject,
  _In_  DWORD dwDesiredAccess,
  _In_  DWORD dwFileOffsetHigh,
  _In_  DWORD dwFileOffsetLow,
  _In_  SIZE_T dwNumberOfBytesToMap
)
{
	FindAndWriteFindings();
	return MapViewOfFile(hFileMappingObject,dwDesiredAccess,dwFileOffsetHigh,dwFileOffsetLow,dwNumberOfBytesToMap);
}

LONG WINAPI RegOpenKeyEx_hook(
  _In_        HKEY hKey,
  _In_opt_    LPCTSTR lpSubKey,
  _In_		  DWORD ulOptions,
  _In_        REGSAM samDesired,
  _Out_       PHKEY phkResult
)
{
	FindAndWriteFindings();
	return RegOpenKeyEx(hKey,lpSubKey,ulOptions,samDesired,phkResult);
}


LONG WINAPI RegQueryValueEx_hook(
  _In_         HKEY hKey,
  _In_opt_     LPCTSTR lpValueName,
  _In_			LPDWORD lpReserved,
  _Out_opt_    LPDWORD lpType,
  _Out_opt_    LPBYTE lpData,
  _Inout_opt_  LPDWORD lpcbData
)
{
	FindAndWriteFindings();
	return RegQueryValueEx(hKey,lpValueName,lpReserved,lpType,lpData,lpcbData);
}

LPVOID WINAPI HeapAlloc_hook(
  _In_  HANDLE hHeap,
  _In_  DWORD dwFlags,
  _In_  SIZE_T dwBytes
)
{
	FindAndWriteFindings();
	return HeapAlloc(hHeap,dwFlags,dwBytes);
}

BOOL WINAPI VirtualProtect_hook(
  _In_   LPVOID lpAddress,
  _In_   SIZE_T dwSize,
  _In_   DWORD flNewProtect,
  _Out_  PDWORD lpflOldProtect
)
{
	FindAndWriteFindings();
	return VirtualProtect(lpAddress,dwSize,flNewProtect,lpflOldProtect);
}

DWORD WINAPI GetFileAttributes_hook(
  _In_  LPCTSTR lpFileName
)
{
	FindAndWriteFindings();
	return GetFileAttributes(lpFileName);
}


FARPROC WINAPI GetProcAddress_hook(
  _In_  HMODULE hModule,
  _In_  LPCSTR lpProcName
)
{
	FindAndWriteFindings();
	return GetProcAddress(hModule,lpProcName);
}

HANDLE WINAPI GetCurrentProcess_hook(void)
{
	FindAndWriteFindings();
	return GetCurrentProcess();
}

int WSAStartup_hook
(
  _In_   WORD wVersionRequested,
  _Out_  LPWSADATA lpWSAData
)
{
	FindAndWriteFindings();
	return WSAStartup(wVersionRequested,lpWSAData);
}

int bind_hook(
  _In_  SOCKET s,
  _In_  const struct sockaddr *name,
  _In_  int namelen
)
{
	FindAndWriteFindings();
	return bind(s,name,namelen);
}


int connect_hook(
  _In_  SOCKET s,
  _In_  const struct sockaddr *name,
  _In_  int namelen
)
{
	FindAndWriteFindings();
	return connect(s,name,namelen);
}

struct hostent* FAR gethostbyname_hook(
  _In_  const char *name
)
{
	FindAndWriteFindings();
	return gethostbyname(name);
}


HOOKING_API void NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* InRemoteInfo)
{
	ULONG ACLEntries[17] = {0};
	readfile_hHook = (HOOK_TRACE_INFO *)calloc(1,sizeof(HOOK_TRACE_INFO));
	writefile_hHook = (HOOK_TRACE_INFO *)calloc(1,sizeof(HOOK_TRACE_INFO));
	//VirtualAlloc_hHook = (HOOK_TRACE_INFO *)calloc(1,sizeof(HOOK_TRACE_INFO));
	WinExec_hHook = (HOOK_TRACE_INFO *)calloc(1,sizeof(HOOK_TRACE_INFO));
	SetFilePointer_hHook = (HOOK_TRACE_INFO *)calloc(1,sizeof(HOOK_TRACE_INFO));
	CreateFile_hHook = (HOOK_TRACE_INFO *)calloc(1,sizeof(HOOK_TRACE_INFO));
	GetFileSize_hHook = (HOOK_TRACE_INFO *)calloc(1,sizeof(HOOK_TRACE_INFO));
	GetTempPath_hHook = (HOOK_TRACE_INFO *)calloc(1,sizeof(HOOK_TRACE_INFO));
	CloseHandle_hHook = (HOOK_TRACE_INFO *)calloc(1,sizeof(HOOK_TRACE_INFO));
	CreateFileMapping_hHook = (HOOK_TRACE_INFO *)calloc(1,sizeof(HOOK_TRACE_INFO));
	MapViewOfFile_hHook = (HOOK_TRACE_INFO *)calloc(1,sizeof(HOOK_TRACE_INFO));
	RegOpenKeyEx_hHook = (HOOK_TRACE_INFO *)calloc(1,sizeof(HOOK_TRACE_INFO));
	RegQueryValueEx_hHook = (HOOK_TRACE_INFO *)calloc(1,sizeof(HOOK_TRACE_INFO));
	//VirtualProtect_hHook = (HOOK_TRACE_INFO *)calloc(1,sizeof(HOOK_TRACE_INFO));
	GetFileAttributes_hHook = (HOOK_TRACE_INFO *)calloc(1,sizeof(HOOK_TRACE_INFO));
	GetCurrentProcess_hHook = (HOOK_TRACE_INFO *)calloc(1,sizeof(HOOK_TRACE_INFO));
	WSAStartup_hHook = (HOOK_TRACE_INFO *)calloc(1,sizeof(HOOK_TRACE_INFO));
	bind_hHook = (HOOK_TRACE_INFO *)calloc(1,sizeof(HOOK_TRACE_INFO));
	connect_hHook = (HOOK_TRACE_INFO *)calloc(1,sizeof(HOOK_TRACE_INFO));
	gethostbyname_hHook = (HOOK_TRACE_INFO *)calloc(1,sizeof(HOOK_TRACE_INFO));
	//MessageBox(NULL,"Hit create file","TEST",(UINT)NULL);
	tolduser = 0;
	logme = fopen ("HookLog.txt","a+");
	InstallThisHook("Kernel32.dll", "ReadFile",&ReadFile_hook, readfile_hHook,16);
	InstallThisHook("Kernel32.dll", "WriteFile",&WriteFile_hook, writefile_hHook,1);
	//InstallThisHook("Kernel32.dll", "VirtualAlloc",&VirtualAlloc_hook, VirtualAlloc_hHook,2);
	InstallThisHook("Kernel32.dll", "WinExec",&WinExec_hook, WinExec_hHook,3);
	InstallThisHook("Kernel32.dll", "SetFilePointer",&SetFilePointer_hook, SetFilePointer_hHook,4);
	InstallThisHook("Kernel32.dll", "CreateFile",&CreateFile_hook, CreateFile_hHook,5);
	InstallThisHook("Kernel32.dll", "GetFileSize",&GetFileSize_hook, GetFileSize_hHook,6);
	InstallThisHook("Kernel32.dll", "GetTempPath",&GetTempPath_hook, GetTempPath_hHook,7);
	InstallThisHook("Kernel32.dll", "CloseHandle",&CloseHandle_hook, CloseHandle_hHook,8);
	InstallThisHook("Kernel32.dll", "CreateFileMapping",&CreateFileMapping_hook, CreateFileMapping_hHook,9);
	InstallThisHook("Kernel32.dll", "MapViewOfFile",&MapViewOfFile_hook, MapViewOfFile_hHook,10);
	InstallThisHook("Advapi32.dll", "RegOpenKeyEx",&RegOpenKeyEx_hook, RegOpenKeyEx_hHook,11);
	InstallThisHook("Advapi32.dll", "RegQueryValueEx",&RegQueryValueEx_hook, RegQueryValueEx_hHook,12);
	//InstallThisHook("Kernel32.dll", "VirtualProtect",&VirtualProtect_hook, VirtualProtect_hHook,13);
	InstallThisHook("Kernel32.dll", "GetFileAttributes",&GetFileAttributes_hook, GetFileAttributes_hHook,14);
	InstallThisHook("Kernel32.dll", "GetCurrentProcess",&GetCurrentProcess_hook, GetCurrentProcess_hHook,15);
	InstallThisHook("Ws2_32.dll", "WSAStartup",&WSAStartup_hook, WSAStartup_hHook,17);
	InstallThisHook("Ws2_32.dll", "bind",&bind_hook, bind_hHook,18);
	InstallThisHook("Ws2_32.dll", "connect",&connect_hook, connect_hHook,19);
	InstallThisHook("Ws2_32.dll", "gethostbyname",&gethostbyname_hook, gethostbyname_hHook,20);
	LhSetExclusiveACL(ACLEntries, 16, readfile_hHook);
	LhSetExclusiveACL(ACLEntries, 1, writefile_hHook);
	//LhSetExclusiveACL(ACLEntries, 2, VirtualAlloc_hHook);
	LhSetExclusiveACL(ACLEntries, 3, WinExec_hHook);
	LhSetExclusiveACL(ACLEntries, 4, SetFilePointer_hHook);
	LhSetExclusiveACL(ACLEntries, 5, CreateFile_hHook);
	LhSetExclusiveACL(ACLEntries, 6, GetFileSize_hHook);
	LhSetExclusiveACL(ACLEntries, 7, GetTempPath_hHook);
	LhSetExclusiveACL(ACLEntries, 8, CloseHandle_hHook);
	LhSetExclusiveACL(ACLEntries, 9, CreateFileMapping_hHook);
	LhSetExclusiveACL(ACLEntries, 10, MapViewOfFile_hHook);
	LhSetExclusiveACL(ACLEntries, 11, RegOpenKeyEx_hHook);
	LhSetExclusiveACL(ACLEntries, 12, RegQueryValueEx_hHook);
	//LhSetExclusiveACL(ACLEntries, 13, VirtualProtect_hHook);
	LhSetExclusiveACL(ACLEntries, 14, GetFileAttributes_hHook);
	LhSetExclusiveACL(ACLEntries, 15, GetCurrentProcess_hHook);
	LhSetExclusiveACL(ACLEntries, 17, WSAStartup_hHook);
	LhSetExclusiveACL(ACLEntries, 18, bind_hHook);
	LhSetExclusiveACL(ACLEntries, 19, connect_hHook);
	LhSetExclusiveACL(ACLEntries, 20, gethostbyname_hHook);
	RhWakeUpProcess();
	//Sleep(1000);
}


void InstallThisHook(char * lib, char * APIName,PVOID hook_handler,HOOK_TRACE_INFO * hHook,int addr)
{
	HMODULE temp = LoadLibrary(lib);
	if( temp != NULL)
	{
		LhInstallHook(GetProcAddress(temp, APIName),hook_handler,(PVOID)addr,hHook);
	}
	else
	{
		MessageBox(NULL,lib,"The below lib did not exist",(UINT)NULL);
	}

}

void FindAndWriteFindings()
{
	unsigned short * code;
	unsigned int ret;
	unsigned int ret_addr;
	PVOID mem_baseaddr;
	PVOID mem_basealloc;
	unsigned short mem_protect;
	MEMORY_BASIC_INFORMATION * pageinfo;
	//MODULE_INFORMATION name;
	HMODULE module;
	char * module_name;

	size_t result;
	code = (unsigned short*)calloc(1,sizeof(unsigned short));
	module_name = (char*)calloc(MAX_FNAME,sizeof(char));
	LhBarrierGetReturnAddress((PVOID*)&ret);
	LhBarrierGetAddressOfReturnAddress((PVOID)&ret_addr);
	if(ret != NULL)
	{
		memcpy_s((void*)code,sizeof(*code),(void*)(ret -6),2);
	}
	pageinfo = (MEMORY_BASIC_INFORMATION*)calloc(1,sizeof(MEMORY_BASIC_INFORMATION));
	result = VirtualQuery((LPCVOID)ret,pageinfo,sizeof(*pageinfo));
	if(pageinfo != NULL)
	{
		mem_baseaddr = pageinfo->BaseAddress;
		mem_basealloc = pageinfo->AllocationBase;
		mem_protect = pageinfo->Protect;
	}
	if(mem_basealloc != NULL)
	{
		BOOL worked = GetModuleHandleEx (GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)mem_basealloc, &module);
		if(worked == TRUE)
		{
			 GetModuleBaseName(GetCurrentProcess(),module,module_name,MAX_FNAME);
		}
		
	}
	//LhBarrierGetCallingModule(&name);
	WriteResultLine(ret,*code,mem_protect,(unsigned int)mem_basealloc,(unsigned int)mem_baseaddr,module_name);
	free(pageinfo);
	free(code);
	free(module_name);
}
