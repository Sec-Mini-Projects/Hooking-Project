//Created by: Sec-Mini-Projects (2013) under the MIT License - See "LICENSE" for Details.
//Description: Using the open source EasyHook library, this program injects the "Hooking" project DLL into the given process
//Usage: Make sure that the "Hooking.dll" file is located in the same directory as the ".exe", run using the following usage.
//		 This Prog.exe c:\fullpath_and_name_of_exe [OPTIONAL]cmdlineparams

#include "stdafx.h"
#include "easyhook.h"


int main(int argc, char * argv[])
{
	unsigned long procid = 0;
	WCHAR path[MAX_PATH] = {0};
	WCHAR params[MAX_PATH] = {0};
	if(argc > 1)
	{
		mbstowcs(path,argv[1],MAX_PATH);
	}
	if(argc == 2)
	{
		NTSTATUS temp = RhCreateAndInject(path,NULL,NULL,NULL,L"Hooking.dll",NULL,NULL,NULL,&procid);
	}
	else if(argc == 3)
	{
		mbstowcs(params,argv[2],MAX_PATH);
		NTSTATUS temp = RhCreateAndInject(path,params,NULL,NULL,L"Hooking.dll",NULL,NULL,NULL,&procid);
	}
	else
	{
		printf("Usage is \"This Prog.exe \"c:\\fullpath_and_name_of_exe\" [OPTIONAL]\"cmdlineparams\" ");
		printf("Usage: \"Hooking.dll\" must exist in the same directory as this executable");
	}
	return 0;
}


