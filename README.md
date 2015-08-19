# Hooking Project

Created by: Sec-Mini-Projects (2015) under the MIT License - See "LICENSE" for Details. 

##Description:

Starts the execution of a x86 32 bit **ONLY** vulnerable program with optional command line parameters and hooks a hard coded list of API calls commonly used by shellcode.  It only returns out of the currently hooked api once and checks for shellcode which provides performance benefits.

While some delay might be introduced, the program remains responsive.

##Warnings

This program will RUN the supplied executable and malicious input file. USE ONLY IN MALWARE RESEARCH LABS.

##Usage

Usage: Hooking Parent.exe <fullpath and name of program> [OPTIONAL]"cmdlineparams"<br>
"Hooking.dll" must exist in the same directory as the "Hooking Parent" executable.


##Compiling & Dependencies

Compiled & written using Visual Studio 2010.

Compile the latest EasyHook project (https://github.com/EasyHook/EasyHook) which is used as the function hooking engine within this program.  Add all EasyHook source (header), library and binary files into the "EasyHook" folder.

Compile the "Hooking Parent" and "Hooking" solutions and copy "Hooking.dll" from the "Hooking" solution into the same directory as the "Hooking Parent" exe.

Both solutions could be combined into one solution and also automate the above but again, these are just hobby projects.

