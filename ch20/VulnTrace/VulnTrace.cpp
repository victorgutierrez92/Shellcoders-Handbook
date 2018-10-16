/*
*  VulnTrace.cpp
*/

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include "detours.h"

#pragma comment(lib,"detours.lib")
#pragma comment(lib, "ws2_32.lib") 

DWORD get_mem_size(char *block)
{
	DWORD     fnum = 0,
		memsize = 0,
		*frame_ptr = NULL,
		*prev_frame_ptr = NULL,
		*stack_base = NULL,
		*stack_top = NULL;

	__asm mov eax, dword ptr fs : [4]
		__asm mov stack_base, eax
	__asm mov eax, dword ptr fs : [8]
		__asm mov stack_top, eax
	__asm mov frame_ptr, ebp

	if (block < (char *)stack_base && block >(char *)stack_top)
		for (fnum = 0; fnum <= 5; fnum++)
		{
			if (frame_ptr < (DWORD *)stack_base && frame_ptr > stack_top)
			{
				prev_frame_ptr = (DWORD *)*frame_ptr;

				if (prev_frame_ptr < stack_base && prev_frame_ptr > stack_top)
				{
					if (frame_ptr < (DWORD *)block && (DWORD *)block < prev_frame_ptr)
					{
						memsize = (DWORD)prev_frame_ptr - (DWORD)block;
						break;
					}
					else
						frame_ptr = prev_frame_ptr;
				}
			}
		}

	return(memsize);
}

DETOUR_TRAMPOLINE(char * WINAPI real_lstrcpynA(char *dest, char *source, int maxlen), lstrcpynA);
DETOUR_TRAMPOLINE(char * WINAPI real_lstrcpyA(char *dest, char *source), lstrcpyA);
DETOUR_TRAMPOLINE(void * WINAPI real_memcpy(char *str1, char *str2, size_t n), memcpy);
DETOUR_TRAMPOLINE(int WINAPI real_send(SOCKET s, char *buf, int len, int flags), send);

char * WINAPI vt_lstrcpynA(char *dest, char *source, int maxlen)
{
	char dbgmsg[1024];
	char * retval;

	_snprintf(dbgmsg, sizeof(dbgmsg), "[VulnTrace]: lstrcpynA(0x%08x:[%d], %s, %d)\n", dest, get_mem_size(dest), source, maxlen);
	dbgmsg[sizeof(dbgmsg) - 1] = 0;

	OutputDebugStringA(dbgmsg);

	retval = real_lstrcpynA(dest, source, maxlen);

	return(retval);
}

char * WINAPI vt_lstrcpyA(char *dest, char *source)
{
	char dbgmsg[1024];
	char * retval;

	_snprintf(dbgmsg, sizeof(dbgmsg), "[VulnTrace]: lstrcpyA(0x%08x:[%d], %s)\n", dest, get_mem_size(dest), source);
	dbgmsg[sizeof(dbgmsg) - 1] = 0;

	OutputDebugStringA(dbgmsg);

	retval = real_lstrcpyA(dest, source);

	return(retval);
}

void * WINAPI vt_memcpy(char *str1, char *str2, size_t n)
{
	char dbgmsg[1024];
	void * retval;

	_snprintf(dbgmsg, sizeof(dbgmsg), "[VulnTrace]: memcpy(0x%08x:[%d], %s, %d)\n", str1, get_mem_size(str1), str2, n);
	dbgmsg[sizeof(dbgmsg) - 1] = 0;

	OutputDebugStringA(dbgmsg);

	retval = real_memcpy(str1, str2, n);

	return(retval);
}

int WINAPI vt_send(SOCKET s, char *buf, int len, int flags)
{
	char dbgmsg[1024];
	int retval;

	_snprintf(dbgmsg, sizeof(dbgmsg), "[VulnTrace]: send(0x%x, 0x%08x, %i, %i)\n", s, buf, len, flags);
	dbgmsg[sizeof(dbgmsg) - 1] = 0;

	OutputDebugStringA(dbgmsg);

	retval = real_send(s, buf, len, flags);

	return(retval);
}

BOOL APIENTRY DllMain(HANDLE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)

{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		DetourFunctionWithTrampoline((PBYTE)real_lstrcpynA, (PBYTE)vt_lstrcpynA);
		DetourFunctionWithTrampoline((PBYTE)real_lstrcpyA, (PBYTE)vt_lstrcpyA);
		//DetourFunctionWithTrampoline((PBYTE)real_memcpy, (PBYTE)vt_memcpy);

		//winsock
		//DetourFunctionWithTrampoline((PBYTE)real_send, (PBYTE)vt_send);
	}
	else if (ul_reason_for_call == DLL_PROCESS_DETACH)
	{
		OutputDebugStringA("[*] Unloading VulnTrace\n");
	}

	return TRUE;
}
