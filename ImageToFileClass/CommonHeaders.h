#ifndef __COMMONHEADERS_H__
#define __COMMONHEADERS_H__

#include <windows.h>
#include <iostream>
#include <fstream>
#include <list>
#include <tchar.h>
#include <WinNT.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "atlstr.h"
#include <Psapi.h>
#include <winternl.h>
//#include <ntstatus.h>
#include <subauth.h>
#include "getopt.h"

#pragma comment(lib, "getopt.lib")
#pragma comment(lib, "Psapi.lib")

using namespace std;

/*	
	1. PID를 받아서 그 프로세스 안에 있는 모든 PE를 파일로 떨군다.
	2. 우선 메모리 처음부터 PE 시그니처 있는 곳을 찾고 있다면 그 영역부터 연결된 메모리 영역을 모두 가져온다.
	그 덩어리를 Chunk라고 한다면 우선 그 Chunk를 구해서 헤더와 바디를 구해보고 제대로 안 된다면 Chunk자체를 파일로 떨군다.
*/

/* 공통 매크로 선언 */
#define DEBUGGING 0
#define SIZE_OF_SECTION 0x28
//#define WARNPRINT(msg, ...)				_tprintf(_T("Warning : ") msg _T("File : %s, Function : %s, Line : %s") _T("\n"), ##__VA_ARGS__, __FILE__, __FUNCTION__, __LINE__);
//#define ERRPRINT(msg, ...)				_tprintf(_T("Error : ") msg _T("File : %s, Function : %s, Line : %s") _T("\n"), ##__VA_ARGS__, __FILE__, __FUNCTION__, __LINE__);
//#define ERRPRINT_GOTO(label, msg, ...)	_tprintf(_T("Error : ") msg _T("File : %s, Function : %s, Line : %s") _T("\n"), ##__VA_ARGS__, __FILE__, __FUNCTION__, __LINE__);
#define DBGPRINT(msg)				logFile<<"Debug : "<<(msg)<<", Function : "<<__FUNCTION__<<", LINE : "<<__LINE__<<", File : "<<__FILE__<<endl;
#define DBGPRINT_GOTO(label, msg)	logFile<<"Debug : "<<(msg)<<", Function : "<<__FUNCTION__<<", LINE : "<<__LINE__<<", File : "<<__FILE__<<endl;	goto label;
#define WARNPRINT(msg)				logFile<<"Warning : "<<(msg)<<", Function : "<<__FUNCTION__<<", LINE : "<<__LINE__<<", File : "<<__FILE__<<endl;
#define WARNPRINT_GOTO(label, msg)	logFile<<"Warning : "<<(msg)<<", Function : "<<__FUNCTION__<<", LINE : "<<__LINE__<<", File : "<<__FILE__<<endl;	goto label;
#define ERRPRINT(msg)				logFile<<"Error : "<<(msg)<<", Function : "<<__FUNCTION__<<", LINE : "<<__LINE__<<", File : "<<__FILE__<<endl;
#define ERRPRINT_GOTO(label, msg)	logFile<<"Error : "<<(msg)<<", Function : "<<__FUNCTION__<<", LINE : "<<__LINE__<<", File : "<<__FILE__<<endl;	goto label;

#define SAFECLOSEHANDLE16(h)	if(h != INVALID_HANDLE_VALUE) { CloseHandle(h); } \
								h = INVALID_HANDLE_VALUE;
#define SAFECLOSEHANDLE32(h)	if(h != NULL)	{ CloseHandle(h); } \
								h = NULL;
#define SAFEDELETE(m)			if(m != NULL)	{	delete (m);		m = NULL;	}
#define SAFEDELETEARRAY1(m)		if(m != NULL)	{	delete[] (m);	m = NULL;	}

/* NtQueryInformationThread API 사용하기 위한 선언 */
typedef NTSTATUS (NTAPI *NTQUERYINFORMATIONTHREAD) (HANDLE, ULONG, PVOID, ULONG, PULONG);
#define ThreadQuerySetWin32StartAddress 9 

/* NtQuerySystemInformation API 사용하기 위한 선언 */
#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)
typedef enum _SYSTEM_INFORMATION_CLASS {  
	SystemBasicInformation = 0,  
	SystemPerformanceInformation = 2,  
	SystemTimeOfDayInformation = 3,  
	SystemProcessInformation = 5,  
	SystemProcessorPerformanceInformation = 8,  
	SystemInterruptInformation = 23,  
	SystemExceptionInformation = 33,  
	SystemRegistryQuotaInformation = 37,  
	SystemLookasideInformation = 45  
} SYSTEM_INFORMATION_CLASS; 

NTSTATUS WINAPI NtQuerySystemInformation(  
	SYSTEM_INFORMATION_CLASS SystemInformationClass,  
	PVOID SystemInformation,  
	ULONG SystemInformationLength,  
	PULONG ReturnLength  
	);  

typedef NTSTATUS (NTAPI *NTQUERYSYSTEMINFORMATION) (SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
#define XGetPtr(base, offset) ((PVOID)((ULONG_PTR) (base) + (ULONG_PTR) (offset)))		// base 구조체에서 offset 만큼 떨어진 위치의 주소를 리턴

typedef struct _CLIENT_ID  
{  
	HANDLE UniqueProcess;	// 프로세스 아이디  
	HANDLE UniqueThread;	// 스레드 아이디  
} CLIENT_ID, *PCLIENT_ID;  

typedef struct _RSYSTEM_THREAD_INFORMATION   
{  
	LARGE_INTEGER KernelTime;	// 커널 모드에서 수행된 시간  
	LARGE_INTEGER UserTime;		// 유저 모드에서 수행된 시간  
	LARGE_INTEGER CreateTime;	// 생성 시간  
	ULONG WaitTime;  
	PVOID StartAddress;			// 시작 주소  
	CLIENT_ID ClientId;			// 프로세스/스레드 아이디  
	ULONG Priority;   
	LONG BasePriority;  
	ULONG ContextSwitches;   
	ULONG ThreadState;			// 현재 스레드 수행 상태  
	ULONG WaitReason;			// 대기 사유  
} RSYSTEM_THREAD_INFORMATION, *PRSYSTEM_THREAD_INFORMATION; 

typedef struct _RSYSTEM_PROCESS_INFORMATION
{  
	ULONG NextEntryOffset; // 다음 프로세스 정보 오프셋  
	ULONG NumberOfThreads; // 이 프로세스 포함된 스레드 개수  
	LARGE_INTEGER WorkingSetPrivateSize;  
	ULONG HardFaultCount;  
	ULONG NumberOfThreadsHighWatermark;  
	ULONGLONG CycleTime; // 프로세스 수행에 소모된 사이클 시간  
	LARGE_INTEGER CreateTime; // 생성 시간  
	LARGE_INTEGER UserTime; // 유저 모드에서 수행된 시간  
	LARGE_INTEGER KernelTime; // 커널 모드에서 수행된 시간  
	UNICODE_STRING ImageName; // 프로세스 이미지 이름  
	ULONG BasePriority;  
	HANDLE UniqueProcessId; // 프로세스 아이디  
	HANDLE InheritedFromUniqueProcessId; // 부모 프로세스 아이디  
	ULONG HandleCount;  
	ULONG SessionId;  
	ULONG_PTR UniqueProcessKey;  
	SIZE_T PeakVirtualSize;  
	SIZE_T VirtualSize;  
	ULONG PageFaultCount;  
	SIZE_T PeakWorkingSetSize;  
	SIZE_T WorkingSetSize;  
	SIZE_T QuotaPeakPagedPoolUsage;  
	SIZE_T QuotaPagedPoolUsage;  
	SIZE_T QuotaPeakNonPagedPoolUsage;  
	SIZE_T QuotaNonPagedPoolUsage;  
	SIZE_T PagefileUsage;  
	SIZE_T PeakPagefileUsage;  
	SIZE_T PrivatePageCount;  
	LARGE_INTEGER ReadOperationCount;  
	LARGE_INTEGER WriteOperationCount;  
	LARGE_INTEGER OtherOperationCount;  
	LARGE_INTEGER ReadTransferCount;  
	LARGE_INTEGER WriteTransferCount;  
	LARGE_INTEGER OtherTransferCount;  
} RSYSTEM_PROCESS_INFORMATION, *PRSYSTEM_PROCESS_INFORMATION;  

/* SMem 구조체 선언 */
struct SMem
{
	UINT_PTR BaseAddr;
	SIZE_T Size;

	SMem (UINT_PTR BaseAddr, SIZE_T Size)
	{
		this->BaseAddr = BaseAddr;
		this->Size = Size;
	}
};

struct SMemSort
{
	bool operator() (const SMem &pObject1, const SMem &pObject2) const
	{
		if ( (UINT_PTR)pObject1.BaseAddr < (UINT_PTR)pObject2.BaseAddr )
			return TRUE;

		return FALSE;
	}
};

#ifndef MAKEULONGLONG
#define MAKEULONGLONG(ldw, hdw) ((ULONGLONG(hdw) << 32) | ((ldw) & 0xFFFFFFFF))
#endif

#ifndef MAXULONGLONG
#define MAXULONGLONG ((ULONGLONG)~((ULONGLONG)0))
#endif

#endif