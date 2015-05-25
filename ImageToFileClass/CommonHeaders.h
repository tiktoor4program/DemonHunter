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
	1. PID�� �޾Ƽ� �� ���μ��� �ȿ� �ִ� ��� PE�� ���Ϸ� ������.
	2. �켱 �޸� ó������ PE �ñ״�ó �ִ� ���� ã�� �ִٸ� �� �������� ����� �޸� ������ ��� �����´�.
	�� ����� Chunk��� �Ѵٸ� �켱 �� Chunk�� ���ؼ� ����� �ٵ� ���غ��� ����� �� �ȴٸ� Chunk��ü�� ���Ϸ� ������.
*/

/* ���� ��ũ�� ���� */
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

/* NtQueryInformationThread API ����ϱ� ���� ���� */
typedef NTSTATUS (NTAPI *NTQUERYINFORMATIONTHREAD) (HANDLE, ULONG, PVOID, ULONG, PULONG);
#define ThreadQuerySetWin32StartAddress 9 

/* NtQuerySystemInformation API ����ϱ� ���� ���� */
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
#define XGetPtr(base, offset) ((PVOID)((ULONG_PTR) (base) + (ULONG_PTR) (offset)))		// base ����ü���� offset ��ŭ ������ ��ġ�� �ּҸ� ����

typedef struct _CLIENT_ID  
{  
	HANDLE UniqueProcess;	// ���μ��� ���̵�  
	HANDLE UniqueThread;	// ������ ���̵�  
} CLIENT_ID, *PCLIENT_ID;  

typedef struct _RSYSTEM_THREAD_INFORMATION   
{  
	LARGE_INTEGER KernelTime;	// Ŀ�� ��忡�� ����� �ð�  
	LARGE_INTEGER UserTime;		// ���� ��忡�� ����� �ð�  
	LARGE_INTEGER CreateTime;	// ���� �ð�  
	ULONG WaitTime;  
	PVOID StartAddress;			// ���� �ּ�  
	CLIENT_ID ClientId;			// ���μ���/������ ���̵�  
	ULONG Priority;   
	LONG BasePriority;  
	ULONG ContextSwitches;   
	ULONG ThreadState;			// ���� ������ ���� ����  
	ULONG WaitReason;			// ��� ����  
} RSYSTEM_THREAD_INFORMATION, *PRSYSTEM_THREAD_INFORMATION; 

typedef struct _RSYSTEM_PROCESS_INFORMATION
{  
	ULONG NextEntryOffset; // ���� ���μ��� ���� ������  
	ULONG NumberOfThreads; // �� ���μ��� ���Ե� ������ ����  
	LARGE_INTEGER WorkingSetPrivateSize;  
	ULONG HardFaultCount;  
	ULONG NumberOfThreadsHighWatermark;  
	ULONGLONG CycleTime; // ���μ��� ���࿡ �Ҹ�� ����Ŭ �ð�  
	LARGE_INTEGER CreateTime; // ���� �ð�  
	LARGE_INTEGER UserTime; // ���� ��忡�� ����� �ð�  
	LARGE_INTEGER KernelTime; // Ŀ�� ��忡�� ����� �ð�  
	UNICODE_STRING ImageName; // ���μ��� �̹��� �̸�  
	ULONG BasePriority;  
	HANDLE UniqueProcessId; // ���μ��� ���̵�  
	HANDLE InheritedFromUniqueProcessId; // �θ� ���μ��� ���̵�  
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

/* SMem ����ü ���� */
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