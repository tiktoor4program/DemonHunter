#include "CImageToFile.h"

/*	Function : Run
	Description : CImageToFile 클래스에서 메인 함수
*/
void CImageToFile::Run()
{
	BOOL bRet = FALSE;

	if(bOpAllProc)
	{
		// 모든 프로세스 검사 시
		bRet = ScanAllProcesses();
	}
	else
	{
		// 특정 프로세스만 검사 시
		hImage = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
		if(hImage == NULL)
		{
			ERRPRINT_GOTO(_EXIT, "Wrong PID");
		}

		bRet = ScanOneProcess();
	}

	_tprintf(_T("\nThe end. Please press <Eenter> key.\n"));
	cin.get();

	/*
	// 모듈 개수 구하기
	if(cITF->GetNumOfModules() == 0)
	{
		ERRPRINT_GOTO(_EXIT, _T("GetNumOfModules error (Error Code : %x)"), GetLastError());
	}
	// 모든 모듈의 주소 구하기
	if(cITF->GetBaseAddressOfModules() == FALSE)
	{
		ERRPRINT_GOTO(_EXIT, _T("GetBaseAddressOfModules error (Error Code : %x)"), GetLastError());
	}
	*/

_EXIT:
	SAFECLOSEHANDLE32(hImage);
}

/*	Function : ScanAllProcesses
	Description : 모든 프로세스에 대해서 스캔한다.
*/
BOOL CImageToFile::ScanAllProcesses()
{
	BOOL bRet = FALSE;
	DWORD *aProc = NULL;
	HANDLE hSnapProc = NULL;
	PROCESSENTRY32 stPe32 = {0};

	hSnapProc = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if(hSnapProc == INVALID_HANDLE_VALUE)
	{
		ERRPRINT_GOTO(_EXIT, "CreateToolhelp32Snapshot");
	}
	
	stPe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hSnapProc, &stPe32))
	{
		ERRPRINT_GOTO(_EXIT, "Process32First");
	}

	do
	{
		dwPid = stPe32.th32ProcessID;
		CString strProcPath = stPe32.szExeFile;
		strProcess = strProcPath.Right(strProcPath.GetLength() - strProcPath.ReverseFind(_T('\\')) - 1);

		hImage = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
		if(hImage == NULL)
		{
			DBGPRINT("Wrong PID");
		}

		if(!ScanOneProcess())
		{
			DBGPRINT("ScanOneProcess returns false");
		}
	}
	while (Process32Next(hSnapProc, &stPe32));

	bRet = TRUE;
_EXIT:
	SAFECLOSEHANDLE32(hImage);
	SAFECLOSEHANDLE16(hSnapProc);
	return bRet;
}

/*	Function : GetAllMemories
	Description : 한 프로세스 내의 Commit된 모든 메모리 주소를 알아낸다.
*/
BOOL CImageToFile::GetAllMemories()
{
	BOOL	bRet = FALSE;
	MEMORY_BASIC_INFORMATION MBI = {0};
	UINT_PTR	upMemAddr = upMinMem;
	DWORD	dwBaseSize = 0;

	// lstAllMem 리스트 비우기
	if(!lstAllMem.empty())
	{
		lstAllMem.clear();
	}

	do
	{
		// 여기에서 VirtualQueryEx를 하는 이유는 upMemAddr가 BaseAddress 주소가 아닐 수 있기 때문임
		if(VirtualQueryEx(hImage, (LPCVOID)upMemAddr, &MBI, sizeof(MEMORY_BASIC_INFORMATION)) != sizeof(MEMORY_BASIC_INFORMATION) ||
			MBI.RegionSize <= 0 || MBI.State != MEM_COMMIT)
		{
			dwBaseSize = MBI.RegionSize <= 0 ? 0x1000 : MBI.RegionSize;
			WARNPRINT_GOTO(_CONTINUE, "VirtualQueryEx");
		}
		
		// BaseAddress부터 이어진 사이즈를 얻음 (주소가 유효하지 않으면 0을 리턴)
		if(dwBaseSize = GetSizeOfChunk((UINT_PTR&)MBI.BaseAddress))
		{
			lstAllMem.push_back(SMem((UINT_PTR)MBI.BaseAddress, dwBaseSize));
		}
		
_CONTINUE:
		upMemAddr += dwBaseSize;
	} while(upMemAddr < upMaxMem);

	bRet = TRUE;
//_EXIT:
	return bRet;
}

/*	Function : list_NotIncludedInAllModules
	Description : lstAddr 리스트와 lstMemRegion 리스트를 비교하여 lstAddr 리스트에만 있는 요소를 lstResult로 복사한다. 비교 기준값은 SMem.BaseAddr이다.
				(std::set_difference 코드 참고)

	ex) lstAddr의 BaseAddr가 100, 200, 300, 400이 있을 때, lstMemRegion의 BaseAddr가 60-70, 90-150, 160-170, 300-400, 450-500이라면 200 주소만 lstResult에 저장된다.
		
	100	──────X───┬───> 60-70
				  │	
	200	────────┐ └O──> 90-150
				│
	300	──────┐ ├──X──> 160-170
			  │ │
	400	─────┐│	└──X──> 300-400 (300이 200보다 크기 때문에 200은 lstMemRegion 리스트에는 200 주소가 없다. 따라서, 200 주소는 lstResult에 저장된다.)
			 └┴────O──>	300-400
						450-500
*/
list<SMem>& CImageToFile::list_NotIncludedInAllModules (list<SMem>& lstAddr, list<SMem>& lstMemRegion, list<SMem>& lstResult)
{
	list<SMem>::iterator iAddr;
	list<SMem>::iterator iMemRegion;

	// 비교할 두 리스트 정렬
	lstAddr.sort(SMemSort());
	lstMemRegion.sort(SMemSort());

	iAddr = lstAddr.begin();
	iMemRegion = lstMemRegion.begin();

	while(iAddr != lstAddr.end() && iMemRegion != lstMemRegion.end())
	{
		if(iMemRegion->BaseAddr + iMemRegion->Size < iAddr->BaseAddr)
		{
			iMemRegion++;
		}
		else if(iMemRegion->BaseAddr <= iAddr->BaseAddr && iAddr->BaseAddr <= iMemRegion->BaseAddr + iMemRegion->Size)
		{
			iAddr++;
		}
		else
		{
			lstResult.push_back(SMem(GetImageBase((*iAddr).BaseAddr), (*iAddr).Size));
			iAddr++;
		}
	}

	// lstAddr의 남은 값이 있다면 모두 lstResult에 복사
	while(iAddr != lstAddr.end())
	{
		lstResult.push_back(SMem(GetImageBase((*iAddr).BaseAddr), (*iAddr).Size));
		iAddr++;
	}

	return lstResult;
}

/*	Function : list_IncludedInAllMemories
	Description : lstAddr 리스트에 있는 주소가 lstMemRegion 주소 대역에 있는지 검사하고 있다면 그 주소 대역을 lstResult에 복사한다
	lstAddr의 주소는 BaseAddress가 아니기 때문에 해당 주소가 어느 주소 영역에 속하는지 구할 때 사용한다
*/
list<SMem>& CImageToFile::list_IncludedInAllMemories (list<SMem>& lstAddr, list<SMem>& lstMemRegion, list<SMem>& lstResult)
{
	list<SMem>::iterator iAddr;
	list<SMem>::iterator iMemRegion;

	lstAddr.sort(SMemSort());
	lstMemRegion.sort(SMemSort());

	iAddr = lstAddr.begin();
	iMemRegion = lstMemRegion.begin();

	while(iAddr != lstAddr.end() && iMemRegion != lstMemRegion.end())
	{
		if(iMemRegion->BaseAddr + iMemRegion->Size < iAddr->BaseAddr)
		{
			iMemRegion++;
		}
		else if(iMemRegion->BaseAddr <= iAddr->BaseAddr && iAddr->BaseAddr <= iMemRegion->BaseAddr + iMemRegion->Size)
		{
			lstResult.push_back(*iMemRegion);
			iAddr++;
		}
		else
		{
			// 검색할 메모리가 모든 커밋된 모든 메모리 영역에 포함되지 않는 경우 (발생할 확률 적음)
			WARNPRINT("MemAddress is not in all memories");
			iAddr++;
		}
	}

	return lstResult;
}

/*	Function : ScanOneProcess
	Description : 하나의 프로세스에 대해서 스캔
*/
BOOL CImageToFile::ScanOneProcess()
{
	BOOL	bRet = FALSE;
	DWORD	dwMemSize = 0;
	DWORD	dwBytesRead = 0;
	DWORD	dwMzOffset = 0;			// 메모리에서 MZ 시그니처까지의 오프셋
	BYTE*	pSusMem = NULL;			// MZ 시그니처를 가진 메모리 영역을 위한 포인터
	BYTE*	pChunkMem = NULL;		// PE를 가진 메모리 영역을 위한 포인터
	list<SMem> lstSusThdMem;		// 모든 모듈 리스트에 포함되지 않는 스레드 시작점 주소를 가진 리스트
	list<SMem> lstSusThdMemBand;	// lstSusThdMem 리스트 주소를 모든 메모리에서 검색하여 해당 메모리 대역을 저장한 리스트
	TCHAR	szImagePath[MAX_PATH] = {0};
	
	// 모든 프로세스 스캔인 경우에는 
	if(bOpAllProc == FALSE)
	{
		GetModuleFileNameEx(hImage, NULL, szImagePath, _countof(szImagePath));
		CString strImagePath = szImagePath;
		strProcess = strImagePath.Right(strImagePath.GetLength() - strImagePath.ReverseFind(_T('\\')) - 1);
	}

	if(strProcess.IsEmpty())
	{
		strProcess = szImagePath;
	}
	_tprintf(_T("%s is being processed... (PID : %d)\n"), strProcess, dwPid);

	// 프로세스 내의 모든 모듈 개수 알아오기
	if(!GetNumOfModules())
	{
		ERRPRINT_GOTO(_EXIT, "GetNumOfModules");
	}
	// 프로세스 내의 모든 모듈 리스트 얻기
	if(!GetAllModMems())
	{
		ERRPRINT_GOTO(_EXIT, "GetAllModMems");
	}

	if(bOpSusMod)
	{
		/* Suspicious 알고리즘 #1 - 의심 스레드 기반 (정의된 모듈 메모리 범위에서 시작하지 않은 스레드 시작 주소 탐지) */
		// 프로세스 내의 모든 스레드 시작 주소 리스트 얻기
		if(!GetAllThdMems())
		{
			ERRPRINT_GOTO(ALGORITHM2, "GetAllThdMems");
		}
		// 모든 스레드 시작 주소 리스트에서 각 시작 주소가 모듈들 주소 대역에 포함되는지 검사 (포함되지 않는 주소는 lstSusThdMem으로 리턴)
		list_NotIncludedInAllModules(lstThdMem, lstAllMod, lstSusThdMem);
		if(lstSusThdMem.empty())
		{
			ERRPRINT_GOTO(ALGORITHM2, "lstSusThdMem empty");
		}

		_tprintf(_T("Algorithm #1 : There is injected code or pe\n"));
		// 모듈들 주소 대역에 포함되지 않는 스레드 시작 주소들의 주소 대역(처음과 끝)을 알아냄
		if(GetMemBand(lstSusThdMem, lstSusThdMemBand))
		{
			DBGPRINT("Suspicious Algorithm #1 Success!")
		}
		// 모듈들 주소 대역에 포함되지 않는 스레드 시작 주소 리스트(lstSusThdMem)를 모든 메모리 대역에서 찾아서 실제 메모리 대역(ImageBase ~ ImageBase + Size)을 찾음
		//list_IncludedInAllMemories(lstSusThdMem, lstAllMem, lstSusThdMemBand);
ALGORITHM2:
		if(CheckThreadBaseAddress(lstSusThdMemBand))
		{
			_tprintf(_T("Algorithm #2 : There is injected code or pe\n"));
			DBGPRINT("Suspicious Algorithm #2 Success!")
		}
		// 아래 메인 스레드를 검사하는 알고리즘은 전체 스레드를 검사하는 것으로 변경한다.
		// 메인 스레드 주소를 기반으로 ImageBase를 알아내고 그곳에 실행 권한이 있는지와 PE인지 확인. 두 가지가 맞다면 lstSusThdMemBand에 세팅
		//if(CheckMainModule(lstSusThdMemBand))
		//{
		//	DBGPRINT("Suspicious Algorithm #2 Success!")
		//}
		/* 부모 프로세스가 없고 Owner PID가 다르면 의심 - 알고리즘 #1, #2로 커버 가능할 듯 */
ALGORITHM3:
		;
		/* Suspicious 알고리즘 #3 - 의심 메모리 기반 (모든 메모리 영역에서 정의된 모듈 메모리 범위를 제외하고 실행 권한이 있는 주소 탐지) */
	}
	else
	{
		// 프로세스 내의 모든 메모리 주소 대역 얻기
		if(!GetAllMemories())
		{
			ERRPRINT_GOTO(_EXIT, "GetAllMemories");
		}
		// 메모리의 모든 메모리를 체크하도록 lstSusThdMemBand에 모든 메모리 주소를 담고 있는 lstAllMem을 복사
		lstSusThdMemBand.assign(lstAllMem.begin(), lstAllMem.end());
	}

	if(lstSusThdMemBand.empty())
	{
		ERRPRINT_GOTO(_EXIT, "lstSusThdMemBand is empty");
	}

	//lstSusThdMemBand.unique();
	CheckPeAndMakeFile(lstSusThdMemBand);

	bRet = TRUE;
_EXIT:
	return bRet;
}

/*	Function : CheckPeAndMakeFile
	Description : 리스트로 들어온 메모리 주소들에 PE가 있는지 확인하고 맞다면 파일로 생성한다.
*/
BOOL CImageToFile::CheckPeAndMakeFile(list<SMem>& lstMem)
{
	BOOL	bRet = FALSE;
	list<SMem>::iterator iMem = lstMem.begin();;
	PBYTE	pSusMem = NULL;
	PBYTE	pChunkMem = NULL;
	SIZE_T	dwBytesRead = 0;
	DWORD	dwMzOffset = 0;

	do
	{
		pSusMem = new BYTE[iMem->Size];
		if(ReadProcessMemory(hImage, (LPCVOID)iMem->BaseAddr, pSusMem, iMem->Size, &dwBytesRead) == FALSE)
		{
			WARNPRINT_GOTO(_CONTINUE, "ReadProcessMemory");
		}
		//_tprintf(_T("dwMemAddr : 0x%x\n"), iRes->BaseAddr);

		if((dwMzOffset = ChkPE(pSusMem, iMem->Size)) == -1)
		{
			WARNPRINT_GOTO(_CONTINUE, "ChkPE");
		}

		// MZ, PE 시그니처가 존재하는 경우 이 메모리부터 연결된 전체 메모리 영역의 크기(SizeOfChunk)를 구한다. 
		DWORD dwSizeOfChunk = 0;
		dwSizeOfChunk = GetSizeOfChunk(iMem->BaseAddr);
		//_tprintf(_T("dwSizeOfChunk : 0x%x\n"), dwSizeOfChunk);
		pChunkMem = new BYTE[dwSizeOfChunk];
		ReadAndMakeFile((UINT_PTR)(iMem->BaseAddr), pChunkMem, dwSizeOfChunk);
		SAFEDELETEARRAY1(pChunkMem);

_CONTINUE:
		SAFEDELETEARRAY1(pSusMem);
		iMem++;
	} while(iMem != lstMem.end());

	bRet = TRUE;
	return bRet;
}

/*	Function : GetMemBand
	Description : 특정 메모리 위치를 Input으로 해당 메모리 대역(처음 위치와 끝 위치)을 알아냄
	현재까지는 의심 스레드 시작 주소의 주소 대역(시작 주소와 끝 주소) 리스트를 얻음
*/
BOOL CImageToFile::GetMemBand(list<SMem>& lstSomeMem, list<SMem>& lstMemBand)
{
	BOOL	bRet = FALSE;
	list<SMem>::iterator iSomeMem;
	list<SMem>::iterator iMemRegion;
	UINT_PTR	upBaseAddr = 0;
	DWORD		dwBandSize = 0;

	if(lstSomeMem.empty())
	{
		ERRPRINT_GOTO(_EXIT, "No members in lstSomeMem");
	}

	lstSomeMem.sort(SMemSort());

	iSomeMem = lstSomeMem.begin();

	while(iSomeMem != lstSomeMem.end())
	{
		// 의심 스레드 시작 주소의 메모리 시작 주소 얻기
		upBaseAddr = GetImageBase(iSomeMem->BaseAddr);
		// 의심 스레드 메모리 사이즈 얻기
		dwBandSize = GetSizeOfChunk(upBaseAddr);
		
		if(upBaseAddr < upMinMem || upMaxMem < upBaseAddr || dwBandSize <= 0)
		{
			WARNPRINT("One band of suspicious thread memories can't be gotten");
		}
		else
		{
			lstMemBand.push_back(SMem(upBaseAddr, dwBandSize));
			// 의심 스레드 대역을 하나라도 알아내면 TRUE 리턴
			bRet = TRUE;
		}
		iSomeMem++;
	}
	
_EXIT:
	return bRet;
}

/*	Function : CImageToFile
	Description : 생성자. 사용자가 입력한 옵션 체크
*/
CImageToFile::CImageToFile(int argc, TCHAR* argv[]) : stMainThdMem(0, 0)
{
	// 변수 초기화
	SYSTEM_INFO		stSI = {0};
	CString strTemp = _T("");
	dwNumOfMod = 0;
	hImage = NULL;
	GetSystemInfo(&stSI);
	upMinMem = (UINT_PTR)stSI.lpMinimumApplicationAddress;
	upMaxMem = (UINT_PTR)stSI.lpMaximumApplicationAddress;
	bOpAllProc = FALSE;
	bOpSusMod = FALSE;
	bOpErr = FALSE;
	strProcess = _T("");

#if DEBUGGING
	bOpAllProc = FALSE;
	bOpSusMod = TRUE;
	dwPid = 896;
#else
	int param_opt;

	if(argc == 1)
	{
		bOpErr = TRUE;
		Help(argv[0]);
		ERRPRINT_GOTO(_EXIT, "There are no args");
	}

	// 옵션 파싱
	while(-1 != (param_opt = getopt(argc, argv, _T("ap:s"))))
	{
		switch(param_opt)
		{
		case _T('a'):  
			bOpAllProc = TRUE;
			break;
		case _T('p'):
			bOpAllProc = FALSE;
			dwPid = _ttoi(optarg);
			break;
		case _T('s'):  
			bOpSusMod = TRUE;
			break;
		case '?':
		default:
			bOpErr = TRUE;
			Help(argv[0]);
			ERRPRINT_GOTO(_EXIT, "args error");
		}
	}
#endif

	// 로그 파일을 위한 설정
	strTemp = GetTempFilePath(_T("ITF"));
	logFile.open(strTemp, ios::out | ios::app);

	// 디버그 권한 얻기
	SetDebugPrivilege();

_EXIT:
;
}

void CImageToFile::Help(LPCTSTR szPrgPath)
{
	CString strPrgPath = szPrgPath;
	// 파일 이름 알아내기
	CString strPrgName = strPrgPath.Right(strPrgPath.GetLength() - strPrgPath.ReverseFind(_T('\\')) - 1);

	_tprintf(_T("\n[Summary]\nThis program makes pe files from images in memory.\n\n"));
	_tprintf(_T("[Version]\n"));
	_tprintf(_T("v2.1\n\n"));
	_tprintf(_T("[Usage]\n"));
	_tprintf(_T("> %s [-a | -p <PID>] [-s]\n\n"), strPrgName);
	_tprintf(_T("[Option]\n"));
	_tprintf(_T("-a : scan all processes\n"));
	_tprintf(_T("-p <PID> : scan one process\n"));
	_tprintf(_T("-s : scan suspicious modules\n\n"));
	_tprintf(_T("[Notes]\n"));
	_tprintf(_T("A log file will be created in %%temp%% folder\n"));	
}

CImageToFile::~CImageToFile()
{
	logFile.close();
}

/*	Function : ChkPE
	Description : pMem에서 PE 헤더 부분이 있는지 간단히 검사 후 있다면 MZ 부분의 오프셋을 리턴하고
	없다면 -1 리턴
*/
DWORD CImageToFile::ChkPE(const BYTE* const pMem, const DWORD dwMemSize)
{
	const BYTE* const pStartOfMem = pMem;
	const BYTE* const pEndOfMem = pMem + dwMemSize;
	DWORD dwIdx = 0;
	DWORD dwPeOffset = 0;
	DWORD dwMinimumSize = 0x400;

	if(dwMemSize < dwMinimumSize)
		return -1;

	// MZ와 PE 존재 검사
	for(dwIdx = 0; dwIdx < dwMemSize; dwIdx++)
	{
		if(pMem[dwIdx] == 'M' && pMem[dwIdx + 1] == 'Z')
		{
			dwPeOffset = *((DWORD *)&pMem[dwIdx + 0x3C]);	// elfanew
			if(dwPeOffset < dwMemSize && pMem[dwPeOffset] == 'P' && pMem[dwPeOffset + 1] == 'E')
			{
				break;
			}
		}
	}

	if(dwIdx == dwMemSize)
	{
		DBGPRINT_GOTO(_EXIT, "Not Pe");
	}

	// Image Dos Header 구하기
	const PIMAGE_DOS_HEADER const pIDH = (const PIMAGE_DOS_HEADER const)(pMem + dwIdx);
	if((const PBYTE)pIDH + sizeof(IMAGE_DOS_HEADER) >= pMem + dwMemSize)
	{
		DBGPRINT_GOTO(_EXIT, "Corrupted Pe");
	}

	// Image Nt Header 구하기
	const PIMAGE_NT_HEADERS const pINH = (const PIMAGE_NT_HEADERS const)(pMem + pIDH->e_lfanew);
	if((const PBYTE)((const PBYTE const)pINH) + sizeof(IMAGE_NT_HEADERS) >= pMem + dwMemSize)
	{
		DBGPRINT_GOTO(_EXIT, "Corrupted Pe");
	}

#ifdef _WIN64
	// 64bit 버전에서는 32bit 모듈을 구하지 않음
	if(pINH->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		DBGPRINT_GOTO(_EXIT, "32bit type pe");
	}
#else
	// 32bit 버전에서는 64bit 모듈을 구하지 않음
	if(pINH->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		DBGPRINT_GOTO(_EXIT, "64bit type pe");
	}
#endif

	return dwIdx;
_EXIT:
	return -1;
}

/*	Function : GetSizeOfChunk
	Description : 주어진 메모리 주소부터 시작하여 연결된 전체 메모리 영역의 크기를 구함
*/
DWORD CImageToFile::GetSizeOfChunk(const UINT_PTR& _MemAddr)
{
	DWORD	dwSizeOfChunk = 0;
	DWORD	dwSizeOfMBI = 0;
	MEMORY_BASIC_INFORMATION MBI = {0};
	UINT_PTR	MemAddr = _MemAddr;
	do 
	{
		if(VirtualQueryEx(hImage, (LPCVOID)MemAddr, &MBI, sizeof(MEMORY_BASIC_INFORMATION)) != sizeof(MEMORY_BASIC_INFORMATION) ||
			MBI.RegionSize <= 0 || MBI.State != MEM_COMMIT)
		{
			break;
		}

		dwSizeOfChunk += MBI.RegionSize;
		MemAddr += MBI.RegionSize;
	} while (MemAddr < upMaxMem);

	return dwSizeOfChunk;
}

/*	Function : GetImageBase
	Description : 인자로 들어온 MemAddr와 이어진 최상위 BaseAddress를 구한다
*/
UINT_PTR CImageToFile::GetImageBase(const UINT_PTR& _MemAddr)
{
	DWORD	dwSizeOfChunk = 0;
	DWORD	dwSizeOfMBI = 0;
	UINT_PTR	MemAddr = _MemAddr;
//	UINT_PTR	upCurBase = 0;		// 현재 주소(pMemAddr)의 베이스 주소
//	UINT_PTR	upUpperMem = 0;		// 현재 주소와 연결된 상위(숫자로는 낮은 쪽) 주소
//	UINT_PTR	upUpperBase = 0;	// 현재 주소와 연결된 상위(숫자로는 낮은 쪽) 베이스 주소
	UINT_PTR	upAllcationBase = 0;
	MEMORY_BASIC_INFORMATION MBI = {0};

	// 인자로 들어온 MemAddr가 속한 BaseAddress 구하기
	if(VirtualQueryEx(hImage, (LPCVOID)MemAddr, &MBI, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		if(MBI.State == MEM_COMMIT)
		{
			upAllcationBase = (UINT_PTR)MBI.AllocationBase;
		}
		else
		{
			ERRPRINT_GOTO(_EXIT, "VirtualQueryEx state");
		}
	}
	else
	{
		ERRPRINT_GOTO(_EXIT, "VirtualQueryEx");
	}

	/* 2015.05.17 과거에는 현재 BaseAddress에 -1을 하여 계속 역추적하였으나, 그냥 위에서 AllocationBase를 구하는 것으로 대체함
	// 상위 메모리 주소는 현재 BaseAddress - 1을 한 주소를 포함
	upUpperMem = upCurBase - 1;
	// 상위에 이어진 메모리 주소를 추적
	do
	{
		if(dwSizeOfMBI = VirtualQueryEx(hImage, (LPCVOID)upUpperMem, &MBI, sizeof(MEMORY_BASIC_INFORMATION)))
		{
			if(MBI.State == MEM_COMMIT)
			{
				upUpperBase = (UINT_PTR)MBI.BaseAddress;
			}
			else
			{
				break;
			}
		}
		upUpperMem = upUpperBase - 1;
	} while (dwSizeOfMBI != 0 && MBI.State == MEM_COMMIT);
	*/
	
_EXIT:
	//return upUpperBase == 0 ? upCurBase : upUpperBase;
	return upAllcationBase;
}

/*	Function : CheckMainModule
	Description : 일반적인 PE는 헤더에 실행 권한이 없다. 따라서 메인 스레드 시작 주소가 있는 메모리 영역의 ImageBase의 권한에 
	실행 권한이 있다면 인젝션된 영역이라고 판단할 수 있다.
*/
BOOL CImageToFile::CheckMainModule(list<SMem>& lstResult)
{
	BOOL	bRet = FALSE;
	list<SMem>::iterator	iThdMem;
	MEMORY_BASIC_INFORMATION MBI = {0};
	UINT_PTR	upImageBase = 0;
	DWORD		dwImageSize = 0;
	DWORD		dwMzOffset = 0;
	PBYTE		pSusMem = NULL;
	DWORD		dwBytesRead = 0;

	if(stMainThdMem.BaseAddr == 0)
	{
		ERRPRINT_GOTO(_EXIT, "stMainThdMem empty");
	}

	// 메인 스레드의 시작 주소가 포함된 메모리 영역의 BaseAddress를 구함
	upImageBase = GetImageBase(stMainThdMem.BaseAddr);

	// BaseAddress의 메모리 권한 확인
	if(VirtualQueryEx(hImage, (LPCVOID)upImageBase, &MBI, sizeof(MEMORY_BASIC_INFORMATION)) != sizeof(MEMORY_BASIC_INFORMATION) ||
		MBI.RegionSize <= 0 || MBI.State != MEM_COMMIT)
	{
		DBGPRINT_GOTO(_EXIT, "VirtualQueryEx");
	}

	// 해당 ImageBase 영역이 현재 실행 권한이 있는지 검사 (순서상 ChkPE가 먼저 검사되어야 하나 성능상 권한을 먼저 체크)
	if(MBI.Protect != PAGE_EXECUTE && MBI.Protect != PAGE_EXECUTE_READ && MBI.Protect != PAGE_EXECUTE_READWRITE)
	{
		DBGPRINT_GOTO(_EXIT, "Maybe normal PE");
	}

	pSusMem = new BYTE[MBI.RegionSize];
	if(ReadProcessMemory(hImage, (LPCVOID)upImageBase, pSusMem, MBI.RegionSize, &dwBytesRead) == FALSE)
	{
		DBGPRINT_GOTO(_EXIT, "ReadProcessMemory");
	}

	// 해당 BaseAddress 영역에 PE 구조가 있는지 확인
	dwMzOffset = ChkPE((const BYTE* const)pSusMem, MBI.RegionSize);
	if(dwMzOffset < 0)
	{
		// PE를 못 찾은 경우
		DBGPRINT_GOTO(_EXIT, "Maybe not PE");
	}
	else if(dwMzOffset > 0)
	{
		// PE를 찾았으나 ImageBase에서 떨어진 곳에서 찾은 경우
		DBGPRINT_GOTO(_EXIT, "Maybe corrupt PE");
	}

	dwImageSize = GetSizeOfChunk(upImageBase);
	lstResult.push_back(SMem((UINT_PTR)MBI.BaseAddress, dwImageSize));
	bRet = TRUE;
_EXIT:
	SAFEDELETEARRAY1(pSusMem);
	return bRet;
}

/*	Function : CheckThreadBaseAddress
	Description : 일반적인 PE는 Image 타입을 가진다. 하지만 VirtualAlloc나 VirtualAllocEx에 의해 생성되는 힙은 Private 타입을 가진다.
	혹은 매핑된 메모리도 Mapped 타입을 가진다. 따라서, PE이면서 Image 타입을 가지지 않았다면 인젝션을 의심할 수 있다.
	코드이면서 Image 타입을 가지지 않는 경우는 패커에서 많이 사용할 것 같다. 예를 들면, 자신 메모리 영역에 힙을 할당하고
	거기에 코드를 쓰고 새로운 쓰레드를 생성하여 실행시킨다면 이 경우에 해당한다. 따라서 PE인 경우만 의심한다. (일반적으로 정상 패커가
	자신 메모리 영역에 힙을 할당해서 PE를 쓰고 새로운 쓰레드로 실행시키는 경우는 거의 없다고 판단함)
*/
BOOL CImageToFile::CheckThreadBaseAddress(list<SMem>& lstResult)
{
	BOOL	bRet = FALSE;
	list<SMem>::iterator	iThdMem;
	MEMORY_BASIC_INFORMATION MBI = {0};
	UINT_PTR	upImageBase = 0;
	DWORD		dwImageSize = 0;
	DWORD		dwMzOffset = 0;
	PBYTE		pSusMem = NULL;
	DWORD		dwBytesRead = 0;

	if(lstThdMem.empty())
	{
		ERRPRINT_GOTO(_EXIT, "lstThdMem empty");
	}

	for(iThdMem = lstThdMem.begin(); iThdMem != lstThdMem.end(); iThdMem++)
	{
		// 쓰레드 시작 주소의 메모리 타입 확인
		if(VirtualQueryEx(hImage, (LPCVOID)iThdMem->BaseAddr, &MBI, sizeof(MEMORY_BASIC_INFORMATION)) != sizeof(MEMORY_BASIC_INFORMATION) ||
			MBI.RegionSize <= 0 || MBI.State != MEM_COMMIT)
		{
			DBGPRINT_GOTO(_CONTINUE, "VirtualQueryEx"); 
		}

		// 해당 ImageBase 영역이 Image 타입인지 검사. 정상 이미지는 Image 타입
		if(MBI.Type == MEM_IMAGE)
		{
			DBGPRINT_GOTO(_CONTINUE, "Maybe normal");
		}

		// 쓰레드의 시작 주소가 포함된 메모리 영역의 BaseAddress를 구함
		upImageBase = GetImageBase(iThdMem->BaseAddr);

		// 쓰레드 베이스 주소 메모리 사이즈 구하기
		if(VirtualQueryEx(hImage, (LPCVOID)upImageBase, &MBI, sizeof(MEMORY_BASIC_INFORMATION)) != sizeof(MEMORY_BASIC_INFORMATION) ||
			MBI.RegionSize <= 0 || MBI.State != MEM_COMMIT)
		{
			DBGPRINT_GOTO(_CONTINUE, "VirtualQueryEx"); 
		}

		pSusMem = new BYTE[MBI.RegionSize];
		if(ReadProcessMemory(hImage, (LPCVOID)upImageBase, pSusMem, MBI.RegionSize, &dwBytesRead) == FALSE)
		{
			DBGPRINT_GOTO(_CONTINUE, "ReadProcessMemory");
		}

		// 해당 BaseAddress 영역에 PE 구조가 있는지 확인
		dwMzOffset = ChkPE((const BYTE* const)pSusMem, MBI.RegionSize);
		if(dwMzOffset < 0)
		{
			// PE를 못 찾은 경우
			DBGPRINT_GOTO(_CONTINUE, "Maybe not PE");
		}
		else if(dwMzOffset > 0)
		{
			// PE를 찾았으나 ImageBase에서 떨어진 곳에서 찾은 경우
			DBGPRINT_GOTO(_CONTINUE, "Maybe corrupt PE");
		}

		dwImageSize = GetSizeOfChunk(upImageBase);
		lstResult.push_back(SMem((UINT_PTR)MBI.BaseAddress, dwImageSize));
		bRet = TRUE;
_CONTINUE:
		SAFEDELETEARRAY1(pSusMem);
	}

_EXIT:
	return bRet;
}

/*	Function : GetFileName
	Description : PE 구조를 인자로 받아 리소스 영역의 버전 정보를 참조하여 파일 이름을 알아낸다.
*/
BOOL CImageToFile::GetFileName(const BYTE* const pPe, const DWORD dwSizeOfChunk, const LPCTSTR szFileName)
{
	BOOL bSuc = FALSE;

	PIMAGE_DOS_HEADER pIDH = NULL;
	PIMAGE_NT_HEADERS pINH = NULL;
	DWORD dwNumOfSecs = 0;
	DWORD dwSizeOfIOH = 0;

	try {
		pIDH = (PIMAGE_DOS_HEADER)(pPe);					// IMAGE_DOS_HEADER
		pINH = (PIMAGE_NT_HEADERS)(pPe + pIDH->e_lfanew);	// IMAGE_NT_HEADER
		dwNumOfSecs = pINH->FileHeader.NumberOfSections;			// NumberOfSections
		dwSizeOfIOH = pINH->FileHeader.SizeOfOptionalHeader;		// SizeOfOptionalHeader
	}
	catch(...)
	{
//		ERRPRINT_GOTO(_EXIT, _T("When analyzing PE Header (0x%x) - ReadAndMakeFile function"), dwMemAddr);
	}

//_EXIT:
	return bSuc;
}

/*	Function : ReadAndMakeFile
	Description : 메모리에서 구한 영역만큼 가져와서 일단 Chunk 파일은 떨군다.
	그리고 Chunk 파일을 파일형태로 재정비하여 파일로 떨군다. 
	처음에 떨궈진 Chunk 파일은 이미지 형태의 정비되지 않은 메모리 영역일 것이고,
	두 번째로 떨군 파일은 어느정도 파일형태로 정제된 파일이다. 파일형태로 정제과정이 실패하면 떨구지 않는다.
*/
BOOL CImageToFile::ReadAndMakeFile(const UINT_PTR& MemAddr, const BYTE* const pImageMem, const DWORD dwSizeOfChunk)
{
	SIZE_T dwBytesRead = 0;
	DWORD dwBytesWritten = 0;
	DWORD dwErr = 0;
	BOOL bRet = FALSE;
	HANDLE hChunkFile = INVALID_HANDLE_VALUE;
	HANDLE hPeFile = INVALID_HANDLE_VALUE;
	//LPTSTR szChunkDir = _T("Chunks");
	CString strModuleDir = _T("");
	//LPTSTR szFileDir = _T("Files");
	CString strFileDir = _T("");
	//LPTSTR szFileName[MAX_PATH] = {0};
	PIMAGE_SECTION_HEADER* pISH = NULL;
	CString strFolderName = _T("");
	CString strModuleFullPath = _T("");
	CString strFileFullPath = _T("");
	TCHAR szModulePath[MAX_PATH] = {0};
	CString strModulePath = _T("");
	CString strModuleName = _T("");
	DWORD	dwPathLen = 0;

	strFolderName.Format(_T("%s_%d"), strProcess, dwPid);				// 프로세스별 폴더 이름 (프로세스 이름_PID)
	strModuleDir.Format(_T("%s\\%s"), strFolderName, _T("Images"));		// Images 폴더에는 메모리에 있는 PE 그대로의 데이터가 저장됨. 원래 이름이 Chunks이었지만 의미 전달을 위해 Images로 변경
	strFileDir.Format(_T("%s\\%s"), strFolderName, _T("Files"));		// 메모리에 있는 PE들이 파일 형태로 변형되어 저장될 폴더

	/* Step 1. 각 프로세스 별로 폴더를 생성하고 Image가 들어갈 Images 폴더와 File이 들어갈 Files 폴더 생성 */
	if(!CreateDirectory(strFolderName, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
	{	// 디렉토리를 못 만드는 경우 (이미 존재한다면 그냥 진행)
		ERRPRINT_GOTO(_EXIT, "CreateDirectory");
	}
	if(!CreateDirectory(strModuleDir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
	{	// 디렉토리를 못 만드는 경우 (이미 존재한다면 그냥 진행)
		ERRPRINT_GOTO(_EXIT, "CreateDirectory");
	}
	if(!CreateDirectory(strFileDir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
	{	// 디렉토리를 못 만드는 경우 (이미 존재한다면 그냥 진행)
		ERRPRINT_GOTO(_EXIT, "CreateDirectory");
	}

	/* Step 2. 해당 메모리 영역을 읽어서 Chunks와 Files 생성 */
	if(ReadProcessMemory(hImage, (LPCVOID)MemAddr, (LPVOID)pImageMem, dwSizeOfChunk, &dwBytesRead) == FALSE)
	{
		ERRPRINT_GOTO(_EXIT, "ReadProcessMemory");
	}

	DWORD dwMzOffset = 0;
	dwMzOffset = ChkPE(pImageMem, dwSizeOfChunk);

	/*
	if(GetFileName(pImageMem + dwMzOffset, dwSizeOfChunk - dwMzOffset, szFileName) == TRUE)
	{
		strChunkName.Format(_T("%s\\%s"), szChunkDir, szFileName);
	}
	else
	{
	*/

	dwPathLen = GetModuleFileNameEx(hImage, (HMODULE)MemAddr, szModulePath, _countof(szModulePath));
	if(dwPathLen > 0)
	{
		strModulePath = szModulePath;
		strModuleName = strModulePath.Right(strModulePath.GetLength() - strModulePath.ReverseFind(_T('\\')) - 1);
		strModuleFullPath.Format(_T("%s\\%s_0x%x"), strModuleDir, strModuleName, MemAddr);
	}
	else
	{
		strModuleFullPath.Format(_T("%s\\0x%x"), strModuleDir, MemAddr);
	}

	hChunkFile = CreateFile(strModuleFullPath,
							GENERIC_WRITE,
							0,
							NULL,
							CREATE_ALWAYS,
							FILE_ATTRIBUTE_NORMAL,
							NULL);
	if(hChunkFile == INVALID_HANDLE_VALUE)
	{
		ERRPRINT_GOTO(_EXIT, "CreateFile");
	}

	/* Step 2-1. Chunks 생성 */
	if(WriteFile(hChunkFile, pImageMem, dwSizeOfChunk, &dwBytesWritten, NULL) == FALSE)
	{
		ERRPRINT_GOTO(_EXIT, "WriteFile"); 
	}

	if(dwBytesWritten != dwSizeOfChunk)	
	{ 
		ERRPRINT_GOTO(_EXIT, "Can't write chunk file enough"); 
	}

	/* Step 2-2. PE 헤더 분석 */
	PIMAGE_DOS_HEADER pIDH = NULL;
	PIMAGE_NT_HEADERS pINH = NULL;
	DWORD dwNumOfSecs = 0;
	DWORD dwSizeOfIOH = 0;

	try {
		pIDH = (PIMAGE_DOS_HEADER)(pImageMem + dwMzOffset);			// IMAGE_DOS_HEADER
		pINH = (PIMAGE_NT_HEADERS)((PBYTE)pIDH + pIDH->e_lfanew);	// IMAGE_NT_HEADER
		dwNumOfSecs = pINH->FileHeader.NumberOfSections;			// NumberOfSections
		dwSizeOfIOH = pINH->FileHeader.SizeOfOptionalHeader;		// SizeOfOptionalHeader
		pISH = new PIMAGE_SECTION_HEADER[dwNumOfSecs];				// IMAGE_SECTION_HEADER 메모리 할당
		for(DWORD dwSecIdx = 0; dwSecIdx < dwNumOfSecs; dwSecIdx++)
		{
			pISH[dwSecIdx] = (PIMAGE_SECTION_HEADER)((PBYTE)&pINH->OptionalHeader + dwSizeOfIOH + (SIZE_OF_SECTION * dwSecIdx));	// IMAGE_SECTION_HEADER
		}
	}
	catch(...)
	{
		ERRPRINT_GOTO(_EXIT, "When analyzing PE Header");
	}

	/* Step 2-3. PE가 EXE인 경우 이미지 재구성 후 파일로 생성 (DLL이 아니면서 GUI나 CUI인 경우 */
	// PE의 ImageBase 값과 실제 ImageBase를 비교한다. (다르다면 Relocation Table을 보고 VA들을 수정해야 한다.)
	if(pINH->OptionalHeader.ImageBase == MemAddr)
	{
		goto _MAKE_FILE;
	}

	// 파일 형태로 고치기 전에 Relocation Table을 보고 값들을 수정해야 한다. 
	UINT_PTR dwDiff = pINH->OptionalHeader.ImageBase - MemAddr;	// PE 헤더에 정의된 ImageBase와 실제 로드된 주소의 차이
	PIMAGE_DATA_DIRECTORY pRelocTable = &(pINH->OptionalHeader.DataDirectory[5]);

	if(pRelocTable->VirtualAddress > dwSizeOfChunk)
	{
		// Relocation Table이 전체 사이즈보다 뒤에 있다면 이미지가 깨진 것이다. 그래도 최대한 파일로 떨구도록 한다.
		WARNPRINT_GOTO(_MAKE_FILE, "RelocTable pointer is invalid");
	}

	if(pRelocTable->Size <= 8 || pRelocTable->VirtualAddress <= 0)
	{
		// Relocation Table이 없다면 수정할 값이 없을 뿐 PE에 이상이 있는 것은 아니다. (사이즈가 8보다 작으면 실제 유효 데이터는 없다.)
		WARNPRINT_GOTO(_MAKE_FILE, "There is no RelocTable");
	}

	PIMAGE_BASE_RELOCATION pIBR = (PIMAGE_BASE_RELOCATION)((BYTE*)pIDH + pRelocTable->VirtualAddress);	// IMAGE_BASE_RELOCATION
	DWORD dwRva = pIBR->VirtualAddress;
	DWORD dwSize = pIBR->SizeOfBlock;

	if(dwRva == 0 || dwSize == 0)	
	{
		WARNPRINT("There is invalid BaseRelocationTable");
	}
	else 
	{
		do 
		{
			WORD* pRT = (WORD *)((BYTE *)pIBR + sizeof(IMAGE_BASE_RELOCATION));
			WORD wOffset = 0;
			DWORD* pChanged = NULL;

			for(; (BYTE *)pRT < (BYTE *)pIBR + dwSize; pRT++)
			{
				if(*pRT == 0x0000) { break; }
				wOffset = *pRT & 0xFFF;
				pChanged = (DWORD *)((BYTE *)pIDH + dwRva + wOffset);
				*pChanged = *pChanged + dwDiff;
			}
			pIBR = (PIMAGE_BASE_RELOCATION)((BYTE *)pIBR + dwSize);
			dwRva = pIBR->VirtualAddress;
			dwSize = pIBR->SizeOfBlock;
		} while(dwRva != 0 && dwSize != 0);
	}
// 여기
_MAKE_FILE:
	// FileAlignment와 SectionAlignment가 같다면 할 것이 없다.
	DWORD dwSecAlign = pINH->OptionalHeader.SectionAlignment;
	DWORD dwFileAlign = pINH->OptionalHeader.FileAlignment;
	DWORD dwSizeOfFile = 0;		// 파일의 끝 위치 (dwSizeOfSec와 dwCerEndSize 중 큰 것을 택한다)
	DWORD dwSizeOfSec = 0;		// 각 섹션의 끝 위치
	DWORD dwIdx = 0;
	
	BYTE* pRAddrOfSecs = NULL;	// 각 섹션의 Raw Address를 가리킴
	BYTE* pVAddrOfSecs = NULL;	// 각 섹션의 Virtual Address를 가리킴
	DWORD dwRawSize = 0;		// 각 섹션의 Raw 사이즈
	DWORD dwVirSize = 0;		// 각 섹션의 Virtual 사이즈
	DWORD dwCopySize = 0;		// 섹션 당길 때 사이즈 (RawSize나 VirSize 중 작은 것을 택해야 한다.)
	DWORD dwOriSizeOfPadding = 0;// 섹션이 RawSize 만큼만 있을 때 뒤에 붙을 NULL 패팅 크기
	DWORD dwSizeOfPadding = 0;	// 실제 당겨진 섹션이 RawSize 보다 작은 경우 실제 각 섹션의 뒤에 붙을 NULL 패딩 크기

	if(dwSecAlign == dwFileAlign)	{  }	// SectionAlignment와 FileAlignment가 같은 경우에는 파일만 생성하면 된다.
	else if(dwSecAlign < dwFileAlign) 
	{ 
		ERRPRINT_GOTO(_EXIT, "FileAlignment is larger than SectionAlignment"); 
	}
	else	// SectionAlignment 보다 FileAlignment가 작은 경우(일반적)에는 파일상의 위치로 맞추어 주어야 한다.
	{
		// 각 파일상 섹션의 주소와 각 이미지상 섹션의 주소 구함
		for(dwIdx = 0; dwIdx < dwNumOfSecs; dwIdx++)
		{
			// 예외될 섹션 명시 (.textbss 섹션)
			if(!strncmp( (const char *)pISH[dwIdx]->Name, ".textbss", 8))
			{
				continue;
			}
			pRAddrOfSecs = (PBYTE)pIDH + pISH[dwIdx]->PointerToRawData;	// MZ주소 처음부터 각 섹션의 PointerToRawData만큼 더해야 메모리상 위치가 나옴
			pVAddrOfSecs = (PBYTE)pIDH + pISH[dwIdx]->VirtualAddress;	// MZ주소 처음부터 각 섹션의 Virtual Address만큼 더해야 메모리상 위치가 나옴
			dwRawSize = pISH[dwIdx]->SizeOfRawData;
			dwVirSize = pISH[dwIdx]->Misc.VirtualSize;
			dwCopySize = dwRawSize > dwVirSize ? dwVirSize : dwRawSize;

			// 쓸 영역이 메모리 초과하는지 체크
			if(pVAddrOfSecs + dwCopySize > (PBYTE)pIDH + dwSizeOfChunk)
				continue;

			// 섹션 당기기
			memcpy_s(pRAddrOfSecs, dwRawSize, pVAddrOfSecs, dwCopySize);

			if(dwRawSize == dwVirSize)
				continue;

			// 섹션 뒤에 붙을 NULL 패딩 크기 구하기
			dwOriSizeOfPadding = dwRawSize % dwFileAlign;
			dwSizeOfPadding = dwOriSizeOfPadding + dwRawSize - dwCopySize;

			// 당겨진 섹션 끝에 NULL 패딩 붙이기
			ZeroMemory(pRAddrOfSecs + dwCopySize, dwSizeOfPadding);		
		}
	}

	// 섹션 중 가장 영역 섹션을 알아냄
	dwSizeOfFile = pISH[0]->PointerToRawData + pISH[0]->SizeOfRawData;
	for(dwIdx = 1; dwIdx < dwNumOfSecs; dwIdx++)
	{
		dwSizeOfSec = pISH[dwIdx]->PointerToRawData + pISH[dwIdx]->SizeOfRawData;
		dwSizeOfFile = dwSizeOfFile < dwSizeOfSec ? dwSizeOfSec : dwSizeOfFile;
	}

	// 여기까지 왔다면 모듈의 이미지가 파일로 무조건 만들어졌으므로 strModuleName을 그대로 사용해도 됨
	if(dwPathLen > 0)
	{
		strFileFullPath.Format(_T("%s\\%s_0x%x"), strFileDir, strModuleName, MemAddr);
	}
	else
	{
		strFileFullPath.Format(_T("%s\\0x%x"), strFileDir, MemAddr);
	}

	hPeFile = CreateFile(strFileFullPath,
						 GENERIC_WRITE,
						 0,
						 NULL,
						 CREATE_ALWAYS,
						 FILE_ATTRIBUTE_NORMAL,
						 NULL);
						
	if(hPeFile == INVALID_HANDLE_VALUE)
	{
		ERRPRINT_GOTO(_EXIT, "CreateFile");
	}

	if(WriteFile(hPeFile, pIDH, dwSizeOfFile, &dwBytesWritten, NULL) == FALSE)
	{
		ERRPRINT_GOTO(_EXIT, "WriteFile");
	}

	if(dwBytesWritten != dwSizeOfFile)
	{ 
		ERRPRINT_GOTO(_EXIT, "Can't write pe file enough"); 
	}
	/* IAT 재구성해야 한다면 재구성 */

_EXIT:
	SAFECLOSEHANDLE16(hPeFile);
	SAFECLOSEHANDLE16(hChunkFile);
	SAFEDELETEARRAY1(pISH);

	return bRet;
}

/*	Function : SetPrivilege
	Description : 프로세스 권한 변경
*/
BOOL CImageToFile::SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	LUID luid;
	BOOL bRet=FALSE;

	if (LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
	{
		TOKEN_PRIVILEGES tp;

		tp.PrivilegeCount=1;
		tp.Privileges[0].Luid=luid;
		tp.Privileges[0].Attributes=(bEnablePrivilege) ? SE_PRIVILEGE_ENABLED: 0;
		//
		//  Enable the privilege or disable all privileges.
		//
		if(AdjustTokenPrivileges(hToken, FALSE, &tp, NULL, (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
		{
			//
			//  Check to see if you have proper access.
			//  You may get "ERROR_NOT_ALL_ASSIGNED".
			//
			bRet=(GetLastError() == ERROR_SUCCESS);
		}
	}
	return bRet;
}

/*	Function : SetDebugPrivilege
	Description : 디버그 권한 얻기
*/
void CImageToFile::SetDebugPrivilege()
{
	HANDLE hProcess = GetCurrentProcess();
	HANDLE hToken;

	if(OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		SetPrivilege(hToken, SE_DEBUG_NAME, TRUE);
		CloseHandle(hToken);
	}
}

/*	Function : GetNumOfModules
	Description : 프로세스 안에 모듈의 개수가 몇 개 있는지 알아낸다. 
	EnumProcessModules API의 마지막 인자는 모듈 배열의 사이즈를 나타내므로 나누기 하나의 모듈 핸들을 하면 몇 개의 모듈을 사용할지 알 수 있다.
*/
DWORD CImageToFile::GetNumOfModules()
{
	HANDLE	hProc = NULL;
	DWORD	dwRet = 0;
	DWORD	dwNumOfMod = 0;

	hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
						FALSE, 
						dwPid);
	if(hProc == NULL)
	{
		ERRPRINT_GOTO(_EXIT, "Wrong PID");
	}

	EnumProcessModules(hProc, NULL, 0, &dwNumOfMod);

	if(dwNumOfMod <= 0)
	{
		ERRPRINT_GOTO(_EXIT, "EnumProcessModules");
	}

	dwRet = this->dwNumOfMod = dwNumOfMod / sizeof(HMODULE);

_EXIT:
	SAFECLOSEHANDLE32(hProc);
	return dwRet;
}

/*	Function : GetAllModMems
	Description : 프로세스 내부에 있는 모든 모듈의 주소를 알아낸다. 
*/
BOOL CImageToFile::GetAllModMems()
{
	BOOL	bRet = FALSE;
	MODULEENTRY32	stME32 = {0};
	DWORD	idxMod = 0;
	HANDLE	hMod = NULL;

	// lstAllMod 리스트 비우기
	if(!lstAllMod.empty())
	{
		lstAllMod.clear();
	}

	hMod = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPid);
	if(hMod == INVALID_HANDLE_VALUE)
	{
		ERRPRINT_GOTO(_EXIT, "CreateToolhelp32Snapshot");
	}

	stME32.dwSize = sizeof(MODULEENTRY32);
	if(!Module32First(hMod, &stME32))
	{
		ERRPRINT_GOTO(_EXIT, "Module32First");
	}

	do 
	{
		//parBaseAddr[idxMod++] = stME32.modBaseAddr;
		lstAllMod.push_back(SMem((UINT_PTR)stME32.modBaseAddr, stME32.modBaseSize));
		if(idxMod++ >= dwNumOfMod)
		{
			break;
		}
	} while (Module32Next(hMod, &stME32));

	bRet = TRUE;

_EXIT:
	SAFECLOSEHANDLE16(hMod);
	return bRet;
}

/*	Function : GetAllThdMems
	Description : 프로세스 내부에 있는 모든 스레드의 시작 주소를 알아낸다.
	RSYSTEM_THREAD_INFORMATION에 있는 StartAddress는 다른 값이다. 그래서 NtQueryInformationThread를 사용하여 스레드 시작 주소를 알아내야 한다.
	Windows 8 이상에서는 NtQueryInformationThread 대신에 GetThreadInformation를 사용해야 하는 듯 하다.
	(ref : http://www.jiniya.net/wp/archives/7676)
*/
BOOL CImageToFile::GetAllThdMems()
{
	BOOL	bRet = FALSE;
	THREADENTRY32	stTE32 = {0};
	DWORD	idxThd = 0;
	HANDLE	hSnapThd = NULL;
	MEMORY_BASIC_INFORMATION stMBI = {0};
	SYSTEM_INFO		stSI = {0};
	NTQUERYSYSTEMINFORMATION	pNtQuerySystemInformation = NULL;
	NTQUERYINFORMATIONTHREAD	pNtQueryInformationThread = NULL;
	HANDLE hThd = NULL;

	PRSYSTEM_PROCESS_INFORMATION pSPI = NULL;
	PRSYSTEM_THREAD_INFORMATION pThd = NULL;
	const int NTQSI_MAX_TRY = 20;  
	const ULONG NTQSI_BUFFER_MARGIN = 4096;  
	const ULONG NTQSI_BUFFER_INIT_SIZE = 200000;  

	ULONG buffer_size = NTQSI_BUFFER_INIT_SIZE;
	PUCHAR buffer = new UCHAR[buffer_size];  
	ULONG req_size = 0;
	NTSTATUS ntStatus = 0;  

	HMODULE	hNtdll = GetModuleHandle(_T("ntdll.dll"));
	if(hNtdll == NULL)
	{
		ERRPRINT_GOTO(_EXIT, "GetModuleHandle");
	}
	pNtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION) GetProcAddress(hNtdll, "NtQuerySystemInformation");
	if(pNtQuerySystemInformation == NULL)
	{
		ERRPRINT_GOTO(_EXIT, "GetProcAddress");
	}

	pNtQueryInformationThread = (NTQUERYINFORMATIONTHREAD) GetProcAddress(hNtdll, "NtQueryInformationThread");
	if(pNtQueryInformationThread == NULL)
	{
		ERRPRINT_GOTO(_EXIT, "GetProcAddress");
	}

	// lstThdMem 리스트 비우기
	if(!lstThdMem.empty())
	{
		lstThdMem.clear();
	}

	for(int i = 0; i < NTQSI_MAX_TRY; i++)
	{  
		ntStatus = pNtQuerySystemInformation(SystemProcessInformation, buffer, buffer_size, &req_size);  
		if(NT_SUCCESS(ntStatus))
		{
			break;
		}
		
		// NtQuerySystemInformation 실패 시 버퍼를 변경하여 다시 시도
		if(buffer)
		{
			delete[] buffer;
			buffer = NULL;
		}

		if(ntStatus == STATUS_INFO_LENGTH_MISMATCH)  
		{  
			buffer_size = req_size + NTQSI_BUFFER_MARGIN;  
			buffer = new UCHAR[buffer_size];
		}  
		else  
		{  
			ERRPRINT_GOTO(_EXIT, "pNtQuerySystemInformation");
		}
	}  

	pSPI = (PRSYSTEM_PROCESS_INFORMATION)buffer;

	// 전체 프로세스에 대한 리스트(?) 중에서 타겟이 되는 프로세스 선택
	while(pSPI->NextEntryOffset != 0)
	{
		if(pSPI->UniqueProcessId == (HANDLE)dwPid)
			break;
		pSPI = (PRSYSTEM_PROCESS_INFORMATION) XGetPtr(pSPI, pSPI->NextEntryOffset);
	}

	ULONGLONG ullMinCreateTime = MAXULONGLONG;
	// 타겟 프로세스에서 스레드들의 시작주소를 다시 타겟 프로세스에 쿼리하여 주소 대역을 알아냄
	pThd = (PRSYSTEM_THREAD_INFORMATION) XGetPtr(pSPI, sizeof(RSYSTEM_PROCESS_INFORMATION));
	for(ULONG i = 0; i < pSPI->NumberOfThreads; i++)
	{
		hThd = OpenThread(THREAD_QUERY_INFORMATION, FALSE, (DWORD)pThd->ClientId.UniqueThread);
		DWORD Err = GetLastError();
		if(hThd == NULL)
		{
			WARNPRINT_GOTO(_CONTINUE, "OpenThread");
		}
		
		PVOID Win32StartAddr = NULL;	// NtQueryInformationThread로 구한 스레드 스타트 주소
		UINT_PTR upStartAddr = 0;		// 실제로 사용할 스레드 스타트 주소
		NTSTATUS ntStatus;  
		// 스레드 시작 주소 알아내기
		ntStatus = pNtQueryInformationThread(hThd,
											ThreadQuerySetWin32StartAddress,
											&Win32StartAddr,
											sizeof(Win32StartAddr),
											NULL);

		if(!NT_SUCCESS(ntStatus))
		{
			ERRPRINT_GOTO(_EXIT, "NtQueryInformationThread");
		}

		// 스레드가 다른 프로세스로부터 공유 메모리로 매핑되어 RtlCreateUserThread API로 생성된 경우 Win32StartAddr가 0이 됨
		upStartAddr = (UINT_PTR)Win32StartAddr == 0 ? (UINT_PTR)pThd->StartAddress : (UINT_PTR)Win32StartAddr;

		/* 테스트 결과 구하는 메모리 영역이 PE의 처음이 아닐 가능성이 큼. 따라서 아래 주석 처리
		// 스레드 시작 주소를 담고 있는 메모리 영역 주소와 사이즈 알기
		if(VirtualQueryEx(hImage, (LPCVOID)BaseAddr, &stMBI, sizeof(MEMORY_BASIC_INFORMATION)) != sizeof(MEMORY_BASIC_INFORMATION) ||
						stMBI.RegionSize <= 0 || stMBI.State != MEM_COMMIT)
		{
			ERRPRINT_GOTO(_CONTINUE, _T("VirtualQueryEx(0x%x)"), BaseAddr);
		}
		*/

		// upStartAddr 주소가 허용 범위 밖에 있는지 검사
		if(upStartAddr < upMinMem || upMaxMem < upStartAddr)
		{
			WARNPRINT_GOTO(_CONTINUE, "Thread StartAddress limit");
		}

		// 메인 스레드 탐색을 위한 부분 (스레드 생성 시간이 제일 작은 값이 메인 스레드)
		if (pThd->CreateTime.QuadPart && (ULONGLONG)pThd->CreateTime.QuadPart < ullMinCreateTime) 
		{
			ullMinCreateTime = pThd->CreateTime.QuadPart;
			stMainThdMem.BaseAddr = upStartAddr;
		}

		lstThdMem.push_back(SMem((UINT_PTR)upStartAddr, 0));
_CONTINUE:
		pThd = (PRSYSTEM_THREAD_INFORMATION) XGetPtr(pThd, sizeof(RSYSTEM_THREAD_INFORMATION));
	}

/*
	hSnapThd = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwPid);
	if(hSnapThd == INVALID_HANDLE_VALUE)
	{
		ERRPRINT_GOTO(_EXIT, _T("Can't get handle of threads (Error Code : %x)"), GetLastError());
	}

	stTE32.dwSize = sizeof(THREADENTRY32);
	if(!Thread32First(hSnapThd, &stTE32))
	{
		ERRPRINT_GOTO(_EXIT, _T("Thread32First (Error Code : %x)"), GetLastError());
	}

	HANDLE hThd = NULL;
	do 
	{
		// 다른 프로세스의 스레드 열기 힘든 듯??
		hThd = OpenThread(THREAD_QUERY_INFORMATION, FALSE, stTE32.th32ThreadID);
		DWORD Err = GetLastError();
		if(hThd == NULL)
		{
			ERRPRINT_GOTO(_CONTINUE, _T("OpenThread (Error Code : %x)"), GetLastError());
		}

		PVOID BaseAddr;  
		NTSTATUS ntStatus;  
		// 스레드 시작 주소 알아내기
		ntStatus = pNtQueryInformationThread(hThd,  
											ThreadQuerySetWin32StartAddress,
											&BaseAddr,
											sizeof(BaseAddr),
											NULL);

		if(!NT_SUCCESS(ntStatus))
		{
			ERRPRINT_GOTO(_EXIT, _T("pNtQueryInformationThread (Error Code : %x)"), GetLastError());
		}
		
		// 스레드 시작 주소를 담고 있는 메모리 영역 주소와 사이즈 알기
		if(VirtualQueryEx(hImage, (LPCVOID)BaseAddr, &stMBI, sizeof(MEMORY_BASIC_INFORMATION)) != sizeof(MEMORY_BASIC_INFORMATION) ||
			stMBI.RegionSize <= 0 || stMBI.State != MEM_COMMIT)
		{
			ERRPRINT_GOTO(_CONTINUE, _T("VirtualQueryEx(0x%x)"), BaseAddr);
		}

		lstThdMem.push_back(SMem(stMBI.BaseAddress, stMBI.RegionSize));
		
_CONTINUE:
		;
		SAFECLOSEHANDLE32(hThd);
	} while (Thread32Next(hSnapThd, &stTE32));
*/
	bRet = TRUE;

_EXIT:
	SAFEDELETEARRAY1(buffer);
	SAFECLOSEHANDLE32(hThd);

//	SAFECLOSEHANDLE16(hSnapThd);
	return bRet;
}

CString CImageToFile::GetTempFilePath(LPCTSTR szPrefix)
{
	CString strPath;
	if(GetTempPath(_MAX_PATH,strPath.GetBuffer(_MAX_PATH+1)) != 0) 
	{
		strPath.ReleaseBuffer();
		CString strTempFile;
		if(GetTempFileName(strPath, szPrefix, 0, strTempFile.GetBuffer(_MAX_PATH+1) ) != 0) 
		{
			strTempFile.ReleaseBuffer();
			return strTempFile;
		}
	}
	return CString();
}