#include "CImageToFile.h"

/*	Function : Run
	Description : CImageToFile Ŭ�������� ���� �Լ�
*/
void CImageToFile::Run()
{
	BOOL bRet = FALSE;

	if(bOpAllProc)
	{
		// ��� ���μ��� �˻� ��
		bRet = ScanAllProcesses();
	}
	else
	{
		// Ư�� ���μ����� �˻� ��
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
	// ��� ���� ���ϱ�
	if(cITF->GetNumOfModules() == 0)
	{
		ERRPRINT_GOTO(_EXIT, _T("GetNumOfModules error (Error Code : %x)"), GetLastError());
	}
	// ��� ����� �ּ� ���ϱ�
	if(cITF->GetBaseAddressOfModules() == FALSE)
	{
		ERRPRINT_GOTO(_EXIT, _T("GetBaseAddressOfModules error (Error Code : %x)"), GetLastError());
	}
	*/

_EXIT:
	SAFECLOSEHANDLE32(hImage);
}

/*	Function : ScanAllProcesses
	Description : ��� ���μ����� ���ؼ� ��ĵ�Ѵ�.
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
	Description : �� ���μ��� ���� Commit�� ��� �޸� �ּҸ� �˾Ƴ���.
*/
BOOL CImageToFile::GetAllMemories()
{
	BOOL	bRet = FALSE;
	MEMORY_BASIC_INFORMATION MBI = {0};
	UINT_PTR	upMemAddr = upMinMem;
	DWORD	dwBaseSize = 0;

	// lstAllMem ����Ʈ ����
	if(!lstAllMem.empty())
	{
		lstAllMem.clear();
	}

	do
	{
		// ���⿡�� VirtualQueryEx�� �ϴ� ������ upMemAddr�� BaseAddress �ּҰ� �ƴ� �� �ֱ� ������
		if(VirtualQueryEx(hImage, (LPCVOID)upMemAddr, &MBI, sizeof(MEMORY_BASIC_INFORMATION)) != sizeof(MEMORY_BASIC_INFORMATION) ||
			MBI.RegionSize <= 0 || MBI.State != MEM_COMMIT)
		{
			dwBaseSize = MBI.RegionSize <= 0 ? 0x1000 : MBI.RegionSize;
			WARNPRINT_GOTO(_CONTINUE, "VirtualQueryEx");
		}
		
		// BaseAddress���� �̾��� ����� ���� (�ּҰ� ��ȿ���� ������ 0�� ����)
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
	Description : lstAddr ����Ʈ�� lstMemRegion ����Ʈ�� ���Ͽ� lstAddr ����Ʈ���� �ִ� ��Ҹ� lstResult�� �����Ѵ�. �� ���ذ��� SMem.BaseAddr�̴�.
				(std::set_difference �ڵ� ����)

	ex) lstAddr�� BaseAddr�� 100, 200, 300, 400�� ���� ��, lstMemRegion�� BaseAddr�� 60-70, 90-150, 160-170, 300-400, 450-500�̶�� 200 �ּҸ� lstResult�� ����ȴ�.
		
	100	������������X��������������> 60-70
				  ��	
	200	������������������ ��O����> 90-150
				��
	300	�������������� ������X����> 160-170
			  �� ��
	400	��������������	������X����> 300-400 (300�� 200���� ũ�� ������ 200�� lstMemRegion ����Ʈ���� 200 �ּҰ� ����. ����, 200 �ּҴ� lstResult�� ����ȴ�.)
			 ������������O����>	300-400
						450-500
*/
list<SMem>& CImageToFile::list_NotIncludedInAllModules (list<SMem>& lstAddr, list<SMem>& lstMemRegion, list<SMem>& lstResult)
{
	list<SMem>::iterator iAddr;
	list<SMem>::iterator iMemRegion;

	// ���� �� ����Ʈ ����
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

	// lstAddr�� ���� ���� �ִٸ� ��� lstResult�� ����
	while(iAddr != lstAddr.end())
	{
		lstResult.push_back(SMem(GetImageBase((*iAddr).BaseAddr), (*iAddr).Size));
		iAddr++;
	}

	return lstResult;
}

/*	Function : list_IncludedInAllMemories
	Description : lstAddr ����Ʈ�� �ִ� �ּҰ� lstMemRegion �ּ� �뿪�� �ִ��� �˻��ϰ� �ִٸ� �� �ּ� �뿪�� lstResult�� �����Ѵ�
	lstAddr�� �ּҴ� BaseAddress�� �ƴϱ� ������ �ش� �ּҰ� ��� �ּ� ������ ���ϴ��� ���� �� ����Ѵ�
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
			// �˻��� �޸𸮰� ��� Ŀ�Ե� ��� �޸� ������ ���Ե��� �ʴ� ��� (�߻��� Ȯ�� ����)
			WARNPRINT("MemAddress is not in all memories");
			iAddr++;
		}
	}

	return lstResult;
}

/*	Function : ScanOneProcess
	Description : �ϳ��� ���μ����� ���ؼ� ��ĵ
*/
BOOL CImageToFile::ScanOneProcess()
{
	BOOL	bRet = FALSE;
	DWORD	dwMemSize = 0;
	DWORD	dwBytesRead = 0;
	DWORD	dwMzOffset = 0;			// �޸𸮿��� MZ �ñ״�ó������ ������
	BYTE*	pSusMem = NULL;			// MZ �ñ״�ó�� ���� �޸� ������ ���� ������
	BYTE*	pChunkMem = NULL;		// PE�� ���� �޸� ������ ���� ������
	list<SMem> lstSusThdMem;		// ��� ��� ����Ʈ�� ���Ե��� �ʴ� ������ ������ �ּҸ� ���� ����Ʈ
	list<SMem> lstSusThdMemBand;	// lstSusThdMem ����Ʈ �ּҸ� ��� �޸𸮿��� �˻��Ͽ� �ش� �޸� �뿪�� ������ ����Ʈ
	TCHAR	szImagePath[MAX_PATH] = {0};
	
	// ��� ���μ��� ��ĵ�� ��쿡�� 
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

	// ���μ��� ���� ��� ��� ���� �˾ƿ���
	if(!GetNumOfModules())
	{
		ERRPRINT_GOTO(_EXIT, "GetNumOfModules");
	}
	// ���μ��� ���� ��� ��� ����Ʈ ���
	if(!GetAllModMems())
	{
		ERRPRINT_GOTO(_EXIT, "GetAllModMems");
	}

	if(bOpSusMod)
	{
		/* Suspicious �˰��� #1 - �ǽ� ������ ��� (���ǵ� ��� �޸� �������� �������� ���� ������ ���� �ּ� Ž��) */
		// ���μ��� ���� ��� ������ ���� �ּ� ����Ʈ ���
		if(!GetAllThdMems())
		{
			ERRPRINT_GOTO(ALGORITHM2, "GetAllThdMems");
		}
		// ��� ������ ���� �ּ� ����Ʈ���� �� ���� �ּҰ� ���� �ּ� �뿪�� ���ԵǴ��� �˻� (���Ե��� �ʴ� �ּҴ� lstSusThdMem���� ����)
		list_NotIncludedInAllModules(lstThdMem, lstAllMod, lstSusThdMem);
		if(lstSusThdMem.empty())
		{
			ERRPRINT_GOTO(ALGORITHM2, "lstSusThdMem empty");
		}

		_tprintf(_T("Algorithm #1 : There is injected code or pe\n"));
		// ���� �ּ� �뿪�� ���Ե��� �ʴ� ������ ���� �ּҵ��� �ּ� �뿪(ó���� ��)�� �˾Ƴ�
		if(GetMemBand(lstSusThdMem, lstSusThdMemBand))
		{
			DBGPRINT("Suspicious Algorithm #1 Success!")
		}
		// ���� �ּ� �뿪�� ���Ե��� �ʴ� ������ ���� �ּ� ����Ʈ(lstSusThdMem)�� ��� �޸� �뿪���� ã�Ƽ� ���� �޸� �뿪(ImageBase ~ ImageBase + Size)�� ã��
		//list_IncludedInAllMemories(lstSusThdMem, lstAllMem, lstSusThdMemBand);
ALGORITHM2:
		if(CheckThreadBaseAddress(lstSusThdMemBand))
		{
			_tprintf(_T("Algorithm #2 : There is injected code or pe\n"));
			DBGPRINT("Suspicious Algorithm #2 Success!")
		}
		// �Ʒ� ���� �����带 �˻��ϴ� �˰����� ��ü �����带 �˻��ϴ� ������ �����Ѵ�.
		// ���� ������ �ּҸ� ������� ImageBase�� �˾Ƴ��� �װ��� ���� ������ �ִ����� PE���� Ȯ��. �� ������ �´ٸ� lstSusThdMemBand�� ����
		//if(CheckMainModule(lstSusThdMemBand))
		//{
		//	DBGPRINT("Suspicious Algorithm #2 Success!")
		//}
		/* �θ� ���μ����� ���� Owner PID�� �ٸ��� �ǽ� - �˰��� #1, #2�� Ŀ�� ������ �� */
ALGORITHM3:
		;
		/* Suspicious �˰��� #3 - �ǽ� �޸� ��� (��� �޸� �������� ���ǵ� ��� �޸� ������ �����ϰ� ���� ������ �ִ� �ּ� Ž��) */
	}
	else
	{
		// ���μ��� ���� ��� �޸� �ּ� �뿪 ���
		if(!GetAllMemories())
		{
			ERRPRINT_GOTO(_EXIT, "GetAllMemories");
		}
		// �޸��� ��� �޸𸮸� üũ�ϵ��� lstSusThdMemBand�� ��� �޸� �ּҸ� ��� �ִ� lstAllMem�� ����
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
	Description : ����Ʈ�� ���� �޸� �ּҵ鿡 PE�� �ִ��� Ȯ���ϰ� �´ٸ� ���Ϸ� �����Ѵ�.
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

		// MZ, PE �ñ״�ó�� �����ϴ� ��� �� �޸𸮺��� ����� ��ü �޸� ������ ũ��(SizeOfChunk)�� ���Ѵ�. 
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
	Description : Ư�� �޸� ��ġ�� Input���� �ش� �޸� �뿪(ó�� ��ġ�� �� ��ġ)�� �˾Ƴ�
	��������� �ǽ� ������ ���� �ּ��� �ּ� �뿪(���� �ּҿ� �� �ּ�) ����Ʈ�� ����
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
		// �ǽ� ������ ���� �ּ��� �޸� ���� �ּ� ���
		upBaseAddr = GetImageBase(iSomeMem->BaseAddr);
		// �ǽ� ������ �޸� ������ ���
		dwBandSize = GetSizeOfChunk(upBaseAddr);
		
		if(upBaseAddr < upMinMem || upMaxMem < upBaseAddr || dwBandSize <= 0)
		{
			WARNPRINT("One band of suspicious thread memories can't be gotten");
		}
		else
		{
			lstMemBand.push_back(SMem(upBaseAddr, dwBandSize));
			// �ǽ� ������ �뿪�� �ϳ��� �˾Ƴ��� TRUE ����
			bRet = TRUE;
		}
		iSomeMem++;
	}
	
_EXIT:
	return bRet;
}

/*	Function : CImageToFile
	Description : ������. ����ڰ� �Է��� �ɼ� üũ
*/
CImageToFile::CImageToFile(int argc, TCHAR* argv[]) : stMainThdMem(0, 0)
{
	// ���� �ʱ�ȭ
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

	// �ɼ� �Ľ�
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

	// �α� ������ ���� ����
	strTemp = GetTempFilePath(_T("ITF"));
	logFile.open(strTemp, ios::out | ios::app);

	// ����� ���� ���
	SetDebugPrivilege();

_EXIT:
;
}

void CImageToFile::Help(LPCTSTR szPrgPath)
{
	CString strPrgPath = szPrgPath;
	// ���� �̸� �˾Ƴ���
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
	Description : pMem���� PE ��� �κ��� �ִ��� ������ �˻� �� �ִٸ� MZ �κ��� �������� �����ϰ�
	���ٸ� -1 ����
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

	// MZ�� PE ���� �˻�
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

	// Image Dos Header ���ϱ�
	const PIMAGE_DOS_HEADER const pIDH = (const PIMAGE_DOS_HEADER const)(pMem + dwIdx);
	if((const PBYTE)pIDH + sizeof(IMAGE_DOS_HEADER) >= pMem + dwMemSize)
	{
		DBGPRINT_GOTO(_EXIT, "Corrupted Pe");
	}

	// Image Nt Header ���ϱ�
	const PIMAGE_NT_HEADERS const pINH = (const PIMAGE_NT_HEADERS const)(pMem + pIDH->e_lfanew);
	if((const PBYTE)((const PBYTE const)pINH) + sizeof(IMAGE_NT_HEADERS) >= pMem + dwMemSize)
	{
		DBGPRINT_GOTO(_EXIT, "Corrupted Pe");
	}

#ifdef _WIN64
	// 64bit ���������� 32bit ����� ������ ����
	if(pINH->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		DBGPRINT_GOTO(_EXIT, "32bit type pe");
	}
#else
	// 32bit ���������� 64bit ����� ������ ����
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
	Description : �־��� �޸� �ּҺ��� �����Ͽ� ����� ��ü �޸� ������ ũ�⸦ ����
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
	Description : ���ڷ� ���� MemAddr�� �̾��� �ֻ��� BaseAddress�� ���Ѵ�
*/
UINT_PTR CImageToFile::GetImageBase(const UINT_PTR& _MemAddr)
{
	DWORD	dwSizeOfChunk = 0;
	DWORD	dwSizeOfMBI = 0;
	UINT_PTR	MemAddr = _MemAddr;
//	UINT_PTR	upCurBase = 0;		// ���� �ּ�(pMemAddr)�� ���̽� �ּ�
//	UINT_PTR	upUpperMem = 0;		// ���� �ּҿ� ����� ����(���ڷδ� ���� ��) �ּ�
//	UINT_PTR	upUpperBase = 0;	// ���� �ּҿ� ����� ����(���ڷδ� ���� ��) ���̽� �ּ�
	UINT_PTR	upAllcationBase = 0;
	MEMORY_BASIC_INFORMATION MBI = {0};

	// ���ڷ� ���� MemAddr�� ���� BaseAddress ���ϱ�
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

	/* 2015.05.17 ���ſ��� ���� BaseAddress�� -1�� �Ͽ� ��� �������Ͽ�����, �׳� ������ AllocationBase�� ���ϴ� ������ ��ü��
	// ���� �޸� �ּҴ� ���� BaseAddress - 1�� �� �ּҸ� ����
	upUpperMem = upCurBase - 1;
	// ������ �̾��� �޸� �ּҸ� ����
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
	Description : �Ϲ����� PE�� ����� ���� ������ ����. ���� ���� ������ ���� �ּҰ� �ִ� �޸� ������ ImageBase�� ���ѿ� 
	���� ������ �ִٸ� �����ǵ� �����̶�� �Ǵ��� �� �ִ�.
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

	// ���� �������� ���� �ּҰ� ���Ե� �޸� ������ BaseAddress�� ����
	upImageBase = GetImageBase(stMainThdMem.BaseAddr);

	// BaseAddress�� �޸� ���� Ȯ��
	if(VirtualQueryEx(hImage, (LPCVOID)upImageBase, &MBI, sizeof(MEMORY_BASIC_INFORMATION)) != sizeof(MEMORY_BASIC_INFORMATION) ||
		MBI.RegionSize <= 0 || MBI.State != MEM_COMMIT)
	{
		DBGPRINT_GOTO(_EXIT, "VirtualQueryEx");
	}

	// �ش� ImageBase ������ ���� ���� ������ �ִ��� �˻� (������ ChkPE�� ���� �˻�Ǿ�� �ϳ� ���ɻ� ������ ���� üũ)
	if(MBI.Protect != PAGE_EXECUTE && MBI.Protect != PAGE_EXECUTE_READ && MBI.Protect != PAGE_EXECUTE_READWRITE)
	{
		DBGPRINT_GOTO(_EXIT, "Maybe normal PE");
	}

	pSusMem = new BYTE[MBI.RegionSize];
	if(ReadProcessMemory(hImage, (LPCVOID)upImageBase, pSusMem, MBI.RegionSize, &dwBytesRead) == FALSE)
	{
		DBGPRINT_GOTO(_EXIT, "ReadProcessMemory");
	}

	// �ش� BaseAddress ������ PE ������ �ִ��� Ȯ��
	dwMzOffset = ChkPE((const BYTE* const)pSusMem, MBI.RegionSize);
	if(dwMzOffset < 0)
	{
		// PE�� �� ã�� ���
		DBGPRINT_GOTO(_EXIT, "Maybe not PE");
	}
	else if(dwMzOffset > 0)
	{
		// PE�� ã������ ImageBase���� ������ ������ ã�� ���
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
	Description : �Ϲ����� PE�� Image Ÿ���� ������. ������ VirtualAlloc�� VirtualAllocEx�� ���� �����Ǵ� ���� Private Ÿ���� ������.
	Ȥ�� ���ε� �޸𸮵� Mapped Ÿ���� ������. ����, PE�̸鼭 Image Ÿ���� ������ �ʾҴٸ� �������� �ǽ��� �� �ִ�.
	�ڵ��̸鼭 Image Ÿ���� ������ �ʴ� ���� ��Ŀ���� ���� ����� �� ����. ���� ���, �ڽ� �޸� ������ ���� �Ҵ��ϰ�
	�ű⿡ �ڵ带 ���� ���ο� �����带 �����Ͽ� �����Ų�ٸ� �� ��쿡 �ش��Ѵ�. ���� PE�� ��츸 �ǽ��Ѵ�. (�Ϲ������� ���� ��Ŀ��
	�ڽ� �޸� ������ ���� �Ҵ��ؼ� PE�� ���� ���ο� ������� �����Ű�� ���� ���� ���ٰ� �Ǵ���)
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
		// ������ ���� �ּ��� �޸� Ÿ�� Ȯ��
		if(VirtualQueryEx(hImage, (LPCVOID)iThdMem->BaseAddr, &MBI, sizeof(MEMORY_BASIC_INFORMATION)) != sizeof(MEMORY_BASIC_INFORMATION) ||
			MBI.RegionSize <= 0 || MBI.State != MEM_COMMIT)
		{
			DBGPRINT_GOTO(_CONTINUE, "VirtualQueryEx"); 
		}

		// �ش� ImageBase ������ Image Ÿ������ �˻�. ���� �̹����� Image Ÿ��
		if(MBI.Type == MEM_IMAGE)
		{
			DBGPRINT_GOTO(_CONTINUE, "Maybe normal");
		}

		// �������� ���� �ּҰ� ���Ե� �޸� ������ BaseAddress�� ����
		upImageBase = GetImageBase(iThdMem->BaseAddr);

		// ������ ���̽� �ּ� �޸� ������ ���ϱ�
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

		// �ش� BaseAddress ������ PE ������ �ִ��� Ȯ��
		dwMzOffset = ChkPE((const BYTE* const)pSusMem, MBI.RegionSize);
		if(dwMzOffset < 0)
		{
			// PE�� �� ã�� ���
			DBGPRINT_GOTO(_CONTINUE, "Maybe not PE");
		}
		else if(dwMzOffset > 0)
		{
			// PE�� ã������ ImageBase���� ������ ������ ã�� ���
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
	Description : PE ������ ���ڷ� �޾� ���ҽ� ������ ���� ������ �����Ͽ� ���� �̸��� �˾Ƴ���.
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
	Description : �޸𸮿��� ���� ������ŭ �����ͼ� �ϴ� Chunk ������ ������.
	�׸��� Chunk ������ �������·� �������Ͽ� ���Ϸ� ������. 
	ó���� ������ Chunk ������ �̹��� ������ ������� ���� �޸� ������ ���̰�,
	�� ��°�� ���� ������ ������� �������·� ������ �����̴�. �������·� ���������� �����ϸ� ������ �ʴ´�.
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

	strFolderName.Format(_T("%s_%d"), strProcess, dwPid);				// ���μ����� ���� �̸� (���μ��� �̸�_PID)
	strModuleDir.Format(_T("%s\\%s"), strFolderName, _T("Images"));		// Images �������� �޸𸮿� �ִ� PE �״���� �����Ͱ� �����. ���� �̸��� Chunks�̾����� �ǹ� ������ ���� Images�� ����
	strFileDir.Format(_T("%s\\%s"), strFolderName, _T("Files"));		// �޸𸮿� �ִ� PE���� ���� ���·� �����Ǿ� ����� ����

	/* Step 1. �� ���μ��� ���� ������ �����ϰ� Image�� �� Images ������ File�� �� Files ���� ���� */
	if(!CreateDirectory(strFolderName, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
	{	// ���丮�� �� ����� ��� (�̹� �����Ѵٸ� �׳� ����)
		ERRPRINT_GOTO(_EXIT, "CreateDirectory");
	}
	if(!CreateDirectory(strModuleDir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
	{	// ���丮�� �� ����� ��� (�̹� �����Ѵٸ� �׳� ����)
		ERRPRINT_GOTO(_EXIT, "CreateDirectory");
	}
	if(!CreateDirectory(strFileDir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
	{	// ���丮�� �� ����� ��� (�̹� �����Ѵٸ� �׳� ����)
		ERRPRINT_GOTO(_EXIT, "CreateDirectory");
	}

	/* Step 2. �ش� �޸� ������ �о Chunks�� Files ���� */
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

	/* Step 2-1. Chunks ���� */
	if(WriteFile(hChunkFile, pImageMem, dwSizeOfChunk, &dwBytesWritten, NULL) == FALSE)
	{
		ERRPRINT_GOTO(_EXIT, "WriteFile"); 
	}

	if(dwBytesWritten != dwSizeOfChunk)	
	{ 
		ERRPRINT_GOTO(_EXIT, "Can't write chunk file enough"); 
	}

	/* Step 2-2. PE ��� �м� */
	PIMAGE_DOS_HEADER pIDH = NULL;
	PIMAGE_NT_HEADERS pINH = NULL;
	DWORD dwNumOfSecs = 0;
	DWORD dwSizeOfIOH = 0;

	try {
		pIDH = (PIMAGE_DOS_HEADER)(pImageMem + dwMzOffset);			// IMAGE_DOS_HEADER
		pINH = (PIMAGE_NT_HEADERS)((PBYTE)pIDH + pIDH->e_lfanew);	// IMAGE_NT_HEADER
		dwNumOfSecs = pINH->FileHeader.NumberOfSections;			// NumberOfSections
		dwSizeOfIOH = pINH->FileHeader.SizeOfOptionalHeader;		// SizeOfOptionalHeader
		pISH = new PIMAGE_SECTION_HEADER[dwNumOfSecs];				// IMAGE_SECTION_HEADER �޸� �Ҵ�
		for(DWORD dwSecIdx = 0; dwSecIdx < dwNumOfSecs; dwSecIdx++)
		{
			pISH[dwSecIdx] = (PIMAGE_SECTION_HEADER)((PBYTE)&pINH->OptionalHeader + dwSizeOfIOH + (SIZE_OF_SECTION * dwSecIdx));	// IMAGE_SECTION_HEADER
		}
	}
	catch(...)
	{
		ERRPRINT_GOTO(_EXIT, "When analyzing PE Header");
	}

	/* Step 2-3. PE�� EXE�� ��� �̹��� �籸�� �� ���Ϸ� ���� (DLL�� �ƴϸ鼭 GUI�� CUI�� ��� */
	// PE�� ImageBase ���� ���� ImageBase�� ���Ѵ�. (�ٸ��ٸ� Relocation Table�� ���� VA���� �����ؾ� �Ѵ�.)
	if(pINH->OptionalHeader.ImageBase == MemAddr)
	{
		goto _MAKE_FILE;
	}

	// ���� ���·� ��ġ�� ���� Relocation Table�� ���� ������ �����ؾ� �Ѵ�. 
	UINT_PTR dwDiff = pINH->OptionalHeader.ImageBase - MemAddr;	// PE ����� ���ǵ� ImageBase�� ���� �ε�� �ּ��� ����
	PIMAGE_DATA_DIRECTORY pRelocTable = &(pINH->OptionalHeader.DataDirectory[5]);

	if(pRelocTable->VirtualAddress > dwSizeOfChunk)
	{
		// Relocation Table�� ��ü ������� �ڿ� �ִٸ� �̹����� ���� ���̴�. �׷��� �ִ��� ���Ϸ� �������� �Ѵ�.
		WARNPRINT_GOTO(_MAKE_FILE, "RelocTable pointer is invalid");
	}

	if(pRelocTable->Size <= 8 || pRelocTable->VirtualAddress <= 0)
	{
		// Relocation Table�� ���ٸ� ������ ���� ���� �� PE�� �̻��� �ִ� ���� �ƴϴ�. (����� 8���� ������ ���� ��ȿ �����ʹ� ����.)
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
// ����
_MAKE_FILE:
	// FileAlignment�� SectionAlignment�� ���ٸ� �� ���� ����.
	DWORD dwSecAlign = pINH->OptionalHeader.SectionAlignment;
	DWORD dwFileAlign = pINH->OptionalHeader.FileAlignment;
	DWORD dwSizeOfFile = 0;		// ������ �� ��ġ (dwSizeOfSec�� dwCerEndSize �� ū ���� ���Ѵ�)
	DWORD dwSizeOfSec = 0;		// �� ������ �� ��ġ
	DWORD dwIdx = 0;
	
	BYTE* pRAddrOfSecs = NULL;	// �� ������ Raw Address�� ����Ŵ
	BYTE* pVAddrOfSecs = NULL;	// �� ������ Virtual Address�� ����Ŵ
	DWORD dwRawSize = 0;		// �� ������ Raw ������
	DWORD dwVirSize = 0;		// �� ������ Virtual ������
	DWORD dwCopySize = 0;		// ���� ��� �� ������ (RawSize�� VirSize �� ���� ���� ���ؾ� �Ѵ�.)
	DWORD dwOriSizeOfPadding = 0;// ������ RawSize ��ŭ�� ���� �� �ڿ� ���� NULL ���� ũ��
	DWORD dwSizeOfPadding = 0;	// ���� ����� ������ RawSize ���� ���� ��� ���� �� ������ �ڿ� ���� NULL �е� ũ��

	if(dwSecAlign == dwFileAlign)	{  }	// SectionAlignment�� FileAlignment�� ���� ��쿡�� ���ϸ� �����ϸ� �ȴ�.
	else if(dwSecAlign < dwFileAlign) 
	{ 
		ERRPRINT_GOTO(_EXIT, "FileAlignment is larger than SectionAlignment"); 
	}
	else	// SectionAlignment ���� FileAlignment�� ���� ���(�Ϲ���)���� ���ϻ��� ��ġ�� ���߾� �־�� �Ѵ�.
	{
		// �� ���ϻ� ������ �ּҿ� �� �̹����� ������ �ּ� ����
		for(dwIdx = 0; dwIdx < dwNumOfSecs; dwIdx++)
		{
			// ���ܵ� ���� ��� (.textbss ����)
			if(!strncmp( (const char *)pISH[dwIdx]->Name, ".textbss", 8))
			{
				continue;
			}
			pRAddrOfSecs = (PBYTE)pIDH + pISH[dwIdx]->PointerToRawData;	// MZ�ּ� ó������ �� ������ PointerToRawData��ŭ ���ؾ� �޸𸮻� ��ġ�� ����
			pVAddrOfSecs = (PBYTE)pIDH + pISH[dwIdx]->VirtualAddress;	// MZ�ּ� ó������ �� ������ Virtual Address��ŭ ���ؾ� �޸𸮻� ��ġ�� ����
			dwRawSize = pISH[dwIdx]->SizeOfRawData;
			dwVirSize = pISH[dwIdx]->Misc.VirtualSize;
			dwCopySize = dwRawSize > dwVirSize ? dwVirSize : dwRawSize;

			// �� ������ �޸� �ʰ��ϴ��� üũ
			if(pVAddrOfSecs + dwCopySize > (PBYTE)pIDH + dwSizeOfChunk)
				continue;

			// ���� ����
			memcpy_s(pRAddrOfSecs, dwRawSize, pVAddrOfSecs, dwCopySize);

			if(dwRawSize == dwVirSize)
				continue;

			// ���� �ڿ� ���� NULL �е� ũ�� ���ϱ�
			dwOriSizeOfPadding = dwRawSize % dwFileAlign;
			dwSizeOfPadding = dwOriSizeOfPadding + dwRawSize - dwCopySize;

			// ����� ���� ���� NULL �е� ���̱�
			ZeroMemory(pRAddrOfSecs + dwCopySize, dwSizeOfPadding);		
		}
	}

	// ���� �� ���� ���� ������ �˾Ƴ�
	dwSizeOfFile = pISH[0]->PointerToRawData + pISH[0]->SizeOfRawData;
	for(dwIdx = 1; dwIdx < dwNumOfSecs; dwIdx++)
	{
		dwSizeOfSec = pISH[dwIdx]->PointerToRawData + pISH[dwIdx]->SizeOfRawData;
		dwSizeOfFile = dwSizeOfFile < dwSizeOfSec ? dwSizeOfSec : dwSizeOfFile;
	}

	// ������� �Դٸ� ����� �̹����� ���Ϸ� ������ ����������Ƿ� strModuleName�� �״�� ����ص� ��
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
	/* IAT �籸���ؾ� �Ѵٸ� �籸�� */

_EXIT:
	SAFECLOSEHANDLE16(hPeFile);
	SAFECLOSEHANDLE16(hChunkFile);
	SAFEDELETEARRAY1(pISH);

	return bRet;
}

/*	Function : SetPrivilege
	Description : ���μ��� ���� ����
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
	Description : ����� ���� ���
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
	Description : ���μ��� �ȿ� ����� ������ �� �� �ִ��� �˾Ƴ���. 
	EnumProcessModules API�� ������ ���ڴ� ��� �迭�� ����� ��Ÿ���Ƿ� ������ �ϳ��� ��� �ڵ��� �ϸ� �� ���� ����� ������� �� �� �ִ�.
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
	Description : ���μ��� ���ο� �ִ� ��� ����� �ּҸ� �˾Ƴ���. 
*/
BOOL CImageToFile::GetAllModMems()
{
	BOOL	bRet = FALSE;
	MODULEENTRY32	stME32 = {0};
	DWORD	idxMod = 0;
	HANDLE	hMod = NULL;

	// lstAllMod ����Ʈ ����
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
	Description : ���μ��� ���ο� �ִ� ��� �������� ���� �ּҸ� �˾Ƴ���.
	RSYSTEM_THREAD_INFORMATION�� �ִ� StartAddress�� �ٸ� ���̴�. �׷��� NtQueryInformationThread�� ����Ͽ� ������ ���� �ּҸ� �˾Ƴ��� �Ѵ�.
	Windows 8 �̻󿡼��� NtQueryInformationThread ��ſ� GetThreadInformation�� ����ؾ� �ϴ� �� �ϴ�.
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

	// lstThdMem ����Ʈ ����
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
		
		// NtQuerySystemInformation ���� �� ���۸� �����Ͽ� �ٽ� �õ�
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

	// ��ü ���μ����� ���� ����Ʈ(?) �߿��� Ÿ���� �Ǵ� ���μ��� ����
	while(pSPI->NextEntryOffset != 0)
	{
		if(pSPI->UniqueProcessId == (HANDLE)dwPid)
			break;
		pSPI = (PRSYSTEM_PROCESS_INFORMATION) XGetPtr(pSPI, pSPI->NextEntryOffset);
	}

	ULONGLONG ullMinCreateTime = MAXULONGLONG;
	// Ÿ�� ���μ������� ��������� �����ּҸ� �ٽ� Ÿ�� ���μ����� �����Ͽ� �ּ� �뿪�� �˾Ƴ�
	pThd = (PRSYSTEM_THREAD_INFORMATION) XGetPtr(pSPI, sizeof(RSYSTEM_PROCESS_INFORMATION));
	for(ULONG i = 0; i < pSPI->NumberOfThreads; i++)
	{
		hThd = OpenThread(THREAD_QUERY_INFORMATION, FALSE, (DWORD)pThd->ClientId.UniqueThread);
		DWORD Err = GetLastError();
		if(hThd == NULL)
		{
			WARNPRINT_GOTO(_CONTINUE, "OpenThread");
		}
		
		PVOID Win32StartAddr = NULL;	// NtQueryInformationThread�� ���� ������ ��ŸƮ �ּ�
		UINT_PTR upStartAddr = 0;		// ������ ����� ������ ��ŸƮ �ּ�
		NTSTATUS ntStatus;  
		// ������ ���� �ּ� �˾Ƴ���
		ntStatus = pNtQueryInformationThread(hThd,
											ThreadQuerySetWin32StartAddress,
											&Win32StartAddr,
											sizeof(Win32StartAddr),
											NULL);

		if(!NT_SUCCESS(ntStatus))
		{
			ERRPRINT_GOTO(_EXIT, "NtQueryInformationThread");
		}

		// �����尡 �ٸ� ���μ����κ��� ���� �޸𸮷� ���εǾ� RtlCreateUserThread API�� ������ ��� Win32StartAddr�� 0�� ��
		upStartAddr = (UINT_PTR)Win32StartAddr == 0 ? (UINT_PTR)pThd->StartAddress : (UINT_PTR)Win32StartAddr;

		/* �׽�Ʈ ��� ���ϴ� �޸� ������ PE�� ó���� �ƴ� ���ɼ��� ŭ. ���� �Ʒ� �ּ� ó��
		// ������ ���� �ּҸ� ��� �ִ� �޸� ���� �ּҿ� ������ �˱�
		if(VirtualQueryEx(hImage, (LPCVOID)BaseAddr, &stMBI, sizeof(MEMORY_BASIC_INFORMATION)) != sizeof(MEMORY_BASIC_INFORMATION) ||
						stMBI.RegionSize <= 0 || stMBI.State != MEM_COMMIT)
		{
			ERRPRINT_GOTO(_CONTINUE, _T("VirtualQueryEx(0x%x)"), BaseAddr);
		}
		*/

		// upStartAddr �ּҰ� ��� ���� �ۿ� �ִ��� �˻�
		if(upStartAddr < upMinMem || upMaxMem < upStartAddr)
		{
			WARNPRINT_GOTO(_CONTINUE, "Thread StartAddress limit");
		}

		// ���� ������ Ž���� ���� �κ� (������ ���� �ð��� ���� ���� ���� ���� ������)
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
		// �ٸ� ���μ����� ������ ���� ���� ��??
		hThd = OpenThread(THREAD_QUERY_INFORMATION, FALSE, stTE32.th32ThreadID);
		DWORD Err = GetLastError();
		if(hThd == NULL)
		{
			ERRPRINT_GOTO(_CONTINUE, _T("OpenThread (Error Code : %x)"), GetLastError());
		}

		PVOID BaseAddr;  
		NTSTATUS ntStatus;  
		// ������ ���� �ּ� �˾Ƴ���
		ntStatus = pNtQueryInformationThread(hThd,  
											ThreadQuerySetWin32StartAddress,
											&BaseAddr,
											sizeof(BaseAddr),
											NULL);

		if(!NT_SUCCESS(ntStatus))
		{
			ERRPRINT_GOTO(_EXIT, _T("pNtQueryInformationThread (Error Code : %x)"), GetLastError());
		}
		
		// ������ ���� �ּҸ� ��� �ִ� �޸� ���� �ּҿ� ������ �˱�
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