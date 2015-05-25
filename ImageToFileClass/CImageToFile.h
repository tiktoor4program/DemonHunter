#ifndef __CIMAGETOFILE_H__
#define __CIMAGETOFILE_H__

#include "CommonHeaders.h"

/* ���� �ڵ带 ���Ϸ� �����ϰų� �ڵ带 PE�� ����� �κ��� ���� */
/* v2.1������ �� ��° �˰����� ����� */
/* ���� �� ��° �˰��򿡼��� ���� ������ �����ּҰ� ���Ե� PE�� ����� Execute ������ ������ �ǽ��Ͽ�����, */
/* v2.1������ ���� ������ �����ּҰ� ���Ե� PE�� �޸� Type�� Private�̸� �ǽ��Ѵ�. */

/* ���� ó�� �α� ���Ϸ� �ϵ��� ��ġ�� */
/* ��ũ�ο��� ���� ���ڰ� ���� ��� ���� �� */

class CImageToFile
{
private:
	/* ���� ���� */
	// �ɼ�
	BOOL	bOpAllProc;		// TRUE : ��� ���μ��� ���, FALSE : Ư�� ���μ��� ��� (dwPid ����)
	BOOL	bOpSusMod;		// TRUE : �ǽ� ��� ���, FALSE : ��� ��� ���
	BOOL	bOpErr;			// �ƹ��� �ɼ��� ���ų� �ش� ���� ���� �ɼ��� ���� �� ��Ʈ

	// ���� ����
	DWORD			dwPid;				// ���� ��ĵ ����� �Ǵ� ���μ��� ���̵�
	CString			strProcess;			// ���� ��ĵ ����� �Ǵ� ���μ��� �̸�
	HANDLE			hImage;				// ���� ��ĵ ����� �Ǵ� ���μ��� �ڵ�
	UINT_PTR		upMinMem;			// ���� �޸𸮿��� ���� ���� �ּ�
	UINT_PTR		upMaxMem;			// ���� �޸𸮿��� ���� ���� �ּ�

	DWORD			dwNumOfMod;			// ��� ����� ����
	list<SMem>		lstAllMem;			// �� ���μ��� ������ ��� Ŀ�Ե� �޸� �ּ�
	list<SMem>		lstAllMod;			// �� ���μ��� ������ ��� ��� �ּ� (��� ����Ʈ�� �����ϴ� ��� ���)
	list<SMem>		lstThdMem;			// �� ���μ��� ������ ��� �����尡 ���� �޸� �ּ�
	SMem			stMainThdMem;		// ���� ������ �޸�

	// �α׸� ���� ����
	ofstream		logFile;

	/* �޼��� ���� */
public:
	// ���� �Լ�
	void Run();

	// ������ & �Ҹ���
	CImageToFile(int argc, TCHAR* argv[]);
	~CImageToFile();

	// ��Ÿ
	BOOL IsOptErr() { return bOpErr; }

private:
	// PE ���� ����
	DWORD ChkPE(const BYTE* const MemAddr, const DWORD dwMemSize);		// MemAddr�� �˻��ؼ� PE ��� ������ �ִ��� �˻�
	DWORD GetSizeOfChunk(const UINT_PTR& _MemAddr);						// MemAddr���� �����ؼ� ����� �޸��� �� �ּұ����� ������ ���
	UINT_PTR GetImageBase(const UINT_PTR& _MemAddr);					// MemAddr���� �����ؼ� ����� �޸��� ó�� �ּҸ� ���
	BOOL GetFileName(const BYTE* const pPe, const DWORD dwSizeOfChunk, const LPCTSTR szFileName);
	BOOL ReadAndMakeFile(const UINT_PTR& MemAddr, const BYTE* const pChunkMem, const DWORD dwSizeOfChunk);

	// ���μ��� ���� (��� ���� dwPid�� hImage ���)
	DWORD GetNumOfModules();	// ���μ����� �ε�� ��� ��� ������ dwNumOfMod�� ���� (dwPid ���)
	BOOL ScanAllProcesses();	// ��� ���μ��� ��� ��ĵ (ScanOneProcess�� ȣ��, dwPid ����Ͽ� hImage ����)
	BOOL ScanOneProcess();		// Ư�� ���μ��� ��� ��ĵ (GetNumOfModules, GetAllThdMems, GetAllModMems, GetAllMemories, CheckMainModule, CheckPeAndMakeFile, list_NotIncludedInAllModules, list_IncludedInAllMemories ȣ��)
	BOOL GetAllMemories();		// Ư�� ���μ��� ������ ��� �޸� �ּҸ� ���� (lstAllMem ���, hImage ���)
	BOOL GetAllModMems();		// Ư�� ���μ��� ������ ��� ��� �ּҸ� ���� (lstAllMod ���, dwPid ���)
	BOOL GetAllThdMems();		// Ư�� ���μ��� ������ ��� ������ ���� �ּҸ� ���� (lstThdMem ���, ���� ���μ��� �˱� ���� dwPid ���)
	BOOL CheckMainModule(list<SMem>& lstResult);						// ���� �������� ���� �ּҸ� ������� BaseAddress(PE ��� ����)�� ���ϰ� �� ������ ���� ������ ������ �ǽ� ���
	BOOL CheckThreadBaseAddress(list<SMem>& lstResult);					// ��� �������� ���� �ּҸ� ������� BaseAddress(PE ��� ����)�� ���ϰ� �� ������ ���� ������ ������ �ǽ� ���
	list<SMem>& CImageToFile::list_NotIncludedInAllModules (list<SMem>& lstAddr, list<SMem>& lstMemRegion, list<SMem>& lstResult);	// lstAddr ����Ʈ�� lstMemRegion ����Ʈ�� ���Ͽ� lstAddr ����Ʈ���� �ִ� ��Ҹ� lstResult�� ����
	list<SMem>& CImageToFile::list_IncludedInAllMemories (list<SMem>& lstAddr, list<SMem>& lstMemRegion, list<SMem>& lstResult);	// lstAddr ����Ʈ�� �ִ� �ּҰ� lstMemRegion �ּ� �뿪�� �ִ��� �˻��ϰ� �ִٸ� �� �ּ� �뿪�� lstResult�� ����
	BOOL CheckPeAndMakeFile(list<SMem>& lstMem);						// �޸� ����Ʈ�� �˻��Ͽ� PE ������ ������ �ִٸ� ���Ϸ� ���� (hImage ���)
	BOOL GetMemBand(list<SMem>& lstSomeMem, list<SMem>& lstMemBand);	// Ư�� �޸� ��ġ�� Input���� �ش� �޸� �뿪(ó�� ��ġ�� �� ��ġ)�� �˾Ƴ�

	// ���� ����
	BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
	void SetDebugPrivilege();

	// ��Ÿ
	void Help(LPCTSTR szPrgPath);
	CString GetTempFilePath(LPCTSTR szPrefix);
};

#endif