#ifndef __CIMAGETOFILE_H__
#define __CIMAGETOFILE_H__

#include "CommonHeaders.h"

/* 아직 코드를 파일로 생성하거나 코드를 PE로 만드는 부분은 없음 */
/* v2.1에서는 두 번째 알고리즘이 변경됨 */
/* 기존 두 번째 알고리즘에서는 메인 쓰레드 시작주소가 포함된 PE의 헤더에 Execute 권한이 있으면 의심하였지만, */
/* v2.1에서는 메인 쓰레드 시작주소가 포함된 PE의 메모리 Type이 Private이면 의심한다. */

/* 에러 처리 로그 파일로 하도록 고치기 */
/* 매크로에서 가변 인자가 없는 경우 에러 남 */

class CImageToFile
{
private:
	/* 변수 선언 */
	// 옵션
	BOOL	bOpAllProc;		// TRUE : 모든 프로세스 대상, FALSE : 특정 프로세스 대상 (dwPid 세팅)
	BOOL	bOpSusMod;		// TRUE : 의심 모듈 대상, FALSE : 모든 모듈 대상
	BOOL	bOpErr;			// 아무런 옵션이 없거나 해당 사항 없는 옵션이 왔을 때 세트

	// 공통 변수
	DWORD			dwPid;				// 현재 스캔 대상이 되는 프로세스 아이디
	CString			strProcess;			// 현재 스캔 대상이 되는 프로세스 이름
	HANDLE			hImage;				// 현재 스캔 대상이 되는 프로세스 핸들
	UINT_PTR		upMinMem;			// 가상 메모리에서 가장 낮은 주소
	UINT_PTR		upMaxMem;			// 가상 메모리에서 가장 높은 주소

	DWORD			dwNumOfMod;			// 모든 모듈의 개수
	list<SMem>		lstAllMem;			// 한 프로세스 내부의 모든 커밋된 메모리 주소
	list<SMem>		lstAllMod;			// 한 프로세스 내부의 모든 모듈 주소 (모듈 리스트에 존재하는 모듈 대상)
	list<SMem>		lstThdMem;			// 한 프로세스 내부의 모든 스레드가 속한 메모리 주소
	SMem			stMainThdMem;		// 메인 스레드 메모리

	// 로그를 위한 변수
	ofstream		logFile;

	/* 메서드 선언 */
public:
	// 메인 함수
	void Run();

	// 생성자 & 소멸자
	CImageToFile(int argc, TCHAR* argv[]);
	~CImageToFile();

	// 기타
	BOOL IsOptErr() { return bOpErr; }

private:
	// PE 파일 관련
	DWORD ChkPE(const BYTE* const MemAddr, const DWORD dwMemSize);		// MemAddr를 검사해서 PE 헤더 구조가 있는지 검사
	DWORD GetSizeOfChunk(const UINT_PTR& _MemAddr);						// MemAddr부터 시작해서 연결된 메모리의 끝 주소까지의 사이즈 얻기
	UINT_PTR GetImageBase(const UINT_PTR& _MemAddr);					// MemAddr부터 시작해서 연결된 메모리의 처음 주소를 얻기
	BOOL GetFileName(const BYTE* const pPe, const DWORD dwSizeOfChunk, const LPCTSTR szFileName);
	BOOL ReadAndMakeFile(const UINT_PTR& MemAddr, const BYTE* const pChunkMem, const DWORD dwSizeOfChunk);

	// 프로세스 관련 (멤버 변수 dwPid나 hImage 사용)
	DWORD GetNumOfModules();	// 프로세스의 로드된 모든 모듈 개수를 dwNumOfMod에 세팅 (dwPid 사용)
	BOOL ScanAllProcesses();	// 모든 프로세스 대상 스캔 (ScanOneProcess를 호출, dwPid 사용하여 hImage 세팅)
	BOOL ScanOneProcess();		// 특정 프로세스 대상 스캔 (GetNumOfModules, GetAllThdMems, GetAllModMems, GetAllMemories, CheckMainModule, CheckPeAndMakeFile, list_NotIncludedInAllModules, list_IncludedInAllMemories 호출)
	BOOL GetAllMemories();		// 특정 프로세스 내부의 모든 메모리 주소를 얻음 (lstAllMem 얻기, hImage 사용)
	BOOL GetAllModMems();		// 특정 프로세스 내부의 모든 모듈 주소를 얻음 (lstAllMod 얻기, dwPid 사용)
	BOOL GetAllThdMems();		// 특정 프로세스 내부의 모든 스레드 시작 주소를 얻음 (lstThdMem 얻기, 현재 프로세스 알기 위해 dwPid 사용)
	BOOL CheckMainModule(list<SMem>& lstResult);						// 메인 스레드의 시작 주소를 대상으로 BaseAddress(PE 헤더 영역)를 구하고 그 영역에 실행 권한이 있으면 의심 모듈
	BOOL CheckThreadBaseAddress(list<SMem>& lstResult);					// 모든 스레드의 시작 주소를 대상으로 BaseAddress(PE 헤더 영역)를 구하고 그 영역에 실행 권한이 있으면 의심 모듈
	list<SMem>& CImageToFile::list_NotIncludedInAllModules (list<SMem>& lstAddr, list<SMem>& lstMemRegion, list<SMem>& lstResult);	// lstAddr 리스트와 lstMemRegion 리스트를 비교하여 lstAddr 리스트에만 있는 요소를 lstResult로 복사
	list<SMem>& CImageToFile::list_IncludedInAllMemories (list<SMem>& lstAddr, list<SMem>& lstMemRegion, list<SMem>& lstResult);	// lstAddr 리스트에 있는 주소가 lstMemRegion 주소 대역에 있는지 검사하고 있다면 그 주소 대역을 lstResult에 복사
	BOOL CheckPeAndMakeFile(list<SMem>& lstMem);						// 메모리 리스트를 검사하여 PE 구조를 가지고 있다면 파일로 생성 (hImage 사용)
	BOOL GetMemBand(list<SMem>& lstSomeMem, list<SMem>& lstMemBand);	// 특정 메모리 위치를 Input으로 해당 메모리 대역(처음 위치와 끝 위치)을 알아냄

	// 권한 관련
	BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
	void SetDebugPrivilege();

	// 기타
	void Help(LPCTSTR szPrgPath);
	CString GetTempFilePath(LPCTSTR szPrefix);
};

#endif