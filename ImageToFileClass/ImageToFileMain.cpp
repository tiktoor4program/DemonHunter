#include "CImageToFile.h"

int _tmain(int argc, TCHAR* argv[])
{
	//_CrtSetBreakAlloc(#);
	CImageToFile *cITF = new CImageToFile(argc, argv);

	if(!cITF->IsOptErr())
	{
		cITF->Run();
	}

	delete cITF;

	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
	return 0;
}