#include "stdafx.h"

InterfaceRegistration* InterfaceRegistration::spInterfaceRegistrations;

__declspec(dllexport) void* CreateInterface(DWORD dwHash) {
	LOG_DEV("[Interface] Processing request for %X", dwHash);

	InterfaceRegistration* pCur;
	for (pCur = InterfaceRegistration::spInterfaceRegistrations; pCur; pCur = pCur->pNext) {
		if (pCur->dwInterfaceNameHash == dwHash) {
			return pCur->CreateFunction();
		}
	}

	return nullptr;
}