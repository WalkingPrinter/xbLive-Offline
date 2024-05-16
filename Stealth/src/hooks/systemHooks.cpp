#include "stdafx.h"


typedef void(*tNetDll_XnpSetChallengeResponse)(XNCALLER_TYPE xnc, DWORD r4, XOSCResponse* respBuff, DWORD respSize);
tNetDll_XnpSetChallengeResponse OriginalNetDll_XnpSetChallengeResponse;
void SystemHooks::NetDll_XnpSetChallengeResponseHook(XNCALLER_TYPE xnc, DWORD r4, XOSCResponse* respBuff, DWORD respSize) 
{
	PXEX_EXECUTION_ID ExecutionID;
	xbLive.bLastXOSCChallengeSuccess = false;

	static BYTE szSupportedChallengeHash[0x14] = { 0x19, 0xB7, 0x2E, 0xCC, 0xD2, 0x3A, 0xC9, 0x69, 0x47, 0x00, 0xA7, 0xC1, 0x78, 0x42, 0x07, 0x91, 0xFA, 0x64, 0x31, 0xEC };
	BYTE szCurrentChallengeHash[0x14] = { 0 };

	XeCryptSha((BYTE*)0x90015000, 0x156C, NULL, NULL, NULL, NULL, szCurrentChallengeHash, 0x14);
	if (memcmp(szCurrentChallengeHash, szSupportedChallengeHash, 0x14) != 0)
	{
		Launch::SetLiveBlock(true);
		Notify(StrEnc("xbLive - XOSC Challenge hash didn't match!")).Message();
		Native::Sleep(Native::DecryptDWORD(0x8ED4B /*4000*/));
		Native::HalReturnToFirmware(HalFatalErrorRebootRoutine);
	}

	LOG_DEV("XOSC hash check sucess!");
	//Utils::WriteFile(Utils::va("XBLIVE:\\Challenges\\xosc_challenge_dirty_%i.bin", (int)time(0)), respBuff, 0x400);

	auto keyVault = Keyvault::GetKeyVault();
	long long hvProtectedFlags = *(long long*)0x8E038678;

	respBuff->dwResult = 0;
	respBuff->verMaj = 9;
	respBuff->verMin = 2;
	respBuff->flags = 0x00000000000001BF;
	respBuff->DvdInqResp = 0;
	respBuff->XeikaInqResp = 0;
	respBuff->ExecIdResp = 0;
	respBuff->HvIdCacheDataResp = 0;
	respBuff->MediaInfoResp = 0xC8003003;
	respBuff->MediaInfodwUnk1 = 0xAAAAAAAA;
	respBuff->MediaInfodwUnk2 = 0xAAAAAAAA;
	respBuff->MediaInfoAbUnk = 0xAAAAAAAA;
	respBuff->MediaInfoPad5 = 0xAAAAAAAA;
	respBuff->HardwareMaskTemplate = 0x40000012;
	XeCryptSha(xbLive.szCPUBinKey, 0x10, 0, 0, 0, 0, respBuff->hvCpuKeyHash, 0x10);
	memcpy(respBuff->zeroEncryptedConsoleType, FusesHashes[Utils::GetConsoleMotherboardIndex(keyVault)], 0x10);
	respBuff->DvdXeikaPhaseLevel = 4;
	memset(respBuff->DvdPfiInfo, 0xAA, sizeof(respBuff->DvdPfiInfo));
	memset(respBuff->DvdDmiMediaSerial, 0xAA, sizeof(respBuff->DvdDmiMediaSerial));
	memset(respBuff->DvdMediaId1, 0xAA, sizeof(respBuff->DvdMediaId1));
	memset(respBuff->abPad, 0xAA, sizeof(respBuff->abPad));
	respBuff->DvdDmi10Data = 0xAAAAAAAAAAAAAAAA;
	respBuff->DvdGeometry.Sectors = 0xAAAAAAAA;
	respBuff->DvdGeometry.BytesPerSector = 0xAAAAAAAA;
	memset(respBuff->DvdMediaId2, 0xAA, sizeof(respBuff->DvdMediaId2));
	memcpy(respBuff->DvdInqRespData, (BYTE*)&keyVault->xeIkaCertificate.Data.OddData.InquiryData, 0x24);
	memcpy(respBuff->XeikaInqData, (BYTE*)&keyVault->xeIkaCertificate.Data.OddData.InquiryData, 0x24);
	memcpy(respBuff->ConsoleSerial, (BYTE*)keyVault->consoleSerialNumber, 12);
	respBuff->wPad = 0xAA;
	respBuff->BldrFlags = 0xD83E;
	respBuff->hvUnrestrictedPrivs = keyVault->gameRegion;
	respBuff->kvOddFeatures = keyVault->oddFeatures;
	respBuff->hvUnknown = 0;
	respBuff->kvPolicyFlashSize = xbLive.bTypeOneKV ? 0 : keyVault->policyFlashSize;
	respBuff->hvKeyStatus = xbLive.bFCRT ? 0x033389D3 : 0x023389D3;
	respBuff->dwPad1 = 0xAAAAAAAA;
	respBuff->secDataDvdBootFailures = 0;
	respBuff->secDataFuseBlowFailures = 0;
	respBuff->dwPad2 = 0xAAAAAAAA;
	respBuff->HardwareMask = 0x4158016002000380;
	respBuff->secDataDvdAuthExFailures = 0;
	respBuff->secDataDvdAuthExTimeouts = 0;
	respBuff->kvRestrictedPrivs = 0;
	respBuff->hvSecurityDetected = 0;
	respBuff->hvSecurityActivated = 0;
	memset(respBuff->ConsoleId, 0, sizeof(respBuff->ConsoleId));
	memcpy(respBuff->ConsoleId, (BYTE*)keyVault->consoleCertificate.ConsoleId.abData, 5);
	respBuff->XboxHardwareInfoFlags = 0x40000207;
	memset(respBuff->HddSerialNumber, 0, sizeof(respBuff->HddSerialNumber));
	memset(respBuff->HddFirmwareRevision, 0, sizeof(respBuff->HddFirmwareRevision));
	memset(respBuff->HddModelNumber, 0, sizeof(respBuff->HddModelNumber));
	respBuff->HddUserAddressableSectors = 0;
	memset(respBuff->unkMediaInfo, 0xAA, sizeof(respBuff->unkMediaInfo));
	respBuff->DvdUnkp1 = 0xAAAAAAAAAAAAAAAA;
	respBuff->MediaInfoUnkp3 = 0xAAAAAAAA;
	respBuff->Mu0Au = 0;
	respBuff->Mu1Au = 0;
	respBuff->SfcAu = 0;
	respBuff->IntMuAu = 0;
	respBuff->UsbMu0 = 0x200000;
	respBuff->UsbMu1 = 0;
	respBuff->UsbMu2 = 0;
	respBuff->crlVersion = 6;
	respBuff->Layer0PfiSectors = 0xAAAAAAAAAAAAAAAA;
	respBuff->Layer1PfiSectors = 0xAAAAAAAAAAAAAAAA;
	respBuff->respMagic = 0x5F534750;
	respBuff->dwFinalPad = 0xAAAAAAAA;


	if (NT_SUCCESS(XamGetExecutionId(&ExecutionID)))
	{
		if (ExecutionID->TitleID == 0 || ExecutionID->TitleID == 0xFFFFFFFF || ExecutionID->MediaID == 0xFFFFFFFF || ExecutionID->TitleID == 0xFFFF0055 || ExecutionID->TitleID == 0xFFFE07FF || ExecutionID->TitleID == 0xF5D10000)
		{
			xbLive.ExecutionIDSpoof.TitleID = 0xFFFE07D1;
			memcpy(&ExecutionID, &xbLive.ExecutionIDSpoof, sizeof(XEX_EXECUTION_ID));

			memset(&respBuff->dwMediaType, 0, sizeof(int));
			memcpy(&respBuff->dwTitleId, &xbLive.ExecutionIDSpoof.TitleID, sizeof(int));
		}
	}

	if (ExecutionID->TitleID != 0xFFFE07D1)
		hvProtectedFlags = 4 | (hvProtectedFlags);
	else
		hvProtectedFlags = 4 | (hvProtectedFlags & 1);

	respBuff->hvProtectedFlags = hvProtectedFlags;

	//Utils::WriteFile(Utils::va("XBLIVE:\\Challenges\\xosc_challenge_clean_%i.bin", (int)time(nullptr)), respBuff, 0x400);
	bool success = true;

	if (respBuff->hvCpuKeyHash == 0
		|| respBuff->zeroEncryptedConsoleType == 0
		|| respBuff->xexHashing == 0
		|| respBuff->BldrFlags != Native::DecryptDWORD(0x9D971 /*0xD83E*/)
		|| memcmp(respBuff->DvdInqRespData, respBuff->XeikaInqData, 0x24)
		|| respBuff->crlVersion != 6
		|| respBuff->respMagic != Native::DecryptDWORD(0x5F5C2A5B /*0x5F534750*/)) {
		success = false;
	}

	if (!success) 
	{
		Launch::SetLiveBlock(true);
		Notify(StrEnc("xbLive - XOSC sanity failed!")).Message();
		Native::Sleep(Native::DecryptDWORD(0x8ED4B /*4000*/));
		Native::HalReturnToFirmware(HalFatalErrorRebootRoutine);
		return;
	}
	else
	{
		memcpy(xbLive.szLastXOSCChallenge, respBuff, 0x400);
		xbLive.bLastXOSCChallengeSuccess = true;
	}

	LOG_DEV("XOSC success");
	OriginalNetDll_XnpSetChallengeResponse(xnc, r4, respBuff, respSize);
}

int SystemHooks::XexLoadImageFromMemoryHook(VOID* Image, int ImageSize, const CHAR* ImageName, int LoadFlags, int Version, HMODULE* ModuleHandle)
{
	if (memcmp(ImageName, "xosc", 4) == 0)
	{
		static BYTE szSupportedChallengeHash[0x14] = { 0xAF, 0xDE, 0x6E, 0x58, 0x55, 0x3D, 0xB7, 0x06, 0xCF, 0x41, 0x78, 0xCF, 0x65, 0xA3, 0xD0, 0xA1, 0x49, 0x33, 0x52, 0xB0 };
		BYTE szCurrentChallengeHash[0x14] = { 0 };

		XeCryptSha((BYTE*)Image + 0x5000, 0x156C, NULL, NULL, NULL, NULL, szCurrentChallengeHash, XECRYPT_SHA_DIGEST_SIZE);
		if (memcmp(szCurrentChallengeHash, szSupportedChallengeHash, 0x14) != 0)
		{
			//Utils::WriteFile(Utils::va("XBLIVE:\\Challenges\\xosc_%i.xex", (int)time(0)), Image, ImageSize);
			Launch::SetLiveBlock(true);
			Notify(StrEnc("xbLive - XOSC Challenge hash didn't match!")).Message();
			Native::Sleep(Native::DecryptDWORD(0x8ED4B /*4000*/));
			Native::HalReturnToFirmware(HalFatalErrorRebootRoutine);
		}
	}

	return XexLoadImageFromMemory(Image, ImageSize, ImageName, LoadFlags, Version, (PHANDLE)ModuleHandle);
}

bool SystemHooks::XexCheckExecutablePrivilegeHook(int priviledge)
{
	if (priviledge == 6) return true; // PRIV_INSECURE_SOCKS
	if (priviledge == 0x11) return false; // PRIV_AP25_MEDIA
	return XexCheckExecutablePrivilege(priviledge);
}

HRESULT SystemHooks::XexStartExecutableHook(FARPROC TitleProcessInitThreadProc) 
{
	auto res = XexStartExecutable(TitleProcessInitThreadProc);
	TitleHooks::RunOnTitleLoad((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle);
	return res;
}

void SystemHooks::XSecurityCloseProcessHook()
{
	return;
}

void SystemHooks::APCWorker(void* Arg1, void* Arg2, void* Arg3) 
{
	if (Arg2)
		((LPOVERLAPPED_COMPLETION_ROUTINE)Arg2)((DWORD)Arg3, 0, (LPOVERLAPPED)Arg1);
}

int SystemHooks::XSecurityCreateProcessHook(int dwHardwareThread)
{
	return 0;
}

int SystemHooks::XSecurityVerifyHook(DWORD dwMilliseconds, LPOVERLAPPED lpOverlapped, LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	if (lpCompletionRoutine)
		NtQueueApcThread((HANDLE)-2, (PIO_APC_ROUTINE)APCWorker, lpOverlapped, (PIO_STATUS_BLOCK)lpCompletionRoutine, 0);

	return ERROR_SUCCESS;
}

int SystemHooks::XSecurityGetFailureInfoHook(PXSECURITY_FAILURE_INFORMATION pFailureInformation) 
{
	if (pFailureInformation->dwSize != 0x18)
		return ERROR_NOT_ENOUGH_MEMORY;

	pFailureInformation->dwBlocksChecked = 0;
	pFailureInformation->dwFailedReads = 0;
	pFailureInformation->dwFailedHashes = 0;
	pFailureInformation->dwTotalBlocks = 0;
	pFailureInformation->fComplete = TRUE;

	return ERROR_SUCCESS;
}

int SystemHooks::XexGetProcedureAddressHook(HANDLE hand, DWORD dwOrdinal, PVOID* pvAddress)
{
	if (hand == GetModuleHandleA(MODULE_XAM)) 
	{
		switch (dwOrdinal) 
		{
			case 0x9BB:
				*pvAddress = XSecurityCreateProcessHook;
				return 0;
			case 0x9BC:
				*pvAddress = XSecurityCloseProcessHook;
				return 0;
			case 0x9BD:
				*pvAddress = XSecurityVerifyHook;
				return 0;
			case 0x9BE:
				*pvAddress = XSecurityGetFailureInfoHook;
				return 0;
		}
	}

	return XexGetProcedureAddress(hand, dwOrdinal, pvAddress);
}

void* SystemHooks::RtlImageXexHeaderFieldHook(void* headerBase, DWORD imageKey)
{
	void* retVal = RtlImageXexHeaderField(headerBase, imageKey);

	if (imageKey == 0x40006 && retVal)
	{
		switch (((XEX_EXECUTION_ID*)retVal)->TitleID) 
		{
			case 0xFFFF0055:   // Xex Menu
			case 0xFFFE07FF:   // XShellXDK
			case 0xF5D10000:   // dl main
			case 0xFFFF011D:   // dl installer
			case 0xF5D20000:   // fsd
			case 0x00000195:   // XeBoy Advance
			case 0x1CED291:    // PlayStation 1
			case 0x00000174:   // MAME360
			case 0x00000177:   // NXE2GOD
			case 0x00000180:   // DosBox
			case 0x00000167:   // Freestyle 3
			case 0x00000176:   // XM360
			case 0x00000184:   // OpenBOR360
			case 0xFFED7301:   // GameBoyAdvance360
			case 0x00001039:   // Snes360 PAL simpel v1
			case 0xFFED0707:   // Snes360
			case 0xFFFF051F:   // Atari 2600
			case 0x00000178:   // SuperMarioWar
			case 0x00000170:   // XexMenu 2.0
			case 0x00000166:   // Aurora
			case 0x4D5707DB:   // Unreal dev engine
			case 0x584b87ff:   // 360dashit
			case 0x00000155:   // psx emulator (early version)
			case 0x1CED2911:
			{  // psx emulator
				int ver = ((XboxKrnlVersion->Major & 0xF) << 28) | ((XboxKrnlVersion->Minor & 0xF) << 24) | (KERNEL_VERSION << 8) | (XboxKrnlVersion->Qfe);
				xbLive.ExecutionIDSpoof.BaseVersion = ver;
				xbLive.ExecutionIDSpoof.Version = ver;
				memcpy(retVal, &xbLive.ExecutionIDSpoof, sizeof(XEX_EXECUTION_ID));
				break;
			}
		}
	}
	else if (imageKey == 0x40006 && !retVal) 
	{
		retVal = &xbLive.ExecutionIDSpoof;
	}

	return retVal;
}

long long SystemHooks::XeKeysExecuteHook(XE_KEYS_BUFFER* buffer, int fileSize, byte* salt, long long input2, long long input3, long long input4) 
{
	BYTE HV_Data[0x50];
	static BYTE szSupportedChallengeHash[0x14] = { 0x0E, 0xA5, 0xDD, 0x7C, 0x32, 0x13, 0xEA, 0x72, 0x93, 0x02, 0x3E, 0x25, 0x73, 0xC1, 0xEA, 0xD9, 0x6F, 0xDF, 0xC6, 0x36 };
	BYTE szCurrentChallengeHash[0x14] = { 0 };
	xbLive.bLastXamChallengeSuccess = false;

	XeCryptSha((BYTE*)buffer, 0x3F0, NULL, NULL, NULL, NULL, szCurrentChallengeHash, 0x14);

	if (memcmp(szCurrentChallengeHash, szSupportedChallengeHash, 0x14) != 0) 
	{
		//Utils::WriteFile(Utils::va("XBLIVE:\\Challenges\\xam_challenge_payload_%i.bin", (int)time(0)), buffer, fileSize);
		Launch::SetLiveBlock(true);
		Notify(StrEnc("xbLive - Challenge hash didn't match!")).Message();
		LOG_ERROR(StrEnc("xbLive - Challenge hash didn't match!"));
		Sleep(4000);
		HalReturnToFirmware(HalFatalErrorRebootRoutine);
	}

	DWORD retryCount = 0;

checkStatus:
	if (!xbLive.bLoadedProperly)
	{
		if (retryCount > 25)
		{
			LOG_PRINT(StrEnc("Enabling live block! #4"));
			Launch::SetLiveBlock(true);
			return 0xC000009A;
		}

		retryCount++;
		Sleep(1000);
		goto checkStatus;
	}

	if (Utils::GetChallengeData(HV_Data, salt))
	{
		memset(buffer, 0, fileSize);
		buffer->wHvMagic = 0x4E4E;
		buffer->dwBaseKernelVersion = 0x07600000;
		buffer->wHvVersion = KERNEL_VERSION;
		buffer->dwUpdateSequence = 0x7F03C300;
		buffer->dwConsoleTypeSeqAllow = xbLive.bTypeOneKV ? 0x010B0400 : 0x0304000E;
		buffer->qwRTOC = 0x0000000200000000;
		buffer->qwHRMOR = 0x0000010000000000;
		buffer->wBldrFlags = 0xD83E;
		buffer->dwHvKeysStatusFlags = xbLive.bFCRT ? 0x033289D3 : 0x023289D3;
		if (xbLive.bCRL) buffer->dwHvKeysStatusFlags = xbLive.bFCRT ? 0x033389D3 : 0x023389D3;

		memcpy(buffer->rsaMemoryKey, xbLive.szRSAKey, 0x80);
		XeCryptSha(xbLive.szCPUBinKey, 0x10, 0, 0, 0, 0, buffer->bCpuKeyDigest, 0x14);

		memcpy(&buffer->hvExAddr, (HV_Data + 0x30), 0x2);
		memcpy(buffer->bHvDigest, (HV_Data + 0x46), 0x6);
		memcpy(buffer->bHvECCDigest, (HV_Data + 0x32), 0x14);

		bool success = true;

		if (Utils::IsBufferEmpty(buffer->bHvDigest, 0x6)
			|| Utils::IsBufferEmpty(buffer->bHvECCDigest, XECRYPT_SHA_DIGEST_SIZE)
			|| Utils::IsBufferEmpty(buffer->bCpuKeyDigest, XECRYPT_SHA_DIGEST_SIZE)
			|| buffer->hvExAddr == 0
			|| Utils::IsBufferEmpty(buffer->rsaMemoryKey, 0x80)
			|| buffer->wHvMagic != 0x4E4E
			|| buffer->wHvVersion != KERNEL_VERSION
			|| buffer->dwBaseKernelVersion != 0x07600000
			|| buffer->wBldrFlags != 0xD83E
			|| buffer->qwHRMOR != 0x0000010000000000
			|| buffer->qwRTOC != 0x0000000200000000) {
			//Utils::WriteFile(Utils::va("XBLIVE:\\Challenges\\xam_challenge_failed_%i.bin", (int)time(0)), buffer, 0x120);
			success = false;
		}

		if (!success)
		{
			Launch::SetLiveBlock(true);
			Notify(StrEnc("xbLive - Challenge sanity failed!")).Message();
			LOG_ERROR(StrEnc("xbLive - Challenge sanity failed!"));
			Sleep(4000);
			HalReturnToFirmware(HalFatalErrorRebootRoutine);
			return 0xC000009A;
		}
		else
		{
			memcpy(xbLive.szLastXamChallenge, buffer, 0x120);
			xbLive.bLastXamChallengeSuccess = true;
		}

		if (!xbLive.bCRL)
		{
			Notify(StrEnc("xbLive - Connected to Live!")).Message();
			//Utils::WriteFile(Utils::va("XBLIVE:\\Challenges\\xam_challenge_success_%i.bin", (int)time(0)), buffer, 0x120);
		}

		xbLive.bCRL = true;

		return ERROR_SUCCESS;
	}

	Launch::SetLiveBlock(true);
	Notify(StrEnc("xbLive - Failed to read challenge data!")).Message();
	LOG_ERROR(StrEnc("xbLive - Failed to read challenge data!"));
	Sleep(4000);
	HalReturnToFirmware(HalFatalErrorRebootRoutine);
	return 0xC000009A;
}

typedef void(*tXNotifyQueueUI)(DWORD dwType, DWORD dwUserIndex, DWORD dwPriority, LPCWSTR pwszStringParam, ULONGLONG qwParam);
tXNotifyQueueUI OriginalXNotifyQueueUI;
void SystemHooks::XNotifyQueueUIHook(DWORD dwType, DWORD dwUserIndex, DWORD dwPriority, LPCWSTR pwszStringParam, ULONGLONG qwParam) 
{
	if (xbLive.bCanNotify)
	{
		OriginalXNotifyQueueUI(dwType, dwUserIndex, dwPriority, pwszStringParam, qwParam);
	}
	else
	{
		if (Notify::Bypass[pwszStringParam])
		{
			OriginalXNotifyQueueUI(dwType, dwUserIndex, dwPriority, pwszStringParam, qwParam);
		} 
		else 
		{
			Notify((wchar_t*)pwszStringParam).HookFix(dwType, dwUserIndex, dwPriority, qwParam);
		}
	}
}

typedef void*(*tXexPcToFileHeader)(DWORD, PLDR_DATA_TABLE_ENTRY*);
tXexPcToFileHeader OriginalXexPcToFileHeader;
void* SystemHooks::XexPcToFileHeaderHook(DWORD pAddress, PLDR_DATA_TABLE_ENTRY* ldatOut)
{
	DWORD dwLR = 0;
	__asm mflr dwLR

	if (dwLR > 0x91C10000 && dwLR < 0x91D10000 && pAddress) 
	{
		if (*(BYTE*)(pAddress) == 'x') 
		{
			// cheat load
			DWORD hiddenThreadStartup = *(DWORD*)(pAddress + 4);
			if (hiddenThreadStartup) 
			{
				Invoke::Call<DWORD>(hiddenThreadStartup);
				if (ldatOut) *ldatOut = nullptr;
				return nullptr;
			}
		}
	}

	return OriginalXexPcToFileHeader(pAddress, ldatOut);
}

HRESULT SystemHooks::Initialize() 
{
	ENCRYPTION_MARKER_BEGIN;

	int ver = ((XboxKrnlVersion->Major & 0xF) << 28) | ((XboxKrnlVersion->Minor & 0xF) << 24) | (KERNEL_VERSION << 8) | (XboxKrnlVersion->Qfe);
	memset(&xbLive.ExecutionIDSpoof, 0, sizeof(XEX_EXECUTION_ID));
	xbLive.ExecutionIDSpoof.Version = ver;
	xbLive.ExecutionIDSpoof.BaseVersion = ver;
	xbLive.ExecutionIDSpoof.TitleID = 0xFFFE07D1;

	Hooking::HookFunction(Native::ResolveFunction(MODULE_XAM, 128), &NetDll_XnpSetChallengeResponseHook, &OriginalNetDll_XnpSetChallengeResponse, true);
	Hooking::HookFunction(Native::ResolveFunction(MODULE_XAM, 656), &XNotifyQueueUIHook, &OriginalXNotifyQueueUI);
	Hooking::HookFunction(Native::ResolveFunction(MODULE_KERNEL, 412), &XexPcToFileHeaderHook, &OriginalXexPcToFileHeader);

	Hooking::HookModuleImport(MODULE_XAM, MODULE_KERNEL, 607, XeKeysExecuteHook);
	Hooking::HookModuleImport(MODULE_XAM, MODULE_KERNEL, 416, XexStartExecutableHook);
	Hooking::HookModuleImport(MODULE_XAM, MODULE_KERNEL, 404, XexCheckExecutablePrivilegeHook);
	Hooking::HookModuleImport(MODULE_XAM, MODULE_KERNEL, 407, XexGetProcedureAddressHook);
	Hooking::HookModuleImport(MODULE_XAM, MODULE_KERNEL, 299, RtlImageXexHeaderFieldHook);
	//Hooking::HookModuleImport(MODULE_XAM, MODULE_KERNEL, 410, XexLoadImageFromMemoryHook);

	IntegrityManager::Push(Native::ResolveFunction(MODULE_KERNEL, Native::DecryptDWORD(0x8EB52 /*607*/)), 16, IntegrityRegisterSettings(IntegrityRebootNoMetric, 0x2080ac71));

	ENCRYPTION_MARKER_END;
	return S_OK;
}