#include "stdafx.h"

char Watermark[] = "xbLive - Made by BLiNDzZ & Cameron <3";

void SystemThread()
{
	DbgPrint((char*)StrEnc("Running...\n"));

	auto mountPath = Utils::GetMountPath();
	if (!SUCCEEDED(Utils::MountPath(StrEnc("XBLIVE:"), mountPath, true)))
	{
		FreeLibraryAndExitThread((HMODULE)xbLive.hMyModule, 0);
		*(WORD*)((DWORD)xbLive.hMyModule + 64) = 1;
		return;
	}

	delete[] mountPath;

	Utils::MountPath(StrEnc("HDD:"), "\\Device\\Harddisk0\\Partition1\\", true);
	Utils::MountPath(StrEnc("USB:"), "\\Device\\Mass0\\", true);

	Log::Initialize();
	
	if (FAILED(Invoker::Initialize()))
	{
		LOG_PRINT(StrEnc("Failed to initialize #3443d0a7"));
		Sleep(Utils::DecryptValue(0x8ED4B) /*4000*/);
		HalReturnToFirmware(HalFatalErrorRebootRoutine);
	} FunctionObfuscation(Invoker::Initialize).Null();

	if (FAILED(Launch::Initialize())) 
	{
		LOG_PRINT(StrEnc("Failed to initialize #3c50eb34"));
		Native::Sleep(Native::DecryptDWORD(0x8ED4B /*4000*/));
		Native::HalReturnToFirmware(HalFatalErrorRebootRoutine);
	} FunctionObfuscation(Launch::Initialize).Null();

	if (FAILED(Config::Initialize()))
	{
		LOG_PRINT(StrEnc("Failed to initialize #4b5d12fd"));
		Native::Sleep(Native::DecryptDWORD(0x8ED4B /*4000*/));
		Native::HalReturnToFirmware(HalFatalErrorRebootRoutine);
	} FunctionObfuscation(Config::Initialize).Null();

	if (FAILED(Hypervisor::Initialize())) 
	{
		LOG_PRINT(StrEnc("Failed to initialize #88900c85"));
		Native::Sleep(Native::DecryptDWORD(0x8ED4B /*4000*/));
		Native::HalReturnToFirmware(HalFatalErrorRebootRoutine);
	} FunctionObfuscation(Hypervisor::Initialize).Null();

	if (FAILED(Global::Initialize())) 
	{
		LOG_PRINT(StrEnc("Failed to initialize #74a0bcb7"));
		Native::Sleep(Native::DecryptDWORD(0x8ED4B /*4000*/));
		Native::HalReturnToFirmware(HalFatalErrorRebootRoutine);
	}  FunctionObfuscation(Global::Initialize).Null();

	if (FAILED(HUD::Initialize())) 
	{
		LOG_PRINT(StrEnc("Failed to initialize #944fa9d9"));
		Native::Sleep(Native::DecryptDWORD(0x8ED4B /*4000*/));
		Native::HalReturnToFirmware(HalFatalErrorRebootRoutine);
	} FunctionObfuscation(HUD::Initialize).Null();

	if (FAILED(CPU::Initialize()))
	{
		LOG_PRINT(StrEnc("Failed to initialize #965322d2"));
		Native::Sleep(Native::DecryptDWORD(0x8ED4B /*4000*/));
		Native::HalReturnToFirmware(HalFatalErrorRebootRoutine);
	} FunctionObfuscation(CPU::Initialize).Null();

	if (FAILED(Keyvault::Initialize())) 
	{
		LOG_PRINT(StrEnc("Failed to initialize #1f39b7b4"));
		Native::Sleep(Native::DecryptDWORD(0x8ED4B /*4000*/));
		Native::HalReturnToFirmware(HalFatalErrorRebootRoutine);
	} FunctionObfuscation(Keyvault::Initialize).Null();

	if (FAILED(Infection::Initialize()))
	{
		LOG_PRINT(StrEnc("Failed to initialize #407b117a"));
		Native::Sleep(Native::DecryptDWORD(0x8ED4B /*4000*/));
		Native::HalReturnToFirmware(HalFatalErrorRebootRoutine);
	} FunctionObfuscation(Infection::Initialize).Null();

	if (FAILED(Utils::HvSetupRsaMemoryKey())) 
	{
		LOG_PRINT(StrEnc("Failed to initialize #5713337"));
		Native::Sleep(Native::DecryptDWORD(0x8ED4B /*4000*/));
		Native::HalReturnToFirmware(HalFatalErrorRebootRoutine);
	} FunctionObfuscation(Utils::HvSetupMemEncryptionKey).Null();

	if (FAILED(SystemHooks::Initialize())) 
	{
		LOG_PRINT(StrEnc("Failed to initialize #578ce42d"));
		Native::Sleep(Native::DecryptDWORD(0x8ED4B /*4000*/));
		Native::HalReturnToFirmware(HalFatalErrorRebootRoutine);
	} FunctionObfuscation(SystemHooks::Initialize).Null();

	LOG_DEV(StrEnc("Initialized successfully!"));

	if (!xbLive.bDevkit) 
	{
		LOG_DEV(StrEnc("Boot XEX: %s"), Launch::strBootXex.c_str());

		while (true) 
		{
			static int counter = 0;
			static vector<string> modules;

			modules.clear();

			if (counter > 40) {
				LOG_DEV(StrEnc("Failed to verify if boot xex was loaded after 40 seconds, initializing anyway"));
				break;
			}

			PLDR_DATA_TABLE_ENTRY ldr = (PLDR_DATA_TABLE_ENTRY)GetModuleHandleA("xboxkrnl.exe");
			PLIST_ENTRY CurrentEntry = ldr->InLoadOrderLinks.Flink;
			PLDR_DATA_TABLE_ENTRY Current = NULL;
			char buffer[30];

			while (CurrentEntry != &ldr->InLoadOrderLinks && CurrentEntry != NULL)
			{
				Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
				if (!Current) 
				{
					break;
				}

				auto name = Current->BaseDllName.Buffer;
				if (!name) 
				{
					break;
				}

				ZeroMemory(buffer, 30);
				wcstombs(buffer, name, sizeof(buffer));

				string actualName(buffer);

				if (strlen(buffer) > 0)
				{
					modules.push_back(actualName);
				}

				CurrentEntry = CurrentEntry->Flink;
			}

			bool load = false;
			for (int i = 0; i < modules.size(); i++) {
				if (!strcmp(modules[i].c_str(), StrEnc("bootanim.xex")))
				{
					load = true;
					break;
				}
			}

			counter++;
			if (!load) { modules.clear(); break; }
			Native::Sleep(1000);
		}
	}

	xbLive.bLoadedProperly = true;

	Native::Sleep(Native::DecryptDWORD(0x8E103 /*1000*/) * 5);

	while (true)
	{
		Native::Sleep(Native::DecryptDWORD(0x8E187 /*100*/));

		if (!xbLive.bCanNotify)
		{
			xbLive.bCanNotify = xbLive.bDevkit ? true : XamIsCurrentTitleDash();
		}

		if (Notify::Queue.size() > 0 && xbLive.bCanNotify) 
		{
			if (KeGetCurrentProcessType() != 1) 
			{
				CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)XNotifyThread, (LPVOID)Notify::Queue[0], 0, NULL);
			} else XNotifyThread(Notify::Queue[0]);

			Notify::Queue.erase(Notify::Queue.begin());
		}
	}

	Watermark[0] = 'x';
}

BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) 
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		srand(time(0));
		if (!SMC::IsTrayOpen() && XboxKrnlVersion->Build == KERNEL_VERSION) 
		{
			xbLive.bDevkit = *(int*)0x8E038610 & 0x8000 ? false : true;
			xbLive.hMyModule = hModule;

			XexPcToFileHeader((PVOID)0x90e00000, &xbLive.pDataTableEntry);

			HANDLE hThread; DWORD hThreadID;
			ExCreateThread(&hThread, 0, &hThreadID, (PVOID)XapiThreadStartup, (LPTHREAD_START_ROUTINE)SystemThread, NULL, 0x1c000427);
			XSetThreadProcessor(hThread, 4);
			ResumeThread(hThread);
			CloseHandle(hThread);
			return TRUE;
		}

		break;

	case DLL_PROCESS_DETACH:
		HalReturnToFirmware(HalFatalErrorRebootRoutine);
		break;
	}

	Launch::SetLiveBlock(true);
	*(WORD*)((DWORD)hModule + 64) = 1;
	return FALSE;
}

BYTE szObfuscationData[0x1000] = { 'n', 'i', 'g', 'g', 'e', 'r', '6', '9' };

extern "C" BOOL WINAPI _CRT_INIT(HANDLE hModule, DWORD dwReason, LPVOID lpReserved);

#pragma code_seg(push, r1, ".ptext")
#pragma pack(push)
#pragma pack(1)
struct ObfuscationData {
	DWORD dwStart;
	DWORD dwSize;
	BYTE bStaticXor;
	BYTE bRC4KeyXor;
	BYTE szRC4Key[0x30];
};
#pragma pack(pop)

#pragma optimize( "", off )
__forceinline DWORD RandomStuff(int rand) {
	auto address = rand;

	address += 999;
	address ^= 1337;
	address ^= 0x1337;
	address += 69;
	address ^= 333;
	address ^= 666;
	address += 123;
	address -= 0x44 + 0xec + 0xa3 + 0x38 + 0x6c + 0xc5 + 0x70 + (0xdd ^ 12) + (12 << 8);
	address ^= 100;
	address ^= 0x12;
	address += 999;
	address ^= 1337;
	address ^= 0x1337;
	address += 69;
	address ^= 333;
	address ^= 666;
	address += 123;
	address -= 0x54 + 0xec + 0xa3 + 0x38 + 0x6c + 0xc5 + 0x70 + (0xdd ^ 12) + (12 << 8);
	address ^= 100;
	address ^= 0x12;
	address += 999;
	address ^= 1337;
	address ^= 0x1337;
	address += 69;
	address ^= 333;
	address ^= 666;
	address += 123;
	address -= 0x64 + 0xec + 0xa3 + 0x38 + 0x6c + 0xc5 + 0x70 + (0xdd ^ 12) + (12 << 8);
	address ^= 100;
	address ^= 0x12;
	address += 999;
	address ^= 1337;
	address ^= 0x1337;
	address += 69;
	address ^= 333;
	address ^= 666;
	address += 123;
	address -= 0xe4 + 0xec + 0xa3 + 0x38 + 0x6c + 0xc5 + 0x70 + (0xdd ^ 12) + (12 << 8);
	address ^= 100;
	address ^= 0x12;

	return address;
}

__forceinline byte RandomStuffByte(DWORD rand) {
	DWORD address = rand;

	address += 999;
	address ^= 1337;
	address ^= 0x1337;
	address += 69;
	address ^= 333;
	address ^= 666;
	address += 123;
	address -= 0x44 + 0xec + 0xa3 + 0x38 + 0x6c + 0xc5 + 0x70 + (0xdd ^ 12) + (12 << 8);
	address ^= 100;
	address ^= 0x12;
	address += 999;
	address ^= 1337;
	address ^= 0x1337;
	address += 69;
	address ^= 333;
	address ^= 666;
	address += 123;
	address -= 0x54 + 0xec + 0xa3 + 0x38 + 0x6c + 0xc5 + 0x70 + (0xdd ^ 12) + (12 << 8);
	address ^= 100;
	address ^= 0x12;
	address += 999;
	address ^= 1337;
	address ^= 0x1337;
	address += 69;
	address ^= 333;
	address ^= 666;
	address += 123;
	address -= 0x64 + 0xec + 0xa3 + 0x38 + 0x6c + 0xc5 + 0x70 + (0xdd ^ 12) + (12 << 8);
	address ^= 100;
	address ^= 0x12;
	address += 999;
	address ^= 1337;
	address ^= 0x1337;
	address += 69;
	address ^= 333;
	address ^= 666;
	address += 123;
	address -= 0xe4 + 0xec + 0xa3 + 0x38 + 0x6c + 0xc5 + 0x70 + (0xdd ^ 12) + (12 << 8);
	address ^= 100;
	address ^= 0x12;

	return (byte)(address & 0xFF);
}

BOOL APIENTRY SecureDllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	if (*(DWORD*)szObfuscationData != 0x6E696767) {
		ObfuscationData* data = (ObfuscationData*)szObfuscationData;
		
		// decrypt RC4 key
		for (auto i = 0; i < sizeof(data->szRC4Key); i++) {
			data->szRC4Key[i] ^= data->bRC4KeyXor;
		}

		RandomStuff(0x6E696767);
		RandomStuffByte(0x6E696767);

		// run new shit
		for (auto address = data->dwStart; address < (data->dwStart + data->dwSize); address++) {
			*(BYTE*)address = (*(BYTE*)address) ^ RandomStuffByte(0x12);
		}

		// run static xor
		for (auto address = data->dwStart; address < (data->dwStart + data->dwSize); address++) {
			*(BYTE*)address = (*(BYTE*)address) ^ data->bStaticXor;
		}

		RandomStuff(0x48565050);
		RandomStuffByte(0x48565050);

		// run RC4
		BYTE* pbKey = (BYTE*)data->szRC4Key;
		DWORD cbKey = sizeof(data->szRC4Key);
		BYTE* pbInpOut = (BYTE*)data->dwStart;
		DWORD cbInpOut = data->dwSize;

		byte s[256];
		byte k[256];
		byte temp;
		int i, j;

		if (!pbKey || !pbInpOut || !cbInpOut) {
			*(WORD*)((DWORD)hModule + 64) = 1;
			return FALSE;
		}

		for (i = 0; i < 256; i++) {
			s[i] = (byte)i;
			k[i] = pbKey[i % cbKey];
			RandomStuffByte(0x96969696);
		}

		j = 0;
		for (i = 0; i < 256; i++) {
			j = (j + s[i] + k[i]) % 256;
			temp = s[i];
			s[i] = s[j];
			s[j] = temp;
		}

		i = j = 0;
		for (int x = 0; x < cbInpOut; x++) {
			i = (i + 1) % 256;
			j = (j + s[i]) % 256;
			temp = s[i];
			s[i] = s[j];
			s[j] = temp;
			int t = (s[i] + s[j]) % 256;
			pbInpOut[x] ^= s[t];
		}

		for (auto address = data->dwStart; address < (data->dwStart + data->dwSize); address++) {
			if (address % 4 == 0) {
				__dcbst(NULL, (PVOID)address);
				__sync();
				__isync();
			}
		}

		RandomStuff(0x12121AAA);
		RandomStuffByte(0x12121AAA);
	}

	_CRT_INIT(hModule, ul_reason_for_call, lpReserved);
	return DllMain(hModule, ul_reason_for_call, lpReserved);
}
#pragma optimize( "", on )
#pragma code_seg(pop, r1)