#include "stdafx.h"
#include <unordered_map>

unsigned char unkKeyBytes[] = {
	0xDA, 0x39, 0xA3, 0xEE,
	0x5E, 0x6B, 0x4B, 0x0D,
	0x32, 0x55, 0xBF, 0xEF,
	0x95, 0x60, 0x18, 0x90,
	0xAF, 0xD8, 0x07, 0x09
};

unsigned char memorySeed[] = 
{
	0xD2, 0x7C, 0xA1, 0x02, 0x15, 0x4A, 0xEC, 0xFA, 0x89, 0x74, 0x9E, 0x24,
	0x1B, 0x83, 0x5E, 0x6D, 0x6E, 0x6C, 0x4D, 0xFB, 0x23, 0x30, 0x08, 0xDB,
	0x89, 0x26, 0xAE, 0x4C, 0xB9, 0x96, 0x5F, 0x45, 0xA8, 0x95, 0xCC, 0xE2,
	0x11, 0x48, 0xA9, 0x44, 0xA0, 0x7B, 0xA4, 0x31, 0x20, 0x86, 0x31, 0x2C
};

unsigned char pubRsaKey[] = {
	// size = 0x10
	0x00, 0x00, 0x00, 0x10,

	// RSA public exponet = 0x00010001 (65537)
	0x00, 0x01, 0x00, 0x01,

	// Reserved. NULL
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	// Public RSA key
	0x04, 0xD0, 0x55, 0x50,
	0x79, 0x19, 0x95, 0x27,
	0x78, 0x89, 0x97, 0x08,
	0xDE, 0x24, 0xD1, 0xED,
	0xB1, 0xEA, 0xE5, 0x48,
	0xAC, 0x1A, 0xC3, 0xC8,
	0x29, 0x45, 0xB0, 0x16,
	0x9B, 0xEF, 0x78, 0x8F,
	0xEF, 0x26, 0x9D, 0x54,
	0x59, 0x95, 0x2D, 0x25,
	0xA5, 0xAC, 0xA3, 0xA6,
	0x94, 0x45, 0xE5, 0x42,
	0x2E, 0x39, 0x88, 0x0C,
	0x3C, 0xAE, 0xEB, 0xFD,
	0x53, 0x3A, 0xE9, 0x70,
	0x43, 0xEA, 0xD1, 0xD1,
	0x78, 0xCE, 0xED, 0x1C,
	0xE5, 0xFD, 0x0F, 0x80,
	0x94, 0x6F, 0x4F, 0xFF,
	0xAD, 0x45, 0x88, 0xCF,
	0x22, 0x4C, 0x56, 0xDE,
	0x03, 0xE2, 0x46, 0x2F,
	0x19, 0xB8, 0x2C, 0xD0,
	0xD7, 0xE9, 0x64, 0xB2,
	0x68, 0x0C, 0x40, 0xF5,
	0x4F, 0xDA, 0x80, 0x8F,
	0x71, 0xA9, 0x64, 0xA4,
	0x15, 0x53, 0x6E, 0x2B,
	0x49, 0x44, 0x55, 0xCB,
	0x05, 0x17, 0x3F, 0x66,
	0xE1, 0x32, 0x2F, 0x1D,
	0xE9, 0x2A, 0xD6, 0x4B
};

char vaBuffer[0x1000];
char* Utils::va(const char* fmt, ...) {
	memset(vaBuffer, 0, 0x1000);
	va_list ap;
	va_start(ap, fmt);
	RtlVsprintf(vaBuffer, fmt, ap); // RtlVsprintf
	va_end(ap);
	return vaBuffer;
}

char* Utils::vaBuff(char* vaBuffer, int size, const char* fmt, ...) {
	memset(vaBuffer, 0, size);
	va_list ap;
	va_start(ap, fmt);
	RtlVsprintf(vaBuffer, fmt, ap);
	va_end(ap);
	return vaBuffer;
}

BOOL Utils::GetSectionInfo(const char* SectionName, DWORD* Address, DWORD* Length) {
	DWORD baseAddr = 0x90E00000;
	DWORD SectionInfoOffset = baseAddr;
	while (!strcmp(StrEnc(".rdata"), (CHAR*)SectionInfoOffset) == FALSE) SectionInfoOffset += 4;
	PIMAGE_SECTION_HEADER DefaultSections = (PIMAGE_SECTION_HEADER)SectionInfoOffset;

	BOOL Succeded = FALSE;
	for (DWORD i = 0; strlen((CHAR*)DefaultSections[i].Name); i++) {
		if (!strcmp(SectionName, (CHAR*)DefaultSections[i].Name) == TRUE) {
			*Address = baseAddr + _byteswap_ulong(DefaultSections[i].VirtualAddress);
			*Length = _byteswap_ulong(DefaultSections[i].Misc.VirtualSize);
			Succeded = TRUE;
			break;
		}
	}

	return Succeded;
}

bool Utils::WriteFile(const CHAR* FilePath, const VOID* Data, DWORD Size) {
	// Open our file
	HANDLE fHandle = CreateFile(FilePath, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fHandle == INVALID_HANDLE_VALUE) {
		LOG_DEV(StrEnc("WriteFile - CreateFile failed"));
		return FALSE;
	}

	// Write our data and close
	DWORD writeSize = Size;
	if (::WriteFile(fHandle, Data, writeSize, &writeSize, NULL) != TRUE) {
		LOG_DEV(StrEnc("WriteFile - WriteFile failed"));
		return FALSE;
	}

	CloseHandle(fHandle);

	// All done
	return TRUE;
}

PWCHAR Utils::vaw(const char* Text, ...) {
	CHAR Buffer[0x1000];
	CHAR MessageBuffer[0x100];
	static WCHAR Message[0x100];

	va_list pArgList;
	va_start(pArgList, Text);
	RtlVsprintf(Buffer, Text, pArgList);
	va_end(pArgList);

	RtlSprintf(MessageBuffer, Buffer);
	mbstowcs(Message, MessageBuffer, strlen(MessageBuffer) + 1);

	ZeroMemory(Buffer, sizeof(Buffer));
	ZeroMemory(MessageBuffer, sizeof(MessageBuffer));

	return Message;
}

bool Utils::FileExists(const char* file) {
	if (GetFileAttributes(file) == -1) {
		DWORD lastError = GetLastError();
		if (lastError == ERROR_FILE_NOT_FOUND || lastError == ERROR_PATH_NOT_FOUND)
			return false;
	}
	return true;
}

HANDLE Utils::ResolveFunction(const char* pModuleName, DWORD dwOrdinal) {
	HANDLE proc = NULL;
	HANDLE hModule = NULL;

	if (!NT_SUCCESS(XexGetModuleHandle((char *)pModuleName, &hModule)))
		return NULL;

	if (!NT_SUCCESS(XexGetProcedureAddress(hModule, dwOrdinal, &proc)))
		return NULL;

	return proc;
}

void Utils::EraseAllSubstrings(string& mainStr, string toErase) {
	size_t pos = string::npos;

	while ((pos = mainStr.find(toErase)) != string::npos) {
		mainStr.erase(pos, toErase.length());
	}
}

HRESULT Utils::DoMountPath(const char* szDrive, const char* szDevice, const char* sysStr) {
	STRING DeviceName, LinkName;
	CHAR szDestinationDrive[MAX_PATH];
	RtlSnprintf(szDestinationDrive, MAX_PATH, sysStr, szDrive);
	RtlInitAnsiString(&DeviceName, szDevice);
	RtlInitAnsiString(&LinkName, szDestinationDrive);
	ObDeleteSymbolicLink(&LinkName);
	return (HRESULT)ObCreateSymbolicLink(&LinkName, &DeviceName);
}

vector<unsigned char> Utils::IntToBytes(int paramInt) {
	vector<unsigned char> arrayOfByte(4);
	for (int i = 0; i < 4; i++)
		arrayOfByte[3 - i] = (paramInt >> (i * 8));
	return arrayOfByte;
}

HRESULT Utils::MountPath(const char* szDrive, const char* szDevice, bool both) {
	HRESULT res;
	if (both) {
		res = DoMountPath(szDrive, szDevice, "\\System??\\%s");
		res = DoMountPath(szDrive, szDevice, "\\??\\%s");
	} else {
		if (KeGetCurrentProcessType() == 2) //SYSTEM_PROC
			res = DoMountPath(szDrive, szDevice, "\\System??\\%s");
		else
			res = DoMountPath(szDrive, szDevice, "\\??\\%s");
	}
	return res;
}

const char* Utils::GetMountPath()
{
	char* DEVICE_DYNAMIC = new char[MAX_PATH];
	wstring ws;
	PLDR_DATA_TABLE_ENTRY TableEntry;
	XexPcToFileHeader((PVOID)0x90e00000, &TableEntry);

	if (TableEntry) 
	{

		ws = TableEntry->FullDllName.Buffer;
		string FullDllName(ws.begin(), ws.end());

		ws = TableEntry->BaseDllName.Buffer;
		string BaseDllName(ws.begin(), ws.end());

		string::size_type i = FullDllName.find(BaseDllName);

		if (i != string::npos)
			FullDllName.erase(i, BaseDllName.length());

		memset(DEVICE_DYNAMIC, 0x0, MAX_PATH);
		strcpy(DEVICE_DYNAMIC, FullDllName.c_str());
	} else {
		LOG_DEV(StrEnc("Mounting failed!"));
	}

	return DEVICE_DYNAMIC;
}

BOOL Utils::IsBufferEmpty(BYTE* pBuffer, DWORD length)
{
	for (DWORD i = 0; i < length; i++) 
	{
		if (pBuffer[i] != 0) return FALSE;
	}

	return TRUE;
}

HRESULT Utils::ApplyPatchData(DWORD* patches, size_t dataSize) 
{
	HRESULT ret;
	const DWORD *patchesEnd = patches + dataSize;

	// loop through all patches in the data
	while (*patches != 0xFFFFFFFF) 
	{

		// bounds check the start of possible patch data
		if (patches + 2 > patchesEnd) 
		{
			return ERROR_INVALID_DATA;
		}

		QWORD patchAddr = *patches++;
		DWORD patchSize = *patches++;
		bool isHvPatch = (patchAddr < 0x40000);

		// bounds check the patch size
		if (patches + patchSize >= patchesEnd) 
		{
			LOG_DEV(StrEnc("Patch size bounds check failed!"));
			return ERROR_BAD_LENGTH;
		}

		// apply this patch
		if (isHvPatch)
		{
			patchAddr = (0x200000000 * (patchAddr / 0x10000)) + patchAddr;
			if (FAILED(ret = Hypervisor::HvPokeBytes(patchAddr, patches, patchSize * sizeof(DWORD))))
			{
				return ret;
			}
		} 
		else
		{
			LOG_DEV("Patching address %X with size %i", (DWORD)patchAddr, patchSize);
			memcpy((void*)patchAddr, (void*)patches, patchSize * sizeof(DWORD));
		}

		// increment past the patch data
		patches += patchSize;
	}

	return S_OK;
}

BYTE Utils::CharToByte(char input) 
{
	if (input >= '0' && input <= '9')
		return input - '0';
	if (input >= 'A' && input <= 'F')
		return input - 'A' + 10;
	if (input >= 'a' && input <= 'f')
		return input - 'a' + 10;
	return 0;
}

NTSTATUS Utils::GetLowPartAllocationUnits(char* device, PDWORD dest)
{
	NTSTATUS ret = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES oab;
	IO_STATUS_BLOCK iosb;
	STRING lstr;
	HANDLE fhand;

	*dest = 0;

	RtlInitAnsiString(&lstr, device);
	oab.RootDirectory = NULL;
	oab.Attributes = 0x40;
	oab.ObjectName = &lstr;

	if (NT_SUCCESS(NtOpenFile(&fhand, 0x100001, &oab, &iosb, 1, 0x800021))) 
	{
		FILE_FS_SIZE_INFORMATION fsinfo;
		if (NT_SUCCESS(ret = NtQueryVolumeInformationFile(fhand, &iosb, &fsinfo, sizeof(FILE_FS_SIZE_INFORMATION), FileFsSizeInformation)))
		{
			*dest = fsinfo.TotalAllocationUnits.LowPart;
		}
		NtClose(fhand);
	}

	return ret;
}

int Utils::GetConsoleMotherboardIndex(PKEY_VAULT keyVault)
{
	BYTE moboSerialByte = 0;

	moboSerialByte = (((Utils::CharToByte(keyVault->consoleCertificate.ConsolePartNumber[2]) << 4) & 0xF0) | ((Utils::CharToByte(keyVault->consoleCertificate.ConsolePartNumber[3]) & 0x0F)));

	if (moboSerialByte < 0x10) // Xenon
		moboSerialByte = 0;

	else if (moboSerialByte < 0x14) // Zephyr
		moboSerialByte = 1;

	else if (moboSerialByte < 0x18) // Falcon
		moboSerialByte = 2;

	else if (moboSerialByte < 0x52) // Jasper
		moboSerialByte = 3;

	else if (moboSerialByte < 0x58) // Trinity (might be 50, idk)
		moboSerialByte = 4;
	else
		moboSerialByte = 5;

	return moboSerialByte;
}

char Utils::GenerateRandomChar() 
{
	static bool seeded = false;
	if (!seeded)
	{
		seeded = true;
		srand(time(0));
	}

	char Characters[10] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };
	return Characters[(rand() % 9)];
}

void Utils::GenerateRandomBytes(unsigned char* arr, int len) 
{
	for (int i = 0; i < len; i++) 
	{
		arr[i] = (unsigned char)(rand() % 256);
	}
}

void LaunchDashboardThread() {
	Native::Sleep(1000);
	XSetLaunchData(NULL, 0);
	XamLoaderLaunchTitleEx(XLAUNCH_KEYWORD_DEFAULT_APP, NULL, NULL, 0);
	ExitThread(0xFF);
}

void Utils::LaunchDashboard() {
	HANDLE hThread;
	DWORD dwThreadId;
	hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)LaunchDashboardThread, 0, CREATE_SUSPENDED, &dwThreadId);
	XSetThreadProcessor(hThread, 2);
	SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL);
	ResumeThread(hThread);
	CloseHandle(hThread);
}

DWORD Utils::Joaat(const char* value) {
	size_t len = strlen(value);
	unsigned int hash, i;
	for (hash = i = 0; i < len; ++i) {
		hash += tolower(value[i]);
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}
	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);
	return hash;
}

void TimedRebootThread(int iMS) {
	Native::Sleep(iMS);
	Native::HalReturnToFirmware(HalFatalErrorRebootRoutine);
}

void Utils::TimedReboot(int ms) {
	CreateThread(0, 0, (LPTHREAD_START_ROUTINE)TimedRebootThread, (void*)ms, 0, 0);
}

struct TimedCallbackArgs {
	int iDelay;
	function<void()> Callback;
};

void TimedCallbackThread(TimedCallbackArgs* args) {
	Native::Sleep(args->iDelay);
	args->Callback();
	delete args;
}

void Utils::TimedCallback(int ms, function<void()> callback) {
	TimedCallbackArgs* args = new TimedCallbackArgs();
	args->Callback = callback;
	args->iDelay = ms;
	
	CreateThread(0, 0, (LPTHREAD_START_ROUTINE)TimedCallbackThread, args, 0, 0);
}

DWORD Utils::DecryptValue(DWORD val) {
	DWORD v = val;

	for (auto i = 49; i >= 0; i--) {
		v ^= (i ^ 69);
	}

	v += 100;
	v ^= 666;
	v ^= 76;
	v -= 747;
	v ^= 4712;
	v ^= 36;
	v ^= 45;
	v -= 585858;
	v ^= 454;
	v ^= 12;

	return v;
}

const char* Utils::XorString(BYTE* str, int len, BYTE key) {
	for (int i = 0; i < len; i++) {
		str[i] ^= key;
	}
}

struct StrEncInfo {
	bool bPopulated;
	char szDecrypted[0x100];
};

unordered_map<DWORD, StrEncInfo*> storage;
const char* Utils::XorStringNoLen(char* str, BYTE key) {
	if (str) {
		DWORD address = (DWORD)str;
		if (storage[address]) {
			if (storage[address]->bPopulated) {
				return storage[address]->szDecrypted;
			}
		}

		storage[address] = new StrEncInfo();
		storage[address]->bPopulated = true;

		for (int i = 0; i < strlen(str); i++) {
			storage[address]->szDecrypted[i] = str[i] ^ 0xFF;
			if (storage[address]->szDecrypted[i] == 0xFF)
				storage[address]->szDecrypted[i] = 0x0;
		}

		// fix \n
		for (int i = 0; i < strlen(storage[address]->szDecrypted); i++) {
			if (storage[address]->szDecrypted[i] == 0x5C) {
				if (i != strlen(storage[address]->szDecrypted) - 1) {
					if (storage[address]->szDecrypted[i + 1] == 0x6E) {
						if (storage[address]->szDecrypted[i + 2] == 0x0) {
							storage[address]->szDecrypted[i] = '\n';
							storage[address]->szDecrypted[i + 1] = 0x0;
						} else {
							storage[address]->szDecrypted[i] = ' ';
							storage[address]->szDecrypted[i + 1] = '\n';
						}
					}
				}
			}
		}

		return storage[address]->szDecrypted;
	}

	return str;
}

void Utils::EnsureRape() {
	Native::HalReturnToFirmware(HalFatalErrorRebootRoutine);

	Sleep(1000);

	// if we get here, it's assumed that they patched the above func. Naughty Naughty!

	for (int i = 0; i < 0x10000; i++) {
		Hypervisor::HvPokeBYTE(i, 0x69);
	}

	// if it gets here, sus
	Hypervisor::HvPokeQWORD(0x101010101010, 0);

	static int i = 0;
	while (true) {
		*(DWORD*)(0x10000000 * 8 + i) = 0x13371337;
		i++;
	}

	for (int i = 0; i < INT_MAX; i++) {
		*(BYTE*)(0x90e00000 + i) = 0x0;
	}
}

void Utils::PrintArray(const char* name, BYTE* arr, int size) {
	DbgPrint("Printing: %s\n", name);
	for (int i = 0; i < size; i++) {
		DbgPrint("%02X", arr[i]);
	} DbgPrint("\n");
}

string Utils::GetModuleNameFromAddress(DWORD dwAddress) {
	PLDR_DATA_TABLE_ENTRY ldr = (PLDR_DATA_TABLE_ENTRY)GetModuleHandleA(MODULE_KERNEL);
	PLIST_ENTRY CurrentEntry = ldr->InLoadOrderLinks.Flink;
	PLDR_DATA_TABLE_ENTRY Current = NULL;

	while (CurrentEntry != &ldr->InLoadOrderLinks && CurrentEntry != NULL) {
		Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		if (!Current) break;
		if (!Current->BaseDllName.Buffer) break;

		DWORD start = (DWORD)Current->ImageBase;
		DWORD size = Current->SizeOfFullImage;

		if (size < 0xFFFFFF) {
			if (Security::IsScanInOurMemory(dwAddress, dwAddress + 4, start, start + size)) {
				char buffer[30];
				ZeroMemory(buffer, 30);
				wcstombs(buffer, Current->BaseDllName.Buffer, sizeof(buffer));
				return string(buffer);
			}
		}

		CurrentEntry = CurrentEntry->Flink;
	}

	return "unknown";
}

void Utils::GenSeedNumber(DWORD totalPairs)
{
	srand(time(0));
	xbLive.keySelected = rand() % totalPairs;
	LOG_DEV("Total Pairs: %i", Config::PairNum);
	Utils::SelectEncKey();
	LOG_DEV("Selected Key: %i", xbLive.keySelected);
}

void Utils::SelectEncKey()
{
	BYTE HV_Key[0x30];
	char SaltName[100];
	RtlSprintf(SaltName, "XBLIVE:\\Pairs\\%i\\Key.bin", xbLive.keySelected);
	FILE* fp = fopen(SaltName, StrEnc("rb"));
	LOG_DEV("%s", SaltName);

	if (fp)
	{
		fread(HV_Key, 1, 0x30, fp);
		fclose(fp);
		memcpy(memorySeed, HV_Key, 0x30);
	}
	else
	{
		LOG_ERROR(StrEnc("Failed to read HV key file"));
		return;
	}
}

void Utils::HvSetupShaSaltedHash(byte* salt, int saltLength, byte* rsaKey, int rsaKeyLength) 
{
	XECRYPT_SHA_STATE sha = { 0 };
	int index = 0;
	byte buffer[4] = { 0 };

	for (int s = 0; s < rsaKeyLength; s += 0x14)
	{
		int Subsize = (s + 0x14 > rsaKeyLength) ? rsaKeyLength - s : 0x14;
		BYTE output[0x14];

		*(int*)buffer = index;
		XeCryptShaInit(&sha);
		XeCryptShaUpdate(&sha, salt, saltLength);
		XeCryptShaUpdate(&sha, buffer, 4);
		XeCryptShaFinal(&sha, output, 0x14);

		for (int l = 0; l < Subsize; l++)
		{
			rsaKey[s + l] ^= output[l];
		}
		index++;
	}
}

bool Utils::HvSetupMemEncryptionKey(byte* memEncSeed, int seedLength /* 0x30 */, byte* memoryRsaKey, int rsaKeyLength /* 0x80 */, byte* secondKey, byte* shaSalt) 
{
	if (rsaKeyLength < 0x2A || seedLength > rsaKeyLength - 0x2A)
		return false;

	memoryRsaKey[0] = 0;

	byte* savedData = memoryRsaKey + 1;
	memcpy(savedData, shaSalt, 0x14);

	memoryRsaKey += 0x15;
	rsaKeyLength -= 0x15;

	memcpy(memoryRsaKey, secondKey, 0x14);
	memset(memoryRsaKey + 0x14, 0, 0x26);

	memoryRsaKey[0x3A] = 1;
	memcpy(memoryRsaKey + 0x3B, memEncSeed, seedLength);

	HvSetupShaSaltedHash(shaSalt, 0x14, memoryRsaKey, rsaKeyLength);
	HvSetupShaSaltedHash(memoryRsaKey, rsaKeyLength, savedData, 0x14);

	return true;
}

void Utils::ReverseData(byte* buffer)
{
	byte tempBuff[0x80];
	int length = 0x7F;
	for (int i = 0; i < 0x80; i++)
	{
		tempBuff[length] = buffer[i];
		length--;
	}

	memcpy(buffer, tempBuff, 0x80);
}

HRESULT Utils::HvSetupRsaMemoryKey(void) 
{
	byte memoryRsaKey[0x80] = { 0 };
	byte shaSalt[0x14] = { 0 }; 

	XECRYPT_RSAPUB_1024* rsa1024 = (XECRYPT_RSAPUB_1024*)pubRsaKey;

	XeCryptRandom(shaSalt, 0x14);
	Utils::GenSeedNumber(Config::PairNum);

	if (!HvSetupMemEncryptionKey(memorySeed, 0x30, memoryRsaKey, 0x80, unkKeyBytes, shaSalt))
	{
		LOG_DEV("HvSetupRsaMemoryKey failed to setup key");
		return S_FALSE;
	}

	ReverseData(memoryRsaKey);
	XeCryptBnQw_SwapDwQwLeBe((PQWORD)memoryRsaKey, (PQWORD)memoryRsaKey, 0x10);

	if (XeCryptBnQwNeRsaPubCrypt((PQWORD)memoryRsaKey, (PQWORD)xbLive.szRSAKey, &rsa1024->Rsa)) 
	{
		XeCryptBnQw_SwapDwQwLeBe((PQWORD)xbLive.szRSAKey, (PQWORD)xbLive.szRSAKey, 0x10);

		return S_OK;
	}

	memset(xbLive.szRSAKey, 0, 0x80);
	return S_FALSE;
}

BOOL Utils::GetChallengeData(BYTE* Data, BYTE* salt)
{
	BYTE HV_Data[0x50];
	char SaltName[100];
	RtlSprintf(SaltName, "XBLIVE:\\Pairs\\%i\\Salts\\0x%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X.bin", xbLive.keySelected, salt[0], salt[1], salt[2], salt[3], salt[4], salt[5], salt[6], salt[7], salt[8], salt[9], salt[10], salt[11], salt[12], salt[13], salt[14], salt[15]);
	FILE* fp = fopen(SaltName, StrEnc("rb"));
	LOG_DEV("%s", SaltName);

	if (fp)
	{
		fread(HV_Data, 1, 0x50, fp);
		fclose(fp);
		memcpy(Data, HV_Data, 0x50);
		return TRUE;
	}
	else
	{
		Launch::SetLiveBlock(true);
		//LOG_ERROR("Failed to read HV files");
		Native::HalReturnToFirmware(HalFatalErrorRebootRoutine);
		return FALSE;
	}
}