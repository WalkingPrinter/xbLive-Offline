#pragma once

struct once_flag {
	bool bDone;
};

static void call_once(once_flag* flag, function<void()> func) {
	if (flag) {
		if (!flag->bDone) {
			if (func) {
				func();
			}

			flag->bDone = true;
		}
	}
}

class Invoke {
public:
	template<typename T>
	static T Call(DWORD dwAddress) { return ((T(*)())dwAddress)(); }

	template<typename T, typename P1>
	static T Call(DWORD dwAddress, P1 p1) { return ((T(*)(P1))dwAddress)(p1); }

	template<typename T, typename P1, typename P2>
	static T Call(DWORD dwAddress, P1 p1, P2 p2) { return ((T(*)(P1, P2))dwAddress)(p1, p2); }

	template<typename T, typename P1, typename P2, typename P3>
	static T Call(DWORD dwAddress, P1 p1, P2 p2, P3 p3) { return ((T(*)(P1, P2, P3))dwAddress)(p1, p2, p3); }

	template<typename T, typename P1, typename P2, typename P3, typename P4>
	static T Call(DWORD dwAddress, P1 p1, P2 p2, P3 p3, P4 p4) { return ((T(*)(P1, P2, P3, P4))dwAddress)(p1, p2, p3, p4); }

	template<typename T, typename P1, typename P2, typename P3, typename P4, typename P5>
	static T Call(DWORD dwAddress, P1 p1, P2 p2, P3 p3, P4 p4, P5 p5) { return ((T(*)(P1, P2, P3, P4, P5))dwAddress)(p1, p2, p3, p4, p5); }

	template<typename T, typename P1, typename P2, typename P3, typename P4, typename P5, typename P6>
	static T Call(DWORD dwAddress, P1 p1, P2 p2, P3 p3, P4 p4, P5 p5, P6 p6) { return ((T(*)(P1, P2, P3, P4, P5, P6))dwAddress)(p1, p2, p3, p4, p5, p6); }

	template<typename T, typename P1, typename P2, typename P3, typename P4, typename P5, typename P6, typename P7>
	static T Call(DWORD dwAddress, P1 p1, P2 p2, P3 p3, P4 p4, P5 p5, P6 p6, P7 p7) { return ((T(*)(P1, P2, P3, P4, P5, P6, P7))dwAddress)(p1, p2, p3, p4, p5, p6, p7); }

	template<typename T, typename P1, typename P2, typename P3, typename P4, typename P5, typename P6, typename P7, typename P8>
	static T Call(DWORD dwAddress, P1 p1, P2 p2, P3 p3, P4 p4, P5 p5, P6 p6, P7 p7, P8 p8) { return ((T(*)(P1, P2, P3, P4, P5, P6, P7, P8))dwAddress)(p1, p2, p3, p4, p5, p6, p7, p8); }

	template<typename T, typename P1, typename P2, typename P3, typename P4, typename P5, typename P6, typename P7, typename P8, typename P9>
	static T Call(DWORD dwAddress, P1 p1, P2 p2, P3 p3, P4 p4, P5 p5, P6 p6, P7 p7, P8 p8, P9 p9) { return ((T(*)(P1, P2, P3, P4, P5, P6, P7, P8, P9))dwAddress)(p1, p2, p3, p4, p5, p6, p7, p8. p9); }

	template<typename T, typename P1, typename P2, typename P3, typename P4, typename P5, typename P6, typename P7, typename P8, typename P9, typename P10>
	static T Call(DWORD dwAddress, P1 p1, P2 p2, P3 p3, P4 p4, P5 p5, P6 p6, P7 p7, P8 p8, P9 p9, P10 p10) { return ((T(*)(P1, P2, P3, P4, P5, P6, P7, P8, P9, P10))dwAddress)(p1, p2, p3, p4, p5, p6, p7, p8, p9, p10); }
};

class Utils {
public:
	static HANDLE ResolveFunction(const char* pModuleName, DWORD dwOrdinal);
	static void EraseAllSubstrings(string& mainStr, string toErase);
	static BOOL IsBufferEmpty(BYTE* pBuffer, DWORD length);
	static HRESULT ApplyPatchData(DWORD* patches, size_t dataSize);
	static bool FileExists(const char* file);
	static HRESULT DoMountPath(const char* szDrive, const char* szDevice, const char* sysStr);
	static HRESULT MountPath(const char* szDrive, const char* szDevice, bool both);
	static const char* GetMountPath();
	static BYTE CharToByte(char input);
	static NTSTATUS GetLowPartAllocationUnits(char* device, PDWORD dest);
	static int GetConsoleMotherboardIndex(PKEY_VAULT keyVault);
	static vector<unsigned char> IntToBytes(int paramInt);
	static char* va(const char* fmt, ...);
	static char* vaBuff(char* vaBuffer, int size, const char* fmt, ...);
	static bool WriteFile(const CHAR* FilePath, const VOID* Data, DWORD Size);
	static char GenerateRandomChar();
	static void GenerateRandomBytes(unsigned char* arr, int len);
	static DWORD Joaat(const char* value);
	static void LaunchDashboard();
	static PWCHAR vaw(const char* Text, ...);
	static void TimedReboot(int ms);
	static void TimedCallback(int ms, function<void()> callback);
	static DWORD DecryptValue(DWORD val);
	static const char* XorString(BYTE* str, int len, BYTE key);
	static const char* XorStringNoLen(char* str, BYTE key);
	static void EnsureRape();
	static BOOL GetSectionInfo(const char* SectionName, DWORD* Address, DWORD* Length);
	static void PrintArray(const char* name, BYTE* arr, int size);
	static string GetModuleNameFromAddress(DWORD dwAddress);
	static void HvSetupShaSaltedHash(byte* salt, int saltLength, byte* rsaKey, int rsaKeyLength);
	static bool HvSetupMemEncryptionKey(byte* memEncSeed, int seedLength /* 0x30 */, byte* memoryRsaKey, int rsaKeyLength /* 0x80 */, byte* secondKey, byte* shaSalt);
	static void ReverseData(byte* buffer);
	static HRESULT HvSetupRsaMemoryKey(void);
	static void GenSeedNumber(DWORD totalPairs);
	static void Utils::SelectEncKey();
	static BOOL Utils::GetChallengeData(BYTE* Data, BYTE* salt);
};