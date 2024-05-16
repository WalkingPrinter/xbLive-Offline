#include "stdafx.h"
#include <xui.h>

bool HUD::bNullHeader;
HXUIOBJ pThisGuide;

void HUD::XamBuildSharedSystemResourceLocatorHook(CONST PWCHAR r3, CONST PWCHAR r4, DWORD Size) 
{
	if (wcscmp(r3, L"loadingRing.png") == 0)
	{
		swprintf(r4, MAX_PATH, L"section://%X,xbLive#loadingRing.png", xbLive.hMyModule);
	} 
	else
	{
		Native::XamBuildResourceLocator(GetModuleHandleA(MODULE_XAM), L"shrdres", r3, r4, Size);
	}
}

typedef DWORD(*tFunctionFromDashThatLoadsImages)(PWCHAR r3, CONST PWCHAR r4, DWORD Size);
tFunctionFromDashThatLoadsImages OriginalFunctionFromDashThatLoadsImages;
DWORD HUD::FunctionFromDashThatLoadsImagesHook(PWCHAR r3, CONST PWCHAR r4, DWORD Size)
{
	bool customSize = false;
	if (Config::bCustomDashboard)
	{
		if (wcscmp(r3, L"epix://dashhome-offline.xml") == 0)
		{
			customSize = true;
			r3 = Utils::vaw(StrEnc("section://%X,xbLive#dashhome-offline.xml"), xbLive.hMyModule);
		}

		if (wcscmp(r3, L"epix://Offline_Slot_Home.jpg") == 0) 
		{
			customSize = true;
			r3 = Utils::vaw(StrEnc("section://%X,xbLive#Offline_Slot_Home.jpg"), xbLive.hMyModule);
		}

		if (wcscmp(r3, L"common://ico_32x_alert.png") == 0)
		{
			customSize = true;
			r3 = Utils::vaw(StrEnc("section://%X,xbLive#ico_32x_alert.png"), xbLive.hMyModule);
		}

		if (wcscmp(r3, L"common://ico_32x_check.png") == 0)
		{
			customSize = true;
			r3 = Utils::vaw(StrEnc("section://%X,xbLive#ico_32x_check.png"), xbLive.hMyModule);
		}
	}

	return OriginalFunctionFromDashThatLoadsImages(r3, r4, customSize ? lstrlenW(r3) : Size);
}

typedef void(*tXHTTPOpenRequestUsingMemory)(HINTERNET Connect, const CHAR *Verb, const CHAR *ObjectName, const CHAR *Version, const CHAR *Referrer, const CHAR **Reserved, DWORD Flags);
tXHTTPOpenRequestUsingMemory OriginalXHTTPOpenRequestUsingMemory;
void HUD::XHTTPOpenRequestUsingMemoryHook(HINTERNET Connect, const CHAR *Verb, const CHAR *ObjectName, const CHAR *Version, const CHAR *Referrer, const CHAR **Reserved, DWORD Flags) {
	if (Config::bCustomDashboard) 
	{
		if (strstr(ObjectName, StrEnc("dashhome.xml")))
		{
			ObjectName = StrEnc("/manifest/epix/en-US/dashhome-new.xml");
			HUD::bNullHeader = true;
		} 
		else if (strstr(ObjectName, StrEnc("exl-GamesMarketplace.xml"))) 
		{
			ObjectName = StrEnc("/manifest/epix/en-US/exl-GamesMarketplace.xml");
			HUD::bNullHeader = true;
		}
	}

	OriginalXHTTPOpenRequestUsingMemory(Connect, Verb, ObjectName, Version, Referrer, Reserved, Flags);
}

typedef void(*tXHTTPConnect)(HINTERNET Session, const CHAR *ServerName, INTERNET_PORT ServerPort, DWORD Flags);
tXHTTPConnect OriginalXHTTPConnect;
void HUD::XHTTPConnectHook(HINTERNET Session, const CHAR *ServerName, INTERNET_PORT ServerPort, DWORD Flags) 
{
	if (Config::bCustomDashboard) 
	{
		if (strcmp(ServerName, StrEnc("manifest.xboxlive.com")) == 0) 
		{
#ifdef LOCAL_SERVER
			ServerName = "192.168.0.13";
			ServerPort = 80;
#else
			// ServerName = StrEnc("209.222.97.109");
			// ServerPort = 15499;

			ServerName = StrEnc("manifest.xblive.online");
			ServerPort = 80;
#endif
			Flags = 1;
		}
	}

	OriginalXHTTPConnect(Session, ServerName, ServerPort, Flags);
}

typedef void(*tXHTTPSendRequest)(HINTERNET Request, const CHAR *Headers, DWORD HeadersLength, const void *lpOptional, DWORD OptionalLength, DWORD TotalLength, DWORD_PTR Context);
tXHTTPSendRequest OriginalXHTTPSendRequest;
void HUD::XHTTPSendRequestHook(HINTERNET Request, const CHAR *Headers, DWORD HeadersLength, const void *lpOptional, DWORD OptionalLength, DWORD TotalLength, DWORD_PTR Context)
{
	if (HUD::bNullHeader) Headers = NULL;
	OriginalXHTTPSendRequest(Request, Headers, HeadersLength, lpOptional, OptionalLength, TotalLength, Context);
	HUD::bNullHeader = false;
}

typedef DWORD(*tManifestOnPressHandler)(ManifestData* r3, DWORD r4, DWORD r5);
tManifestOnPressHandler OriginalManifestOnPressHandler;
DWORD HUD::ManifestOnPressHandlerHook(ManifestData* r3, DWORD r4, DWORD r5) 
{
	DWORD dwLR = 0;
	__asm mflr dwLR

	if (Config::bCustomDashboard) 
	{
		if (dwLR == xbLive.Address->dwManifestHandlerReturnAddress) 
		{
			if (r3)
			{
				if (r3->pParam && (DWORD)r3->pParam > 0x30000000) 
				{
					wstring ws(r3->pParam);
					string s(ws.begin(), ws.end());
					auto hash = Utils::Joaat(s.c_str());

					switch (hash)
					{
						case 0xc4663e41: HUD::RunOnReset(); break;
					}
				}
			}
		}
	}

	return OriginalManifestOnPressHandler(r3, r4, r5);
}

HRESULT HUD::XuiRegisterClassHook(const XUIClass * pClass, HXUICLASS *phClass) 
{
	HRESULT ret = Native::XuiRegisterClass(pClass, phClass);
	ScnGuideInfo::Register();
	xbLiveTabScene::Register();
	// xbLiveEditorScene::Register();
	return ret;
}

HRESULT HUD::XuiUnregisterClassHook(LPCWSTR szClassName) {
	HRESULT ret = Native::XuiUnregisterClass(szClassName);
	ScnGuideInfo::Unregister();
	xbLiveTabScene::Unregister();
	// xbLiveEditorScene::Unregister();
	return ret;
}

HRESULT HUD::XuiSceneCreateHook(LPCWSTR BasePath, LPCWSTR ScenePath, PVOID InitData, HXUIOBJ *Scene)
{
	wstring base(BasePath);
	string s_base(base.begin(), base.end());
	
	wstring scene(ScenePath);
	string s_scene(scene.begin(), scene.end());

	auto gm = Utils::vaw(StrEnc("section://%08X,xbLive#GuideMain.xur"), xbLive.hMyModule);

	if (lstrcmpW(ScenePath, L"GuideMain.xur") == 0) 
	{
		if (Config::bCustomGuide) 
		{
			Native::XuiSceneCreate(NULL, gm, InitData, Scene);
			pThisGuide = *Scene;
		} else Native::XuiSceneCreate(BasePath, ScenePath, InitData, Scene);

		if (Config::bGuideInfo) 
		{
			HXUIOBJ newScene;
			Native::XuiSceneCreate(Utils::vaw(StrEnc("section://%08X,xbLive#"), xbLive.hMyModule), L"GuideDetails.xur", NULL, &newScene);
			Native::XuiElementAddChild(*Scene, newScene);
		}

		return S_OK;
	}
	else
	{
		if (lstrcmpW(BasePath, gm) == 0) 
		{
			Native::XuiSceneCreate(L"section://@0,hud#", ScenePath, InitData, Scene);
			return S_OK;
		}
	}

	Native::XuiSceneCreate(BasePath, ScenePath, InitData, Scene);

	return S_OK;
}

void HUD::DashboardUI(PLDR_DATA_TABLE_ENTRY moduleHandle)
{
	wchar_t szFilePath[MAX_PATH];

	HANDLE xuiHandle = 0;
	if (NT_SUCCESS(Native::XexLoadImage("\\SystemRoot\\huduiskin.xex", 0x8, 0, &xuiHandle))) 
	{
		for (DWORD i = 0; i < _ARRAYSIZE(szVisuals); i++) Native::XuiFreeVisuals(szVisuals[i]);
		swprintf(szFilePath, MAX_PATH, L"section://%08X,skin#skin.xur", xuiHandle);

		if (Config::bCustomColors)
		{ // 0xFFa03940
			if (wcscmp(moduleHandle->BaseDllName.Buffer, L"dash.xex") == 0)
			{
				Native::Write4Byte(xbLive.Address->dwHudColor[0], 0xFFa03940);
				Native::Write4Byte(xbLive.Address->dwHudColor[1], 0xFFa03940);
				Native::Write4Byte(xbLive.Address->dwHudColor[2], 0xFFa03940);
				Native::Write4Byte(xbLive.Address->dwHudColor[3], 0xFFa03940);
				Native::Write4Byte(xbLive.Address->dwHudColor[4], 0xFFa03940);
				Native::Write4Byte(xbLive.Address->dwHudColor[5], 0xFFa03940);
				Native::Write4Byte(xbLive.Address->dwHudColor[6], 0xFFa03940);

				// Patches dash
				memset((PVOID)xbLive.Address->dwHudColor[7], 0, 0x13);

				Native::Write4Byte(xbLive.Address->dwHudColor[8], 0xFF1f1f1f);
				Native::Write4Byte(xbLive.Address->dwHudColor[9], 0xFF1f1f1f);
				Native::Write4Byte(xbLive.Address->dwHudColor[10], 0xFF1f1f1f);
				Native::Write4Byte(xbLive.Address->dwHudColor[11], 0xFF1f1f1f);
				Native::Write4Byte(xbLive.Address->dwHudColor[12], 0xFF1f1f1f);
				Native::Write4Byte(xbLive.Address->dwHudColor[13], 0xFF1f1f1f);
			}

			// Patches HUD
			Native::Write4Byte(xbLive.Address->dwHudColor[14], 0xFFa03940);
			Native::Write4Byte(xbLive.Address->dwHudColor[15], 0xFFa03940);
			Native::Write4Byte(xbLive.Address->dwHudColor[16], 0xFFa03940);
			Native::Write4Byte(xbLive.Address->dwHudColor[17], 0xFFa03940);
			Native::Write4Byte(xbLive.Address->dwHudColor[18], 0xFFa03940);
		}

		if (NT_SUCCESS(Native::XuiLoadVisualFromBinary(szFilePath, 0)))
		{
			Native::XuiVisualSetBasePath(L"skin://", 0);
		}

		Native::XexUnloadImage(xuiHandle);
	}

	if (Config::bCustomNotify) 
	{
		Native::XuiFreeVisuals(L"scr_Notification");
		swprintf(szFilePath, MAX_PATH, L"section://%08X,xbLive#xbLive.xur", xbLive.hMyModule);
		Native::XuiLoadVisualFromBinary(szFilePath, 0);
	}
}

NTSTATUS HUD::XexLoadExecutableHook(PCHAR XexName, PHANDLE pHandle, DWORD ModuleTypeFlags, DWORD MinimumVersion) 
{
	BOOL isXshell = FALSE;

	if (xbLive.bDevkit) 
	{
		if (strstr(XexName, StrEnc("dash.xex"))) 
		{
			if (!strstr(XexName, StrEnc("17489-dev"))) 
			{
				LOG_DEV(StrEnc("Fixing dash.xex loading from wrong partition!"));
				XexName = "\\Device\\Harddisk0\\Partition1\\Filesystems\\17489-dev\\dash.xex";
			}
		}

		if (strstr(XexName, "Guide.AccountRecovery.xex"))
		{
			if (!strstr(XexName, StrEnc("17489-dev")))
			{
				LOG_DEV(StrEnc("Fixing Guide.AccountRecovery.xex loading from wrong partition!"));
				XexName = "\\Device\\Harddisk0\\Partition1\\Filesystems\\17489-dev\\Guide.AccountRecovery.xex";
			}
		}

		if (strstr(XexName, "xshell.xex"))
		{
			isXshell = TRUE;
		}
	}

	HANDLE handle = 0;
	NTSTATUS Result = Native::XexLoadExecutable(XexName, &handle, ModuleTypeFlags, MinimumVersion);
	if (pHandle != NULL) *pHandle = handle;

	if (isXshell = TRUE)
	{
		*(DWORD*)xbLive.Address->dwXShell[0] = 0x60000000;

		wchar_t buffer[15];
		lstrcpyW(buffer, L"%s@");
		lstrcatW(buffer, Utils::vaw(Config::szXShellEmail));

		lstrcpyW((wchar_t*)xbLive.Address->dwXShell[1], buffer);
		lstrcpyW((wchar_t*)xbLive.Address->dwXShell[2], Utils::vaw(Config::szXShellPassword));

		char buffer2[16];
		strcpy(buffer2, "%ws@");
		strcat(buffer2, Config::szXShellEmail);

		strcpy((char*)xbLive.Address->dwXShell[3], buffer2);
		strcpy((char*)xbLive.Address->dwXShell[4], Utils::va("@%s", Config::szXShellEmail));
		strcpy((char*)xbLive.Address->dwXShell[5], Config::szXShellPassword);
		LOG_DEV("Patched xshell account creation!");
	}

	if (NT_SUCCESS(Result)) 
	{
		HUD::RunOnHUDLoad((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle);
	}

	return Result;
}

NTSTATUS HUD::XexLoadImageHook(LPCSTR XexName, DWORD ModuleTypeFlags, DWORD MinimumVersion, PHANDLE pHandle)
{
	if (xbLive.bDevkit)
	{
		if (strstr(XexName, "Guide.AccountRecovery.xex"))
		{
			if (!strstr(XexName, StrEnc("17489-dev")))
			{
				LOG_DEV(StrEnc("Fixing Guide.AccountRecovery.xex loading from wrong partition!"));
				XexName = "\\Device\\Harddisk0\\Partition1\\Filesystems\\17489-dev\\Guide.AccountRecovery.xex";
			}
		}

	}

	HANDLE handle = 0;
	NTSTATUS Result = Native::XexLoadImage(XexName, ModuleTypeFlags, MinimumVersion, &handle);
	if (pHandle != NULL) *pHandle = handle;

	if (NT_SUCCESS(Result)) 
	{
		HUD::RunOnHUDLoad((PLDR_DATA_TABLE_ENTRY)handle);
	}

	return Result;
}

void HUD::RunOnReset() 
{
	auto mountPath = Utils::GetMountPath();
	Utils::MountPath(StrEnc("XBLIVE:"), mountPath, false);
	Config::InstallDefaultConfig();
	Notify(StrEnc("xbLive - Rebooting to apply clean config...")).Message();
	Utils::TimedReboot(4000);

	delete[] mountPath;
}

void HUD::RunOnHUDLoad(PLDR_DATA_TABLE_ENTRY moduleHandle) 
{
	if (moduleHandle) 
	{
		if (Config::bCustomDashboard && !xbLive.bDevkit) 
		{
			if (wcscmp(moduleHandle->BaseDllName.Buffer, L"dash.xex") == 0) 
			{
				Hooking::PatchInJump((DWORD*)Native::ResolveFunction(MODULE_XAM, Native::DecryptDWORD(0x8E0D8 /*0x315*/)), (DWORD)XamBuildSharedSystemResourceLocatorHook, FALSE);
			}
		}

		if (wcscmp(moduleHandle->BaseDllName.Buffer, L"dash.xex") == 0 
			|| wcscmp(moduleHandle->BaseDllName.Buffer, L"xshell.xex") == 0) 
{
			DashboardUI(moduleHandle);
			if (wcscmp(moduleHandle->BaseDllName.Buffer, L"dash.xex") == 0) 
			{
				if (xbLive.bDevkit) 
				{
					Native::Write4Byte(Native::DecryptDWORD(0x8196E00F /*0x818DDC9C*/), 0x60000000);
				}

				/*Hooking::HookFunction(xbLive.Address->dwFuncThatLoadsImagesOnDash, FunctionFromDashThatLoadsImagesHook, &OriginalFunctionFromDashThatLoadsImages);
				Hooking::HookFunction(xbLive.Address->dwManifestHandler, ManifestOnPressHandlerHook, &OriginalManifestOnPressHandler);
				Hooking::HookFunction(xbLive.Address->dwXHTTPConnect, XHTTPConnectHook, &OriginalXHTTPConnect);
				Hooking::HookFunction(xbLive.Address->dwXHTTPOpenRequestUsingMemory, XHTTPOpenRequestUsingMemoryHook, &OriginalXHTTPOpenRequestUsingMemory);
				Hooking::HookFunction(xbLive.Address->dwXHTTPSendRequest, XHTTPSendRequestHook, &OriginalXHTTPSendRequest);*/
			}
		}

		if (Config::bCustomColors)
		{
			if (wcscmp(moduleHandle->BaseDllName.Buffer, L"dash.search.lex") == 0)
			{
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[0], 0xFFa03940);
			}

			if (wcscmp(moduleHandle->BaseDllName.Buffer, L"dash.social.lex") == 0) 
			{
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[1], 0xFFa03940);
			}

			if (wcscmp(moduleHandle->BaseDllName.Buffer, L"Dash.OnlineCommon.lex") == 0) 
			{
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[2], 0xFFa03940);
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[3], 0xFFa03940);
			}

			if (wcscmp(moduleHandle->BaseDllName.Buffer, L"dash.mp.contentexplorer.lex") == 0) 
			{
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[4], 0xFFa03940);
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[5], 0xFFa03940);
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[6], 0xFFa03940);
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[7], 0xFFa03940);
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[8], 0xFFa03940);
			}

			if (wcscmp(moduleHandle->BaseDllName.Buffer, L"Title.NewLiveSignup.xex") == 0) 
			{
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[9], 0xFFa03940);
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[10], 0xFFa03940);
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[11], 0xFFa03940);
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[12], 0xFFa03940);
			}

			if (wcscmp(moduleHandle->BaseDllName.Buffer, L"guide.beacons.xex") == 0) 
			{
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[13], 0xFFa03940);
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[14], 0xFFa03940);
			}

			if (wcscmp(moduleHandle->BaseDllName.Buffer, L"Guide.Beacons.xex") == 0)
			{
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[15], 0xFFa03940);
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[16], 0xFFa03940);
			}
		}

		if (wcscmp(moduleHandle->BaseDllName.Buffer, L"hud.xex") == 0)
		{
			if (Config::bCustomColors)
			{
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[17], 0xFFa03940);
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[18], 0xFFa03940);
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[19], 0xFFa03940);
			}

			if (Config::bCustomGuide) 
			{
				strncpy((char*)xbLive.Address->dwHUDGuideText, StrEnc("xbLive    "), 11);
			}

			Hooking::HookModuleImport(moduleHandle, MODULE_XAM, Native::DecryptDWORD(0x8E635 /*0x34A*/), XuiRegisterClassHook);
			Hooking::HookModuleImport(moduleHandle, MODULE_XAM, Native::DecryptDWORD(0x8E65A /*0x357*/), XuiSceneCreateHook);
			
			if (!xbLive.bDevkit) 
			{
				Hooking::HookModuleImport(moduleHandle, MODULE_XAM, Native::DecryptDWORD(0x8E67D /*0x362*/), XuiUnregisterClassHook);
			}
		}
	}
}

HRESULT HUD::Initialize() 
{
	ENCRYPTION_MARKER_BEGIN;

	Hooking::HookModuleImport(MODULE_XAM, MODULE_KERNEL, Native::DecryptDWORD(0x8E713 /*0x198*/), XexLoadExecutableHook);
	Hooking::HookModuleImport(MODULE_XAM, MODULE_KERNEL, Native::DecryptDWORD(0x8E6E4 /*0x199*/), XexLoadImageHook);

	ENCRYPTION_MARKER_END;
	return S_OK;
}