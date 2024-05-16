#include "stdafx.h"

void TitleHooks::RunOnTitleLoad(PLDR_DATA_TABLE_ENTRY moduleHandle)
{
	if (moduleHandle && moduleHandle->BaseDllName.Buffer) 
	{
		char buffer[30];
		ZeroMemory(buffer, 30);
		wcstombs(buffer, moduleHandle->BaseDllName.Buffer, sizeof(buffer));

		if (!strstr(buffer, StrEnc("dash")) && !strstr(buffer, StrEnc("xshell"))) 
		{
			if (!Hooking::HookModuleImport(moduleHandle, MODULE_KERNEL, 407, SystemHooks::XexGetProcedureAddressHook)) 
			{
				LOG_PRINT(StrEnc("Failed to hook #fa1b79f7"));
			}

			if (!Hooking::HookModuleImport(moduleHandle, MODULE_KERNEL, 405, XexGetModuleHandleHook))
			{
				LOG_PRINT(StrEnc("Failed to hook #6d99575e"));
			}
		}
	}

	auto mountPath = Utils::GetMountPath();
	Utils::MountPath(StrEnc("XBLIVE:"), mountPath, true);
	delete[] mountPath;

	if (moduleHandle) 
	{
		XEX_EXECUTION_ID* executionId = (XEX_EXECUTION_ID*)RtlImageXexHeaderField(moduleHandle->XexHeaderBase, XEX_HEADER_EXECUTION_ID);
		if (!executionId)
		{
			LOG_DEV(StrEnc("Failed to get execution id!"));
			return;
		}

		AntiCheat::HandleTitle(moduleHandle, executionId->TitleID);
	}
}