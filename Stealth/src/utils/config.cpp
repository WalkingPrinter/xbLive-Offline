#include "stdafx.h"

map<DWORD, bool> Config::Cheats;
map<DWORD, bool> Config::Bypasses;

bool Config::bBypassAllUI;
bool Config::bCustomColors;
bool Config::bCustomDashboard;
bool Config::bCustomGuide;
bool Config::bGuideInfo;
bool Config::bCustomNotify;
bool Config::bUsingNoKV;
char Config::szXShellEmail[0xC];
char Config::szXShellPassword[0xB];
int Config::PairNum;

void Config::UpdateConfig() {
	IniParse parse("XBLIVE:\\xbLive.ini");
	if (parse.IsGood()) {
		FILE* file = fopen("XBLIVE:\\xbLive.ini", StrEnc("w+"));
		if (file) {
			parse.SetBool(StrEnc("User Interface"), StrEnc("Bypass all"), bBypassAllUI);
			parse.SetBool(StrEnc("User Interface"), StrEnc("Custom Colors"), bCustomColors);
			parse.SetBool(StrEnc("User Interface"), StrEnc("Custom Dashboard"), bCustomDashboard);
			parse.SetBool(StrEnc("User Interface"), StrEnc("Custom Guide"), bCustomGuide);
			parse.SetBool(StrEnc("User Interface"), StrEnc("Guide Info"), bGuideInfo);
			parse.SetBool(StrEnc("User Interface"), StrEnc("Custom Notify"), bCustomNotify);

			parse.SetBool(StrEnc("Cheats"), StrEnc("COD WAW"), Cheats[0x4156081C]);
			parse.SetBool(StrEnc("Cheats"), StrEnc("COD MW1"), Cheats[0x415607E6]);
			parse.SetBool(StrEnc("Cheats"), StrEnc("COD MW2"), Cheats[0x41560817]);
			parse.SetBool(StrEnc("Cheats"), StrEnc("COD MW3"), Cheats[0x415608CB]);
			parse.SetBool(StrEnc("Cheats"), StrEnc("COD BO1"), Cheats[0x41560855]);
			parse.SetBool(StrEnc("Cheats"), StrEnc("COD BO2"), Cheats[0x415608C3]);
			parse.SetBool(StrEnc("Cheats"), StrEnc("COD BO3"), Cheats[0x4156091D]);
			parse.SetBool(StrEnc("Cheats"), StrEnc("COD AW"), Cheats[0x41560914]);
			parse.SetBool(StrEnc("Cheats"), StrEnc("COD GHOST"), Cheats[0x415608FC]);
			parse.SetBool(StrEnc("Cheats"), StrEnc("GTAV"), Cheats[0x545408A7]);

			parse.SetBool(StrEnc("Bypasses"), StrEnc("COD BO2"), Bypasses[0x415608C3]);
			parse.SetBool(StrEnc("Bypasses"), StrEnc("COD BO3"), Bypasses[0x4156091D]);
			parse.SetBool(StrEnc("Bypasses"), StrEnc("COD AW"), Bypasses[0x41560914]);
			parse.SetBool(StrEnc("Bypasses"), StrEnc("COD GHOST"), Bypasses[0x415608FC]);
			parse.SetBool(StrEnc("Bypasses"), StrEnc("GTAV"), Bypasses[0x545408A7]);

			parse.SetBool(StrEnc("Misc"), StrEnc("No KV Mode"), bUsingNoKV);
			parse.SetInt(StrEnc("Misc"), StrEnc("Pair Numbers"), PairNum);
			
			parse.SetString(StrEnc("XDK"), StrEnc("XShell Account Creation Email"), szXShellEmail);
			parse.SetString(StrEnc("XDK"), StrEnc("XShell Account Creation Password"), szXShellPassword);

			auto sections = parse.GetSections();
			for (int i = 0; i < sections.size(); i++) {
				fprintf(file, StrEnc("[%s]\n"), sections[i].c_str());

				auto data = parse.GetDataFromSection(sections[i].c_str());
				for (int j = 0; j < data.size(); j++) {
					fprintf(file, StrEnc("%s = %s\n"), data[j].first.c_str(), data[j].second.c_str());
				}

				data.clear();

				if (i != sections.size() - 1) {
					fprintf(file, StrEnc("\n"));
				}
			}

			sections.clear();
		}

		parse.ItemMap.clear();

		fclose(file);
	}
}

void Config::InstallDefaultConfig() {
	IniParse parse;
	parse.SetBool(StrEnc("User Interface"), StrEnc("Bypass all"), false);
	parse.SetBool(StrEnc("User Interface"), StrEnc("Custom Colors"), true);
	parse.SetBool(StrEnc("User Interface"), StrEnc("Custom Dashboard"), true);
	parse.SetBool(StrEnc("User Interface"), StrEnc("Custom Guide"), true);
	parse.SetBool(StrEnc("User Interface"), StrEnc("Guide Info"), true);
	parse.SetBool(StrEnc("User Interface"), StrEnc("Custom Notify"), true);

	parse.SetBool(StrEnc("Cheats"), StrEnc("COD WAW"), true);
	parse.SetBool(StrEnc("Cheats"), StrEnc("COD MW1"), true);
	parse.SetBool(StrEnc("Cheats"), StrEnc("COD MW2"), true);
	parse.SetBool(StrEnc("Cheats"), StrEnc("COD MW3"), true);
	parse.SetBool(StrEnc("Cheats"), StrEnc("COD BO1"), true);
	parse.SetBool(StrEnc("Cheats"), StrEnc("COD BO2"), true);
	parse.SetBool(StrEnc("Cheats"), StrEnc("COD BO3"), true);
	parse.SetBool(StrEnc("Cheats"), StrEnc("COD AW"), true);
	parse.SetBool(StrEnc("Cheats"), StrEnc("COD GHOST"), true);
	parse.SetBool(StrEnc("Cheats"), StrEnc("GTAV"), true);

	parse.SetBool(StrEnc("Bypasses"), StrEnc("COD BO2"), true);
	parse.SetBool(StrEnc("Bypasses"), StrEnc("COD BO3"), true);
	parse.SetBool(StrEnc("Bypasses"), StrEnc("COD AW"), true);
	parse.SetBool(StrEnc("Bypasses"), StrEnc("COD GHOST"), true);
	parse.SetBool(StrEnc("Bypasses"), StrEnc("GTAV"), true);

	parse.SetBool(StrEnc("Misc"), StrEnc("No KV Mode"), false);
	parse.SetInt(StrEnc("Misc"), StrEnc("Pair Numbers"), 5);

	parse.SetString(StrEnc("XDK"), StrEnc("XShell Account Creation Email"), StrEnc("chammy.info"));
	parse.SetString(StrEnc("XDK"), StrEnc("XShell Account Creation Password"), StrEnc("xblive"));

	FILE* file = fopen("XBLIVE:\\xbLive.ini", StrEnc("w+"));
	if (file) {
		auto sections = parse.GetSections();
		for (int i = 0; i < sections.size(); i++) {
			fprintf(file, StrEnc("[%s]\n"), sections[i].c_str());

			auto data = parse.GetDataFromSection(sections[i].c_str());
			for (int j = 0; j < data.size(); j++) {
				fprintf(file, StrEnc("%s = %s\n"), data[j].first.c_str(), data[j].second.c_str());
			}

			data.clear();

			if (i != sections.size() - 1) {
				fprintf(file, StrEnc("\n"));
			}
		}

		sections.clear();

		fclose(file);
	}

	parse.ItemMap.clear();
}

HRESULT Config::Initialize() {
	ENCRYPTION_MARKER_BEGIN;

	CreateDirectoryA("XBLIVE:\\xbLive Cheat Cache\\", NULL);

	IniParse parse("XBLIVE:\\xbLive.ini");
	if (parse.IsGood()) {
		bBypassAllUI = parse.ReadBool(StrEnc("User Interface"), StrEnc("Bypass all"), false);
		if (!bBypassAllUI) {
			bCustomColors = parse.ReadBool(StrEnc("User Interface"), StrEnc("Custom Colors"), true);
			bCustomDashboard = parse.ReadBool(StrEnc("User Interface"), StrEnc("Custom Dashboard"), true);
			bCustomGuide = parse.ReadBool(StrEnc("User Interface"), StrEnc("Custom Guide"), true);
			bGuideInfo = parse.ReadBool(StrEnc("User Interface"), StrEnc("Guide Info"), true);
			bCustomNotify = parse.ReadBool(StrEnc("User Interface"), StrEnc("Custom Notify"), true);
		}

		bUsingNoKV = parse.ReadBool(StrEnc("Misc"), StrEnc("No KV Mode"), false);
		PairNum = parse.ReadInt(StrEnc("Misc"), StrEnc("Pair Numbers"), 5);

		Cheats[0x4156081C] = parse.ReadBool(StrEnc("Cheats"), StrEnc("COD WAW"), true);
		Cheats[0x415607E6] = parse.ReadBool(StrEnc("Cheats"), StrEnc("COD MW1"), true);
		Cheats[0x41560817] = parse.ReadBool(StrEnc("Cheats"), StrEnc("COD MW2"), true);
		Cheats[0x415608CB] = parse.ReadBool(StrEnc("Cheats"), StrEnc("COD MW3"), true);
		Cheats[0x41560855] = parse.ReadBool(StrEnc("Cheats"), StrEnc("COD BO1"), true);
		Cheats[0x415608C3] = parse.ReadBool(StrEnc("Cheats"), StrEnc("COD BO2"), true);
		Cheats[0x4156091D] = parse.ReadBool(StrEnc("Cheats"), StrEnc("COD BO3"), true);
		Cheats[0x41560914] = parse.ReadBool(StrEnc("Cheats"), StrEnc("COD AW"), true);
		Cheats[0x415608FC] = parse.ReadBool(StrEnc("Cheats"), StrEnc("COD GHOST"), true);
		Cheats[0x545408A7] = parse.ReadBool(StrEnc("Cheats"), StrEnc("GTAV"), true);

		Bypasses[0x415608C3] = parse.ReadBool(StrEnc("Bypasses"), StrEnc("COD BO2"), true);
		Bypasses[0x4156091D] = parse.ReadBool(StrEnc("Bypasses"), StrEnc("COD BO3"), true);
		Bypasses[0x41560914] = parse.ReadBool(StrEnc("Bypasses"), StrEnc("COD AW"), true);
		Bypasses[0x415608FC] = parse.ReadBool(StrEnc("Bypasses"), StrEnc("COD GHOST"), true);
		Bypasses[0x545408A7] = parse.ReadBool(StrEnc("Bypasses"), StrEnc("GTAV"), true);

		if (!Bypasses[0x415608C3]) LOG_DEV(StrEnc("Opting out of using COD BO2 bypasses!"));
		if (!Bypasses[0x4156091D]) LOG_DEV(StrEnc("Opting out of using COD BO3 bypasses!"));
		if (!Bypasses[0x41560914]) LOG_DEV(StrEnc("Opting out of using COD AW bypasses!"));
		if (!Bypasses[0x415608FC]) LOG_DEV(StrEnc("Opting out of using COD GHOST bypasses!"));
		if (!Bypasses[0x545408A7]) LOG_DEV(StrEnc("Opting out of using GTAV bypasses!"));

		auto email = parse.ReadString(StrEnc("XDK"), StrEnc("XShell Account Creation Email"), StrEnc("chammy.info"));
		auto pw = parse.ReadString(StrEnc("XDK"), StrEnc("XShell Account Creation Password"), StrEnc("xblive"));

		parse.ItemMap.clear();

		if (strlen(email) > 12)
			Notify(StrEnc("xbLive - XShell email is too long! Max chars: 12")).Message();
		else strcpy(szXShellEmail, email);

		if (strlen(pw) > 11)
			Notify(StrEnc("xbLive - XShell password is too long! Max chars: 11")).Message();
		else strcpy(szXShellPassword, pw);

		// re-cache
		UpdateConfig();
	} else {
		// create base file
		InstallDefaultConfig();

		// set default vars seeing how it only just now created the file
		bBypassAllUI = false;
		bCustomColors = true;
		bCustomDashboard = true;
		bCustomGuide = true;
		bGuideInfo = true;
		bCustomNotify = true;

		bUsingNoKV = false;

		Cheats[0x4156081C] = true;
		Cheats[0x415607E6] = true;
		Cheats[0x41560817] = true;
		Cheats[0x415608CB] = true;
		Cheats[0x41560855] = true;
		Cheats[0x415608C3] = true;
		Cheats[0x4156091D] = true;
		Cheats[0x41560914] = true;
		Cheats[0x415608FC] = true;
		Cheats[0x545408A7] = true;

		Bypasses[0x415608C3] = true;
		Bypasses[0x4156091D] = true;
		Bypasses[0x41560914] = true;
		Bypasses[0x415608FC] = true;
		Bypasses[0x545408A7] = true;

		strcpy(szXShellEmail, StrEnc("chammy.info"));
		strcpy(szXShellPassword, StrEnc("xblive"));
	}

	ENCRYPTION_MARKER_END;
	return S_OK;
}