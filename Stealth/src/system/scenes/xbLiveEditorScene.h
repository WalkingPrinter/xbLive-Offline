#pragma once

class xbLiveEditorScene : CXuiSceneImpl {
public:
	xbLiveEditorScene() {}
	~xbLiveEditorScene() {}

	static xbLiveEditorScene& getInstance() {
		static xbLiveEditorScene singleton;
		return singleton;
	}

	XUI_IMPLEMENT_CLASS(xbLiveEditorScene, L"scn_xbLive", XUI_CLASS_SCENE)
		XUI_BEGIN_MSG_MAP()
		XUI_ON_XM_NOTIFY_PRESS(OnPress)
		XUI_ON_XM_INIT(OnInit)
		XUI_ON_XM_ENTER_TAB(OnEnterTab)
		XUI_END_MSG_MAP()

	DWORD OnEnterTab(BOOL& bHandled);
	DWORD OnInit(XUIMessageInit *pInitData, BOOL& bHandled);
	DWORD OnPress(HXUIOBJ hObjPressed, BOOL& bHandled);
	DWORD InitializeChildren();
};