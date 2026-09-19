// SilverFoxShell.cpp — Win11 右键「一级菜单」扩展：用银狐主防查杀
// 机制：稀疏包 + PackagedCom（SurrogateServer 经 dllhost 加载本 DLL）+ IExplorerCommand。
// 不依赖 ATL；字符串必须 SHStrDup/CoTaskMemAlloc（shell 用 CoTaskMemFree 释放，严禁 SysAllocString）；
// 由 AppxManifest.xml 声明 com:Class Id（CLSID）与本 DLL 的 ThreadingModel=STA。
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _WIN32_WINNT 0x0A00
#define WINVER 0x0A00
#include <windows.h>
#include <shellapi.h>
#include <shobjidl.h>
#include <shlwapi.h>
#include <new>
#include <string>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "uuid.lib")

// ================================================================ 常量
// 与 AppxManifest.xml 中 com:Class Id、desktop5:Verb Clsid 保持一致
static const CLSID CLSID_ProbeCommand = {0x860B45D8, 0x4E6A, 0x4F29, {0x9A, 0x5C, 0x7D, 0x0E, 0x3A, 0x1F, 0x8B, 0x42}};
// 规范化名（GetCanonicalName 返回，可任意但须稳定）
static const GUID  GUID_Canonical   = {0x860B45D8, 0x4E6A, 0x4F29, {0x9A, 0x5C, 0x7D, 0x0E, 0x3A, 0x1F, 0x8B, 0x42}};

static volatile LONG g_locks = 0;

static LPWSTR AllocStr(const wchar_t* s) {
    if (!s) return nullptr;
    size_t n = wcslen(s);
    LPWSTR p = (LPWSTR)CoTaskMemAlloc((n + 1) * sizeof(wchar_t));
    if (p) wcscpy_s(p, n + 1, s);
    return p;
}

// 定位服务端主程序（安装目录固定：%ProgramFiles%\SilverFoxGuard）
static std::wstring GuardExePath() {
    wchar_t pf[MAX_PATH] = {0};
    if (GetEnvironmentVariableW(L"ProgramFiles", pf, MAX_PATH) == 0) return L"";
    return std::wstring(pf) + L"\\SilverFoxGuard\\SilverFoxGuardSvc.exe";
}

// ================================================================ IExplorerCommand
class CProbeCommand final : public IExplorerCommand {
    LONG m_ref = 1;
public:
    // ---- IUnknown ----
    STDMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        *ppv = nullptr;
        if (riid == IID_IUnknown || riid == IID_IExplorerCommand) {
            *ppv = static_cast<IExplorerCommand*>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }
    STDMETHODIMP_(ULONG) AddRef() override { return (ULONG)InterlockedIncrement(&m_ref); }
    STDMETHODIMP_(ULONG) Release() override {
        LONG r = InterlockedDecrement(&m_ref);
        if (r == 0) delete this;
        return (ULONG)r;
    }
    // ---- IExplorerCommand ----
    STDMETHODIMP GetTitle(IShellItemArray*, LPWSTR* ppszName) override {
        if (!ppszName) return E_POINTER;
        *ppszName = AllocStr(L"用银狐主防查杀");
        return *ppszName ? S_OK : E_OUTOFMEMORY;
    }
    STDMETHODIMP GetIcon(IShellItemArray*, LPWSTR* ppszIcon) override {
        if (!ppszIcon) return E_POINTER;
        std::wstring e = GuardExePath();
        *ppszIcon = e.empty() ? nullptr : AllocStr((e + L",0").c_str());
        return *ppszIcon ? S_OK : E_FAIL;
    }
    STDMETHODIMP GetToolTip(IShellItemArray*, LPWSTR*) override { return E_NOTIMPL; }
    STDMETHODIMP GetCanonicalName(GUID* pguid) override {
        if (!pguid) return E_POINTER;
        *pguid = GUID_Canonical;
        return S_OK;
    }
    STDMETHODIMP GetState(IShellItemArray*, BOOL, EXPCMDSTATE* pcmd) override {
        if (!pcmd) return E_POINTER;
        *pcmd = ECS_ENABLED;
        return S_OK;
    }
    STDMETHODIMP GetFlags(EXPCMDFLAGS* pflags) override {
        if (!pflags) return E_POINTER;
        *pflags = ECF_DEFAULT;
        return S_OK;
    }
    STDMETHODIMP EnumSubCommands(IEnumExplorerCommand** ppEnum) override {
        if (ppEnum) *ppEnum = nullptr;
        return E_NOTIMPL;
    }
    // 对选中文件启动：SilverFoxGuardSvc.exe --probe --file="<path>"
    STDMETHODIMP Invoke(IShellItemArray* psia, IBindCtx*) override {
        if (!psia) return E_INVALIDARG;
        std::wstring exe = GuardExePath();
        if (exe.empty()) return E_FAIL;
        DWORD n = 0;
        if (FAILED(psia->GetCount(&n)) || n == 0) return S_OK;
        for (DWORD i = 0; i < n; ++i) {
            IShellItem* si = nullptr;
            if (FAILED(psia->GetItemAt(i, &si)) || !si) continue;
            PWSTR p = nullptr;
            if (FAILED(si->GetDisplayName(SIGDN_FILESYSPATH, &p)))
                si->GetDisplayName(SIGDN_DESKTOPABSOLUTEPARSING, &p);
            if (p) {
                std::wstring args = L"--probe --file=\"" + std::wstring(p) + L"\"";
                ShellExecuteW(nullptr, L"open", exe.c_str(), args.c_str(), nullptr, SW_HIDE);
                CoTaskMemFree(p);
            }
            si->Release();
        }
        return S_OK;
    }
};

// ================================================================ 类工厂
class CProbeFactory final : public IClassFactory {
    LONG m_ref = 1;
public:
    STDMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        *ppv = nullptr;
        if (riid == IID_IUnknown || riid == IID_IClassFactory) {
            *ppv = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }
    STDMETHODIMP_(ULONG) AddRef() override { return (ULONG)InterlockedIncrement(&m_ref); }
    STDMETHODIMP_(ULONG) Release() override {
        LONG r = InterlockedDecrement(&m_ref);
        if (r == 0) delete this;
        return (ULONG)r;
    }
    STDMETHODIMP CreateInstance(IUnknown* outer, REFIID riid, void** ppv) override {
        if (outer) return CLASS_E_NOAGGREGATION;
        CProbeCommand* obj = new (std::nothrow) CProbeCommand();
        if (!obj) return E_OUTOFMEMORY;
        HRESULT hr = obj->QueryInterface(riid, ppv);
        obj->Release();
        return hr;
    }
    STDMETHODIMP LockServer(BOOL fLock) override {
        if (fLock) InterlockedIncrement(&g_locks);
        else InterlockedDecrement(&g_locks);
        return S_OK;
    }
};

// ================================================================ 导出
// 用链接器 EXPORT pragma 避免与 combaseapi.h 已有原型冲突（STDAPI=EXTERN_C+__stdcall）
#pragma comment(linker, "/EXPORT:DllGetClassObject")
#pragma comment(linker, "/EXPORT:DllCanUnloadNow")

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv) {
    if (rclsid != CLSID_ProbeCommand) return CLASS_E_CLASSNOTAVAILABLE;
    CProbeFactory* f = new (std::nothrow) CProbeFactory();
    if (!f) return E_OUTOFMEMORY;
    HRESULT hr = f->QueryInterface(riid, ppv);
    f->Release();
    return hr;
}

STDAPI DllCanUnloadNow(void) {
    return (g_locks == 0) ? S_OK : S_FALSE;
}