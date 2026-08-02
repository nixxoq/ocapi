/*
 * PROJECT:     One-Core-API Compatibility Layer Shell Extension
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     CLayerUIPropPage implementation
 * COPYRIGHT:   Copyright 2015-2019 Mark Jansen (mark.jansen@reactos.org)
 */

#include "precomp.h"

#include <shlwapi.h>
#include <shellapi.h>
#include <shellutils.h>
#include <strsafe.h>
#include <apphelp.h>
#include <windowsx.h>
#include <commctrl.h>

#define ISOLATION_AWARE_ENABLED 1

#include <windows.h>
#include <uxtheme.h>

const GUID CLSID_CLayerUIPropPage = { 0x3c6a9f10, 0x3f75, 0x4a3f, { 0x81, 0x3b, 0x9e, 0x53, 0xf9, 0x12, 0xaa, 0xbb } };

#define GPLK_USER 1
#define GPLK_MACHINE 2
#define MAX_LAYER_LENGTH 256

#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

static struct {
    const PCWSTR Display;
    const PCWSTR Name;
} g_CompatModes[] = {
    { L"Windows 2000 (Service Pack 4)", L"5.0.2195.4.0.2.Service Pack 4" },
    { L"Windows XP (Service Pack 2)", L"5.1.2600.2.0.2.Service Pack 2" },
    { L"Windows XP (Service Pack 3)", L"5.1.2600.3.0.2.Service Pack 3" },
    { L"Windows Server 2003 (Service Pack 1))", L"5.2.3790.1.0.2.Service Pack 1" },
    { L"Windows Server 2003 (Service Pack 2)", L"5.2.3790.2.0.2.Service Pack 2" },
    { L"Windows Vista", L"6.0.6000.0.0.2." },
    { L"Windows Vista (Service Pack 1)", L"6.0.6001.1.0.2.Service Pack 1" },
    { L"Windows Vista (Service Pack 2)", L"6.0.6002.2.0.2.Service Pack 2" },
    { L"Windows 7 (Service Pack 1)", L"6.1.7601.1.0.2.Service Pack 1" },
    { L"Windows 8", L"6.2.9200.0.0.2." },
    { L"Windows 8.1", L"6.3.9600.0.0.2." },
    { L"Windows 10 1511", L"10.0.10586.0.0.2." },
    { L"Windows 10 1607", L"10.0.14393.0.0.2." },
    { L"Windows 10 1809", L"10.0.17763.0.0.2." },
    { L"Windows 10 22H2", L"10.0.19045.0.0.2." },
    { L"Windows 11 24H2", L"10.0.22600.0.0.2." },
    { NULL, NULL }
};

static struct {
    const PCWSTR Name;
    DWORD Id;
} g_Layers[] = {
    { L"256COLOR", IDC_CHKRUNIN256COLORS },
    { L"640X480", IDC_CHKRUNIN640480RES },
    { L"DISABLETHEMES", IDC_CHKDISABLEVISUALTHEMES },
#if 0
    { L"DISABLEDWM", IDC_??, TRUE },
    { L"HIGHDPIAWARE", IDC_??, TRUE },
    { L"RUNASADMIN", IDC_??, TRUE },
#endif
    { NULL, 0 }
};

static const WCHAR* g_AllowedExtensions[] = {
    L".exe",
    L".msi",
    L".pif",
    L".bat",
    L".cmd",
    0
};

BOOL IsBuiltinLayer(PCWSTR Name)
{
    size_t n;

    for (n = 0; g_CompatModes[n].Name; ++n)
    {
        if (!wcsicmp(g_CompatModes[n].Name, Name))
        {
            return TRUE;
        }
    }
    return FALSE;
}


void ACDBG_FN(PCSTR FunctionName, PCWSTR Format, ...)
{
    WCHAR Buffer[512];
    WCHAR* Current = Buffer;
    size_t Length = _countof(Buffer);

    StringCchPrintfExW(Current, Length, &Current, &Length, STRSAFE_NULL_ON_FAILURE, L"[%-20S] ", FunctionName);
    va_list ArgList;
    va_start(ArgList, Format);
    StringCchVPrintfExW(Current, Length, &Current, &Length, STRSAFE_NULL_ON_FAILURE, Format, ArgList);
    va_end(ArgList);
    OutputDebugStringW(Buffer);
}

#define ACDBG(fmt, ...)  ACDBG_FN(__FUNCTION__, fmt, ##__VA_ARGS__ )

void SanitizeFilenameForRegistry(const TCHAR* src, TCHAR* dst, size_t dstSize)
{
    size_t i;
    for (i = 0; src[i] != 0 && i < dstSize - 1; i++)
    {
        if (src[i] == _T('\\'))
            dst[i] = _T('/'); // substitui barra invertida por barra normal
        else
            dst[i] = src[i];
    }
    dst[i] = 0;
}

void WriteToRegistry(const TCHAR* value, BOOL useMessageBox, CString m_Filename)
{
    HKEY hKey;
    LONG result;
    TCHAR subKey[MAX_PATH];
    TCHAR sanitizedName[MAX_PATH];

    // Sanitiza m_Filename para não ter '\'
    SanitizeFilenameForRegistry(m_Filename, sanitizedName, MAX_PATH);

    // monta caminho: SOFTWARE\OCA\Settings\<sanitizedName>
    _stprintf(subKey, _T("SOFTWARE\\OCA\\Settings\\%s"), sanitizedName);

    result = RegCreateKeyEx(
        HKEY_LOCAL_MACHINE,
        subKey,
        0, NULL, 0,
        KEY_SET_VALUE, NULL, &hKey, NULL
    );

    if (result == ERROR_SUCCESS)
    {
        RegSetValueEx(hKey, _T("CompatWindowsVersion"), 0, REG_SZ,
            (const BYTE*)value,
            ((DWORD)_tcslen(value) + 1) * sizeof(TCHAR));

        RegCloseKey(hKey);
    }

#ifdef _M_AMD64
    {
        HKEY Wow64hKey;
        _stprintf(subKey, _T("SOFTWARE\\Wow6432Node\\OCA\\Settings\\%s"), sanitizedName);

        result = RegCreateKeyEx(
            HKEY_LOCAL_MACHINE,
            subKey,
            0, NULL, 0,
            KEY_SET_VALUE, NULL, &Wow64hKey, NULL
        );

        if (result == ERROR_SUCCESS)
        {
            RegSetValueEx(Wow64hKey, _T("CompatWindowsVersion"), 0, REG_SZ,
                (const BYTE*)value,
                ((DWORD)_tcslen(value) + 1) * sizeof(TCHAR));
            RegCloseKey(Wow64hKey);
        }
    }
#endif
}

BOOL ReadFromRegistry(TCHAR* outValue, DWORD outSize, CString m_Filename)
{
    HKEY hKey;
    LONG result;
    TCHAR subKey[MAX_PATH];
    TCHAR sanitizedName[MAX_PATH];
    DWORD type = REG_SZ;

    SanitizeFilenameForRegistry(m_Filename, sanitizedName, MAX_PATH);

    _stprintf(subKey, _T("SOFTWARE\\OCA\\Settings\\%s"), sanitizedName);

    result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, &hKey);
    if (result != ERROR_SUCCESS)
    {
#ifdef _M_AMD64
        _stprintf(subKey, _T("SOFTWARE\\Wow6432Node\\OCA\\Settings\\%s"), sanitizedName);
        result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, &hKey);
        if (result != ERROR_SUCCESS)
            return FALSE;
#else
        return FALSE;
#endif
    }

    result = RegQueryValueEx(hKey, _T("CompatWindowsVersion"), NULL, &type,
                             (BYTE*)outValue, &outSize);
    RegCloseKey(hKey);

    return (result == ERROR_SUCCESS);
}

void DisableOsSpoofingReg(DWORD disableOsSpoofing, CString m_Filename)
{
    HKEY hKey;
    LONG result;
    TCHAR subKey[MAX_PATH];
    TCHAR sanitizedName[MAX_PATH];

    SanitizeFilenameForRegistry(m_Filename, sanitizedName, MAX_PATH);
    _stprintf(subKey, _T("SOFTWARE\\OCA\\Settings\\%s"), sanitizedName);

    result = RegCreateKeyEx(
        HKEY_LOCAL_MACHINE,
        subKey,
        0, NULL, 0,
        KEY_SET_VALUE, NULL, &hKey, NULL
    );

    if (result == ERROR_SUCCESS)
    {
        RegSetValueEx(hKey, _T("DisableOsSpoofing"), 0, REG_DWORD,
            (const BYTE*)&disableOsSpoofing,
            sizeof(DWORD));

        RegCloseKey(hKey);
    }

#ifdef _M_AMD64
    {
        HKEY Wow64hKey;
        _stprintf(subKey, _T("SOFTWARE\\Wow6432Node\\OCA\\Settings\\%s"), sanitizedName);

        result = RegCreateKeyEx(
            HKEY_LOCAL_MACHINE,
            subKey,
            0, NULL, 0,
            KEY_SET_VALUE, NULL, &Wow64hKey, NULL
        );

        if (result == ERROR_SUCCESS)
        {
            RegSetValueEx(Wow64hKey, _T("DisableOsSpoofing"), 0, REG_DWORD,
                (const BYTE*)&disableOsSpoofing,
                sizeof(DWORD));
            RegCloseKey(Wow64hKey);
        }
    }
#endif
}

BOOL ReadDisableOsSpoofingReg(DWORD* outValue, CString m_Filename)
{
    HKEY hKey;
    LONG result;
    TCHAR subKey[MAX_PATH];
    TCHAR sanitizedName[MAX_PATH];
    DWORD type = REG_DWORD;
    DWORD outSize = sizeof(DWORD);

    SanitizeFilenameForRegistry(m_Filename, sanitizedName, MAX_PATH);

    _stprintf(subKey, _T("SOFTWARE\\OCA\\Settings\\%s"), sanitizedName);

    result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, &hKey);
    if (result != ERROR_SUCCESS)
    {
#ifdef _M_AMD64
        _stprintf(subKey, _T("SOFTWARE\\Wow6432Node\\OCA\\Settings\\%s"), sanitizedName);
        result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, &hKey);
        if (result != ERROR_SUCCESS)
            return FALSE;
#else
        return FALSE;
#endif
    }

    result = RegQueryValueEx(hKey, _T("DisableOsSpoofing"), NULL, &type,
                             (BYTE*)outValue, &outSize);
    RegCloseKey(hKey);

    return (result == ERROR_SUCCESS);
}

#include <shlwapi.h> // já tem no seu ficheiro, mantive aqui só para referência

BOOL DeleteFromRegistry(CString m_Filename)
{
    HKEY hKey = NULL;
    LONG lRes;
    TCHAR sanitizedName[MAX_PATH];

    SanitizeFilenameForRegistry(m_Filename, sanitizedName, MAX_PATH);

    BOOL deletedAny = FALSE;

    // --- 1) Tentar apagar em HKLM\SOFTWARE\OCA\Settings\<sanitizedName>
    lRes = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                        TEXT("SOFTWARE\\OCA\\Settings"),
                        0,
                        KEY_WRITE | KEY_ENUMERATE_SUB_KEYS,
                        &hKey);
    if (lRes == ERROR_SUCCESS)
    {
        lRes = RegDeleteKey(hKey, sanitizedName);
        if (lRes == ERROR_SUCCESS)
        {
            ACDBG(L"Deleted key: SOFTWARE\\OCA\\Settings\\%s\r\n", sanitizedName);
            deletedAny = TRUE;
        }
        else
        {
            ACDBG(L"RegDeleteKey failed for SOFTWARE\\OCA\\Settings\\%s : %ld. Trying SHDeleteKey...\r\n",
                  sanitizedName, lRes);
            // fallback: tenta apagar recursivamente
            lRes = SHDeleteKey(hKey, sanitizedName);
            if (lRes == ERROR_SUCCESS)
            {
                ACDBG(L"SHDeleteKey succeeded for SOFTWARE\\OCA\\Settings\\%s\r\n", sanitizedName);
                deletedAny = TRUE;
            }
            else
            {
                ACDBG(L"SHDeleteKey also failed for SOFTWARE\\OCA\\Settings\\%s : %ld\r\n", sanitizedName, lRes);
            }
        }
        RegCloseKey(hKey);
    }
    else
    {
        ACDBG(L"RegOpenKeyEx SOFTWARE\\OCA\\Settings failed: %ld\r\n", lRes);
    }

    // --- 2) Também tentar remover a versão Wow6432Node (útil em x64)
    lRes = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                        TEXT("SOFTWARE\\Wow6432Node\\OCA\\Settings"),
                        0,
                        KEY_WRITE | KEY_ENUMERATE_SUB_KEYS,
                        &hKey);
    if (lRes == ERROR_SUCCESS)
    {
        LONG lResDel = RegDeleteKey(hKey, sanitizedName);
        if (lResDel == ERROR_SUCCESS)
        {
            ACDBG(L"Deleted key: SOFTWARE\\Wow6432Node\\OCA\\Settings\\%s\r\n", sanitizedName);
            deletedAny = TRUE;
        }
        else
        {
            ACDBG(L"RegDeleteKey failed for Wow6432Node\\OCA\\Settings\\%s : %ld. Trying SHDeleteKey...\r\n",
                  sanitizedName, lResDel);
            lResDel = SHDeleteKey(hKey, sanitizedName);
            if (lResDel == ERROR_SUCCESS)
            {
                ACDBG(L"SHDeleteKey succeeded for Wow6432Node\\OCA\\Settings\\%s\r\n", sanitizedName);
                deletedAny = TRUE;
            }
            else
            {
                ACDBG(L"SHDeleteKey also failed for Wow6432Node\\OCA\\Settings\\%s : %ld\r\n",
                      sanitizedName, lResDel);
            }
        }
        RegCloseKey(hKey);
    }
    else
    {
        ACDBG(L"RegOpenKeyEx SOFTWARE\\Wow6432Node\\OCA\\Settings failed: %ld\r\n", lRes);
    }

    return deletedAny;
}


CLayerUIPropPage::CLayerUIPropPage()
: m_AllowPermLayer(FALSE)
, m_LayerQueryFlags(GPLK_USER)  /* TODO: When do we read from HKLM? */
, m_RegistryOSMode(0)
, m_OSMode(0)
, m_RegistryEnabledLayers(0)
, m_EnabledLayers(0)
{
    CComBSTR title;
    title.LoadString(g_hModule, IDS_COMPAT_TITLE);
    m_psp.pszTitle = title.Detach();
    m_psp.dwFlags |= PSP_USETITLE;
}

CLayerUIPropPage::~CLayerUIPropPage()
{
    CComBSTR title;
    title.Attach((BSTR)m_psp.pszTitle);
}

HRESULT CLayerUIPropPage::InitFile(PCWSTR Filename)
{
    CString ExpandedFilename;
    DWORD dwRequired = ExpandEnvironmentStringsW(Filename, NULL, 0);
    if (dwRequired > 0)
    {
        LPWSTR Buffer = ExpandedFilename.GetBuffer(dwRequired);
        DWORD dwReturned = ExpandEnvironmentStringsW(Filename, Buffer, dwRequired);
        if (dwRequired == dwReturned)
        {
            ExpandedFilename.ReleaseBufferSetLength(dwReturned - 1);
            ACDBG(L"Expanded '%s' => '%s'\r\n", Filename, (PCWSTR)ExpandedFilename);
        }
        else
        {
            ExpandedFilename.ReleaseBufferSetLength(0);
            ExpandedFilename = Filename;
            ACDBG(L"Failed during expansion '%s'\r\n", Filename);
        }
    }
    else
    {
        ACDBG(L"Failed to expand '%s'\r\n", Filename);
        ExpandedFilename = Filename;
    }
    PCWSTR pwszExt = PathFindExtensionW(ExpandedFilename);
    if (!pwszExt)
    {
        ACDBG(L"Failed to find an extension: '%s'\r\n", (PCWSTR)ExpandedFilename);
        return E_FAIL;
    }
    if (!wcsicmp(pwszExt, L".lnk"))
    {
        WCHAR Buffer[MAX_PATH];
        if (!GetExeFromLnk(ExpandedFilename, Buffer, _countof(Buffer)))
        {
            ACDBG(L"Failed to read link target from: '%s'\r\n", (PCWSTR)ExpandedFilename);
            return E_FAIL;
        }
        if (!wcsicmp(Buffer, ExpandedFilename))
        {
            ACDBG(L"Link redirects to itself: '%s'\r\n", (PCWSTR)ExpandedFilename);
            return E_FAIL;
        }
        return InitFile(Buffer);
    }

    CString tmp;
    if (tmp.GetEnvironmentVariable(L"SystemRoot"))
    {
        tmp += L"\\System32";
        if (ExpandedFilename.GetLength() >= tmp.GetLength() &&
            ExpandedFilename.Left(tmp.GetLength()).MakeLower() == tmp.MakeLower())
        {
            ACDBG(L"Ignoring System32: %s\r\n", (PCWSTR)ExpandedFilename);
            return E_FAIL;
        }
        tmp.GetEnvironmentVariable(L"SystemRoot");
        tmp += L"\\WinSxs";
        if (ExpandedFilename.GetLength() >= tmp.GetLength() &&
            ExpandedFilename.Left(tmp.GetLength()).MakeLower() == tmp.MakeLower())
        {
            ACDBG(L"Ignoring WinSxs: %s\r\n", (PCWSTR)ExpandedFilename);
            return E_FAIL;
        }
    }

    for (size_t n = 0; g_AllowedExtensions[n]; ++n)
    {
        if (!wcsicmp(g_AllowedExtensions[n], pwszExt))
        {
            m_Filename = ExpandedFilename;
            ACDBG(L"Got: %s\r\n", (PCWSTR)ExpandedFilename);
            m_AllowPermLayer = AllowPermLayer(ExpandedFilename);
            return S_OK;
        }
    }
    ACDBG(L"Extension not included: '%s'\r\n", pwszExt);
    return E_FAIL;
}

static BOOL GetLayerInfo(PCWSTR Filename, DWORD QueryFlags, PDWORD OSMode, PDWORD Enabledlayers, CSimpleArray<CString>& customLayers)
{
    WCHAR wszLayers[MAX_LAYER_LENGTH] = { 0 };
    DWORD dwBytes = sizeof(wszLayers);

    *OSMode = *Enabledlayers = 0;
    customLayers.RemoveAll();
    if (!SdbGetPermLayerKeys(Filename, wszLayers, &dwBytes, QueryFlags))
        return FALSE;

    for (PWCHAR Layer = wcstok(wszLayers, L" "); Layer; Layer = wcstok(NULL, L" "))
    {
        size_t n;
        for (n = 0; g_Layers[n].Name; ++n)
        {
            if (!wcsicmp(g_Layers[n].Name, Layer))
            {
                *Enabledlayers |= (1<<n);
                break;
            }
        }
        /* Did we find it? */
        if (g_Layers[n].Name)
            continue;

        for (n = 0; g_CompatModes[n].Name; ++n)
        {
            if (!wcsicmp(g_CompatModes[n].Name, Layer))
            {
                *OSMode = n+1;
                break;
            }
        }
        /* Did we find it? */
        if (g_CompatModes[n].Name)
            continue;

        /* Must be a 'custom' layer */
        customLayers.Add(Layer);
    }
    return TRUE;
}

int CLayerUIPropPage::OnSetActive()
{
    int i;
    HWND hCombo = GetDlgItem(IDC_COMPATIBILITYMODE);

    // Inicializa vars registradas
    m_RegistryOSMode = 0;
    m_RegistryEnabledLayers = 0;
    m_RegistryDisableOsSpoofing = 0;
    m_RegistryCustomLayers.RemoveAll();

    DWORD disableOsSpoofing = 0;
    if (ReadDisableOsSpoofingReg(&disableOsSpoofing, m_Filename) && disableOsSpoofing)
    {
        CheckDlgButton(IDC_CHKDISABLEOSSPOOFING, BST_UNCHECKED);
        m_RegistryDisableOsSpoofing = 1;
    }
    else
    {
        CheckDlgButton(IDC_CHKDISABLEOSSPOOFING, BST_CHECKED);
    }

    TCHAR regValue[256] = {0};
    if (ReadFromRegistry(regValue, sizeof(regValue), m_Filename))
    {
        CheckDlgButton(IDC_CHKRUNCOMPATIBILITY, BST_CHECKED);

        // Procura índice correspondente no array versionValues
        int selIndex = -1;
        int countVersions = 0;
        while (g_CompatModes[countVersions].Display) ++countVersions;

        for (i = 0; i < countVersions; i++)
        {
            if (_tcscmp(regValue, g_CompatModes[i].Name) == 0)
            {
                selIndex = i;
                break;
            }
        }

        if (selIndex != -1)
            SendMessage(hCombo, CB_SETCURSEL, selIndex, 0);
        else
            SendMessage(hCombo, CB_SETCURSEL, 0, 0); // fallback

        ::EnableWindow(hCombo, TRUE);

        // Atualiza variáveis 'registradas' para refletir o que foi lido
        m_RegistryOSMode = ComboBox_GetCurSel(hCombo) + 1;
        // Se houver outras flags registradas (layers/custom) leia-as aqui também.
        // No seu código original a leitura completa de layers foi comentada.
        // Se você tiver uma função GetLayerInfo use-a para preencher m_RegistryEnabledLayers e m_RegistryCustomLayers.
    }
    else
    {
        CheckDlgButton(IDC_CHKRUNCOMPATIBILITY, BST_UNCHECKED);
        ::EnableWindow(hCombo, FALSE);

        m_RegistryOSMode = 0;
        m_RegistryEnabledLayers = 0;
        m_RegistryCustomLayers.RemoveAll();
    }

    // Inicializa os valores atuais (m_*) com os valores registrados para que
    // HasChanges() comece consistente.
    m_OSMode = m_RegistryOSMode;
    m_EnabledLayers = m_RegistryEnabledLayers;
    m_DisableOsSpoofing = m_RegistryDisableOsSpoofing;
    m_CustomLayers = m_RegistryCustomLayers;

    UpdateControls();

    return 0;
}



static BOOL ArrayEquals(const CSimpleArray<CString>& lhs, const CSimpleArray<CString>& rhs)
{
    if (lhs.GetSize() != rhs.GetSize())
        return FALSE;

    for (int n = 0; n < lhs.GetSize(); ++n)
    {
        if (lhs[n] != rhs[n])
            return FALSE;
    }
    return TRUE;
}

BOOL CLayerUIPropPage::HasChanges() const
{
    if (m_RegistryEnabledLayers != m_EnabledLayers)
        return TRUE;

    if (m_RegistryOSMode != m_OSMode)
        return TRUE;

    if (m_RegistryDisableOsSpoofing != m_DisableOsSpoofing)
        return TRUE;

    if (!ArrayEquals(m_RegistryCustomLayers, m_CustomLayers))
        return TRUE;

    return FALSE;
}

int CLayerUIPropPage::OnApply()
{
    // Calcula os valores atuais antes de aplicar
    UpdateControls();

    BOOL bChecked = (IsDlgButtonChecked(IDC_CHKRUNCOMPATIBILITY) == BST_CHECKED);

    if (bChecked)
    {
        HWND hCombo = GetDlgItem(IDC_COMPATIBILITYMODE);
        int idx = (int)SendMessage(hCombo, CB_GETCURSEL, 0, 0);

        if (idx >= 0)
        {
            const TCHAR* selectedValue = g_CompatModes[idx].Name;
            WriteToRegistry(selectedValue, TRUE, m_Filename);
            // atualiza estado registrado
            m_RegistryOSMode = idx + 1;
        }
        else
        {
            // combo sem seleção: remove o valor (defensivo)
            DeleteFromRegistry(m_Filename);
            m_RegistryOSMode = 0;
        }
    }
    else
    {
        // Checkbox desmarcado -> remover compat mode do registro
        DeleteFromRegistry(m_Filename);
        m_RegistryOSMode = 0;
    }

    // Se você escreve também as layers/custom, atualize m_RegistryEnabledLayers
    // e m_RegistryCustomLayers aqui para refletir o que foi gravado.

    // Notifica alteração ao shell
    SHChangeNotify(SHCNE_UPDATEITEM, SHCNF_PATHW, (PCWSTR)m_Filename, NULL);

    // Depois de gravar, não há mais "modificações pendentes"
    // sincroniza m_* com os valores atuais e limpa o flag Modified
    
    BOOL bSpoofingChecked = (IsDlgButtonChecked(IDC_CHKDISABLEOSSPOOFING) == BST_CHECKED);
    DWORD newDisableOsSpoofing = bSpoofingChecked ? 0 : 1;
    DisableOsSpoofingReg(newDisableOsSpoofing, m_Filename);
    m_RegistryDisableOsSpoofing = newDisableOsSpoofing;

    m_OSMode = m_RegistryOSMode;
    m_EnabledLayers = m_RegistryEnabledLayers;
    m_DisableOsSpoofing = m_RegistryDisableOsSpoofing;
    m_CustomLayers = m_RegistryCustomLayers;

    SetModified(FALSE); // limpa o botão Aplicar
    // ou alternativamente UpdateControls();

    return PSNRET_NOERROR;
}


LRESULT CLayerUIPropPage::OnInitDialog(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL &bHandled)
{
    HWND cboMode = GetDlgItem(IDC_COMPATIBILITYMODE);
	
	HWND hDlg = this->m_hWnd;
	
	EnableThemeDialogTexture(hDlg, ETDT_ENABLETAB);
	
    for (size_t n = 0; g_CompatModes[n].Display; ++n)
        ComboBox_AddString(cboMode, g_CompatModes[n].Display);
    ComboBox_SetCurSel(cboMode, 4);

    CStringW explanation;
    if (!m_AllowPermLayer)
    {
        explanation.LoadString(g_hModule, IDS_FAILED_NETWORK);
        DisableControls();
        ACDBG(L"AllowPermLayer returned FALSE\r\n");
    }
    else
    {
        return TRUE;
    }
    SetDlgItemTextW(IDC_EXPLANATION, explanation);
    return TRUE;
}

INT_PTR CLayerUIPropPage::DisableControls()
{
    ::EnableWindow(GetDlgItem(IDC_COMPATIBILITYMODE), 0);
    ::EnableWindow(GetDlgItem(IDC_CHKRUNCOMPATIBILITY), 0);
    for (size_t n = 0; g_Layers[n].Name; ++n)
        ::EnableWindow(GetDlgItem(g_Layers[n].Id), 0);
    ::EnableWindow(GetDlgItem(IDC_EDITCOMPATIBILITYMODES), 0);
    return TRUE;
}

void CLayerUIPropPage::UpdateControls()
{
    m_OSMode = 0, m_EnabledLayers = 0;
    BOOL ModeEnabled = IsDlgButtonChecked(IDC_CHKRUNCOMPATIBILITY);
    if (ModeEnabled)
        m_OSMode = ComboBox_GetCurSel(GetDlgItem(IDC_COMPATIBILITYMODE))+1;
    ::EnableWindow(GetDlgItem(IDC_COMPATIBILITYMODE), ModeEnabled);

    for (size_t n = 0; g_Layers[n].Name; ++n)
    {
        m_EnabledLayers |= IsDlgButtonChecked(g_Layers[n].Id) ? (1<<n) : 0;
        ::ShowWindow(GetDlgItem(g_Layers[n].Id), SW_SHOW);
    }

    m_DisableOsSpoofing = (IsDlgButtonChecked(IDC_CHKDISABLEOSSPOOFING) == BST_CHECKED) ? 0 : 1;

    CStringW customLayers;
    for (int j = 0; j < m_CustomLayers.GetSize(); ++j)
    {
        if (j > 0)
            customLayers += L", ";
        customLayers += m_CustomLayers[j];
    }
    SetDlgItemTextW(IDC_ENABLED_LAYERS, customLayers);

    SetModified(HasChanges());
}

LRESULT CLayerUIPropPage::OnCtrlCommand(WORD wNotifyCode, WORD wID, HWND hWndCtl, BOOL &bHandled)
{
    UpdateControls();
    return 0;
}

LRESULT CLayerUIPropPage::OnEditModes(WORD wNotifyCode, WORD wID, HWND hWndCtl, BOOL &bHandled)
{
    if (ShowEditCompatModes(m_hWnd, this))
        UpdateControls();
    return 0;
}

LRESULT CLayerUIPropPage::OnClickNotify(INT uCode, LPNMHDR hdr, BOOL& bHandled)
{
    if (hdr->idFrom == IDC_INFOLINK)
        ShellExecute(NULL, L"open", L"https://reactos.org/forum/viewforum.php?f=4", NULL, NULL, SW_SHOW);
    return 0;
}

// static BOOL DisableShellext()
// {
    // HKEY hkey;
    // LSTATUS ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat", 0, KEY_QUERY_VALUE, &hkey);
    // BOOL Disable = FALSE;
    // if (ret == ERROR_SUCCESS)
    // {
        // DWORD dwValue = 0;
        // DWORD type, size = sizeof(dwValue);
        // ret = RegQueryValueExW(hkey, L"DisableEngine", NULL, &type, (PBYTE)&dwValue, &size);
        // if (ret == ERROR_SUCCESS && type == REG_DWORD)
        // {
            // Disable = !!dwValue;
        // }
        // if (!Disable)
        // {
            // size = sizeof(dwValue);
            // ret = RegQueryValueExW(hkey, L"DisablePropPage", NULL, &type, (PBYTE)&dwValue, &size);
            // if (ret == ERROR_SUCCESS && type == REG_DWORD)
            // {
                // Disable = !!dwValue;
            // }
        // }

        // RegCloseKey(hkey);
    // }
    // return Disable;
// }

STDMETHODIMP CLayerUIPropPage::Initialize(PCIDLIST_ABSOLUTE pidlFolder, LPDATAOBJECT pDataObj, HKEY hkeyProgID)
{
    FORMATETC etc = { CF_HDROP, NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL };
    STGMEDIUM stg;

    // if (DisableShellext())
        // return E_ACCESSDENIED;

    HRESULT hr = pDataObj->GetData(&etc, &stg);
    if (FAILED(hr))
    {
        ACDBG(L"Failed to retrieve Data from pDataObj.\r\n");
        return E_INVALIDARG;
    }
    hr = E_FAIL;
    HDROP hdrop = (HDROP)GlobalLock(stg.hGlobal);
    if (hdrop)
    {
        UINT uNumFiles = DragQueryFileW(hdrop, 0xFFFFFFFF, NULL, 0);
        if (uNumFiles == 1)
        {
            WCHAR szFile[MAX_PATH * 2];
            if (DragQueryFileW(hdrop, 0, szFile, _countof(szFile)))
            {
                this->AddRef();
                hr = InitFile(szFile);
            }
            else
            {
                ACDBG(L"Failed to query the file.\r\n");
            }
        }
        else
        {
            ACDBG(L"Invalid number of files: %d\r\n", uNumFiles);
        }
        GlobalUnlock(stg.hGlobal);
    }
    else
    {
        ACDBG(L"Could not lock stg.hGlobal\r\n");
    }
    ReleaseStgMedium(&stg);
    return hr;
}
