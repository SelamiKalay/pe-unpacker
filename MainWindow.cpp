// =============================================================================
//  MainWindow — Win32 native GUI
//
//  Tasarim:
//    - Tek pencere, sabit duzen (CreateWindowEx ile mutlak konum)
//    - Visual styles (Common Controls v6) bir manifest dependency ile saglanir
//    - Logger::SetSink ile motor log'lari pencere icine yonlendirilir
//    - Unpack islemi ayri bir thread'de calisir → UI donmaz
//    - Worker → UI iletisimi PostMessage(WM_USER_*) ile thread-safe
// =============================================================================

#include "MainWindow.h"
#include "Logger.h"
#include "PEParser.h"
#include "ProcessManager.h"
#include "DebuggerEngine.h"
#include "Dumper.h"
#include "IATRebuilder.h"

#include <commdlg.h>
#include <commctrl.h>
#include <psapi.h>
#include <shellapi.h>
#include <filesystem>
#include <string>
#include <vector>
#include <sstream>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shell32.lib")

// Modern visual styles (XP+)
#pragma comment(linker, "\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// =============================================================================
//  Kontrol ID'leri ve ozel mesajlar
// =============================================================================
enum : int {
    ID_EDIT_INPUT     = 1001,
    ID_BTN_BROWSE_IN  = 1002,
    ID_EDIT_OUTPUT    = 1003,
    ID_BTN_BROWSE_OUT = 1004,

    ID_CHK_EXEC_BP    = 1010,
    ID_EDIT_EXEC_BP   = 1011,

    ID_CHK_IAT        = 1020,
    ID_EDIT_IAT_VA    = 1021,
    ID_EDIT_IAT_SIZE  = 1022,

    ID_BTN_ANALYZE    = 1030,
    ID_BTN_UNPACK     = 1031,
    ID_BTN_CLEAR      = 1032,

    ID_EDIT_LOG       = 1040,
    ID_STATUS         = 1050,
};

static constexpr UINT WM_APP_LOG     = WM_APP + 1;   // wp=level, lp=heap wstring*
static constexpr UINT WM_APP_STATUS  = WM_APP + 2;   // lp=heap wstring*
static constexpr UINT WM_APP_DONE    = WM_APP + 3;   // wp=success(0/1)

// =============================================================================
//  Yardimci: UTF-8 → UTF-16
// =============================================================================
static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    const int len = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(len, L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), len);
    return w;
}
static std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    const int len = ::WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                                          nullptr, 0, nullptr, nullptr);
    std::string s(len, '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), s.data(), len,
                          nullptr, nullptr);
    return s;
}

// =============================================================================
//  Pencere olusturma
// =============================================================================
bool MainWindow::Create(HINSTANCE hInst, int nCmdShow)
{
    m_hInst = hInst;

    // Common Controls
    INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_STANDARD_CLASSES | ICC_BAR_CLASSES };
    ::InitCommonControlsEx(&icc);

    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = &MainWindow::WndProcStatic;
    wc.hInstance     = hInst;
    wc.hCursor       = ::LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"UnpackerMainWindow";
    if (!::RegisterClassExW(&wc)) return false;

    m_hwnd = ::CreateWindowExW(
        0,
        L"UnpackerMainWindow",
        L"Executable Unpacker — Defansif RE Araci",
        WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_THICKFRAME,
        CW_USEDEFAULT, CW_USEDEFAULT, 900, 680,
        nullptr, nullptr, hInst, this);

    if (!m_hwnd) return false;

    ::ShowWindow(m_hwnd, nCmdShow);
    ::UpdateWindow(m_hwnd);
    return true;
}

int MainWindow::RunMessageLoop()
{
    MSG msg;
    while (::GetMessageW(&msg, nullptr, 0, 0) > 0) {
        ::TranslateMessage(&msg);
        ::DispatchMessageW(&msg);
    }
    if (m_worker.joinable()) m_worker.join();
    return (int)msg.wParam;
}

// =============================================================================
//  WndProc — static yonlendirici → uye fonksiyon
// =============================================================================
LRESULT CALLBACK MainWindow::WndProcStatic(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    MainWindow* self = nullptr;
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
        self = static_cast<MainWindow*>(cs->lpCreateParams);
        self->m_hwnd = hwnd;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
    } else {
        self = reinterpret_cast<MainWindow*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    }
    if (self) return self->WndProc(msg, wp, lp);
    return ::DefWindowProcW(hwnd, msg, wp, lp);
}

LRESULT MainWindow::WndProc(UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE:
        OnCreate();
        return 0;

    case WM_COMMAND:
        OnCommand(LOWORD(wp));
        return 0;

    case WM_APP_LOG: {
        auto* heap = reinterpret_cast<std::wstring*>(lp);
        AppendLog(static_cast<int>(wp), *heap);
        delete heap;
        return 0;
    }
    case WM_APP_STATUS: {
        auto* heap = reinterpret_cast<std::wstring*>(lp);
        SetStatus(*heap);
        delete heap;
        return 0;
    }
    case WM_APP_DONE:
        SetBusy(false);
        if (m_worker.joinable()) m_worker.join();
        if (wp) ::MessageBoxW(m_hwnd, L"Islem basariyla tamamlandi.",
                              L"Bitti", MB_OK | MB_ICONINFORMATION);
        else    ::MessageBoxW(m_hwnd, L"Islem hata ile sonlandi. Loglara bakin.",
                              L"Hata", MB_OK | MB_ICONWARNING);
        return 0;

    case WM_CLOSE:
        if (m_busy.load()) {
            if (::MessageBoxW(m_hwnd, L"Bir islem suruyor. Yine de cikilsin mi?",
                              L"Onay", MB_YESNO | MB_ICONQUESTION) != IDYES)
                return 0;
        }
        ::DestroyWindow(m_hwnd);
        return 0;

    case WM_DESTROY:
        if (m_font)     ::DeleteObject(m_font);
        if (m_fontMono) ::DeleteObject(m_fontMono);
        ::PostQuitMessage(0);
        return 0;
    }
    return ::DefWindowProcW(m_hwnd, msg, wp, lp);
}

// =============================================================================
//  Kontrolleri olustur
// =============================================================================
void MainWindow::OnCreate()
{
    // Fontlar
    m_font = ::CreateFontW(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    m_fontMono = ::CreateFontW(-13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");

    auto Label = [&](LPCWSTR text, int x, int y, int w, int h) {
        HWND h_ = ::CreateWindowExW(0, L"STATIC", text,
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            x, y, w, h, m_hwnd, nullptr, m_hInst, nullptr);
        ::SendMessageW(h_, WM_SETFONT, (WPARAM)m_font, TRUE);
        return h_;
    };
    auto Edit = [&](int id, int x, int y, int w, int h, DWORD extra = 0) {
        HWND h_ = ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL | extra,
            x, y, w, h, m_hwnd, (HMENU)(INT_PTR)id, m_hInst, nullptr);
        ::SendMessageW(h_, WM_SETFONT, (WPARAM)m_font, TRUE);
        return h_;
    };
    auto Button = [&](LPCWSTR text, int id, int x, int y, int w, int h) {
        HWND h_ = ::CreateWindowExW(0, L"BUTTON", text,
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            x, y, w, h, m_hwnd, (HMENU)(INT_PTR)id, m_hInst, nullptr);
        ::SendMessageW(h_, WM_SETFONT, (WPARAM)m_font, TRUE);
        return h_;
    };
    auto Check = [&](LPCWSTR text, int id, int x, int y, int w, int h) {
        HWND h_ = ::CreateWindowExW(0, L"BUTTON", text,
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
            x, y, w, h, m_hwnd, (HMENU)(INT_PTR)id, m_hInst, nullptr);
        ::SendMessageW(h_, WM_SETFONT, (WPARAM)m_font, TRUE);
        return h_;
    };

    int y = 12;

    // ── Hedef EXE ──
    Label(L"Hedef EXE:", 12, y, 80, 20);
    m_editInput   = Edit(ID_EDIT_INPUT,    100, y - 2, 660, 24);
    m_btnBrowseIn = Button(L"Gozat…", ID_BTN_BROWSE_IN, 770, y - 3, 100, 26);

    y += 36;
    Label(L"Cikti EXE:", 12, y, 80, 20);
    m_editOutput   = Edit(ID_EDIT_OUTPUT,   100, y - 2, 660, 24);
    m_btnBrowseOut = Button(L"Kaydet…", ID_BTN_BROWSE_OUT, 770, y - 3, 100, 26);

    // ── OEP execute BP ──
    y += 44;
    m_chkExecBp = Check(L"HW Execute Breakpoint (OEP):",
                       ID_CHK_EXEC_BP, 12, y, 250, 22);
    m_editExecBp = Edit(ID_EDIT_EXEC_BP, 270, y - 2, 200, 24);
    ::SetWindowTextW(m_editExecBp, L"0x");
    Label(L"  (mutlak VA, ornek: 0x7FF71B9619C0)", 480, y, 380, 20);

    // ── IAT yeniden insa ──
    y += 32;
    m_chkIAT = Check(L"IAT yeniden insa et:", ID_CHK_IAT, 12, y, 250, 22);
    Label(L"VA:", 270, y, 30, 20);
    m_editIatVA   = Edit(ID_EDIT_IAT_VA,   305, y - 2, 170, 24);
    ::SetWindowTextW(m_editIatVA, L"0x");
    Label(L"Boyut:", 485, y, 50, 20);
    m_editIatSize = Edit(ID_EDIT_IAT_SIZE, 540, y - 2, 120, 24);
    ::SetWindowTextW(m_editIatSize, L"0x200");

    // ── Aksiyon butonlari ──
    y += 40;
    m_btnAnalyze = Button(L"PE Analizi",   ID_BTN_ANALYZE, 12,  y, 130, 32);
    m_btnUnpack  = Button(L"UNPACK BASLAT", ID_BTN_UNPACK,  152, y, 160, 32);
    m_btnClear   = Button(L"Loglari Temizle", ID_BTN_CLEAR, 322, y, 150, 32);

    // ── Log alani ──
    y += 44;
    m_editLog = ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL |
        ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
        12, y, 858, 470,
        m_hwnd, (HMENU)(INT_PTR)ID_EDIT_LOG, m_hInst, nullptr);
    ::SendMessageW(m_editLog, WM_SETFONT, (WPARAM)m_fontMono, TRUE);

    // ── Status bar ──
    m_status = ::CreateWindowExW(0, STATUSCLASSNAMEW, L"Hazir.",
        WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
        0, 0, 0, 0, m_hwnd, (HMENU)(INT_PTR)ID_STATUS, m_hInst, nullptr);

    // Logger sink kur — motor ne yazarsa pencereye gelir
    Logger::SetSink([this](Logger::Level lvl, const std::string& msg) {
        auto* w = new std::wstring(Utf8ToWide(msg));
        ::PostMessageW(m_hwnd, WM_APP_LOG,
                       static_cast<WPARAM>(static_cast<int>(lvl)),
                       reinterpret_cast<LPARAM>(w));
    });
}

// =============================================================================
//  Komut dispatcher
// =============================================================================
void MainWindow::OnCommand(WORD id)
{
    switch (id) {
    case ID_BTN_BROWSE_IN:  OnBrowseInput();  break;
    case ID_BTN_BROWSE_OUT: OnBrowseOutput(); break;
    case ID_BTN_ANALYZE:    OnAnalyze();      break;
    case ID_BTN_UNPACK:     OnUnpack();       break;
    case ID_BTN_CLEAR:      OnClear();        break;
    }
}

// =============================================================================
//  Dosya secim dialoglari
// =============================================================================
void MainWindow::OnBrowseInput()
{
    wchar_t buf[MAX_PATH] = {};
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = m_hwnd;
    ofn.lpstrFilter = L"Yurutulebilir dosyalar (*.exe;*.dll)\0*.exe;*.dll\0Tum dosyalar\0*.*\0";
    ofn.lpstrFile   = buf;
    ofn.nMaxFile    = MAX_PATH;
    ofn.Flags       = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (::GetOpenFileNameW(&ofn)) {
        ::SetWindowTextW(m_editInput, buf);
        // Cikti yolu bossa otomatik onerelim
        if (::GetWindowTextLengthW(m_editOutput) == 0) {
            std::filesystem::path p(buf);
            auto out = p.parent_path() / (p.stem().wstring() + L"_unpacked.exe");
            ::SetWindowTextW(m_editOutput, out.c_str());
        }
    }
}

void MainWindow::OnBrowseOutput()
{
    wchar_t buf[MAX_PATH] = {};
    ::GetWindowTextW(m_editOutput, buf, MAX_PATH);

    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = m_hwnd;
    ofn.lpstrFilter = L"EXE\0*.exe\0Tum dosyalar\0*.*\0";
    ofn.lpstrFile   = buf;
    ofn.nMaxFile    = MAX_PATH;
    ofn.lpstrDefExt = L"exe";
    ofn.Flags       = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    if (::GetSaveFileNameW(&ofn))
        ::SetWindowTextW(m_editOutput, buf);
}

// =============================================================================
//  Yardimcilar
// =============================================================================
std::wstring MainWindow::GetEditText(HWND hEdit) const
{
    const int len = ::GetWindowTextLengthW(hEdit);
    std::wstring s(len, L'\0');
    if (len > 0) ::GetWindowTextW(hEdit, s.data(), len + 1);
    return s;
}

void MainWindow::AppendLog(int level, const std::wstring& text)
{
    const wchar_t* prefix = L"[INFO ] ";
    switch (static_cast<Logger::Level>(level)) {
    case Logger::Level::Info:  prefix = L"[INFO ] "; break;
    case Logger::Level::Event: prefix = L"[EVENT] "; break;
    case Logger::Level::Warn:  prefix = L"[WARN ] "; break;
    case Logger::Level::Error: prefix = L"[ERROR] "; break;
    }
    std::wstring line = prefix + text + L"\r\n";

    // Edit kontrolune ekle (sona)
    const int len = ::GetWindowTextLengthW(m_editLog);
    ::SendMessageW(m_editLog, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    ::SendMessageW(m_editLog, EM_REPLACESEL, FALSE, (LPARAM)line.c_str());
    ::SendMessageW(m_editLog, EM_SCROLLCARET, 0, 0);
}

void MainWindow::SetStatus(const std::wstring& text)
{
    ::SendMessageW(m_status, SB_SETTEXTW, 0, (LPARAM)text.c_str());
}

void MainWindow::SetBusy(bool busy)
{
    m_busy = busy;
    ::EnableWindow(m_btnAnalyze, !busy);
    ::EnableWindow(m_btnUnpack,  !busy);
    ::EnableWindow(m_btnBrowseIn, !busy);
    ::EnableWindow(m_btnBrowseOut, !busy);
    SetStatus(busy ? L"Calisiyor..." : L"Hazir.");
}

void MainWindow::OnClear()
{
    ::SetWindowTextW(m_editLog, L"");
}

// =============================================================================
//  Analiz (sadece statik PE bilgisi)
// =============================================================================
void MainWindow::OnAnalyze()
{
    if (m_busy.load()) return;

    const auto inputW = GetEditText(m_editInput);
    if (inputW.empty()) {
        ::MessageBoxW(m_hwnd, L"Once bir hedef EXE secin.", L"Eksik girdi",
                      MB_OK | MB_ICONWARNING);
        return;
    }

    try {
        LOG_INFO("====== STATIK PE ANALIZI ======");
        std::filesystem::path inputPath(inputW);
        PEParser parser(inputPath);
        parser.PrintPEInfo();   // Logger sink uzerinden penceredeki edit'e gider
        SetStatus(L"Analiz tamamlandi.");
    }
    catch (const std::exception& e) {
        LOG_ERROR("Analiz hatasi: {}", e.what());
        SetStatus(L"Analiz hatasi.");
    }
}

// =============================================================================
//  PEParser.PrintPEInfo log'a yazmak yerine std::cout'a yazar.
//  Bu yuzden Analiz'i ozel olarak ele almak istemezsek alternatif:
//  PrintPEInfo'yu Logger uzerinden gecirmek. Daha az invazif yontem:
//  PEParser bilgilerini elle log'a yazdiralim.
//
//  Asagidaki OnUnpack akisi zaten Logger uzerinden ilerliyor.
// =============================================================================

// =============================================================================
//  Asagida tekrarlanan kucuk yardimci: hedef surecte ana modul base'i
// =============================================================================
static std::uintptr_t FindMainModuleBase(HANDLE hProc,
                                         const std::filesystem::path& exePath)
{
    std::vector<HMODULE> mods(512);
    DWORD needed = 0;
    if (!::EnumProcessModulesEx(hProc, mods.data(),
                                static_cast<DWORD>(mods.size() * sizeof(HMODULE)),
                                &needed, LIST_MODULES_ALL))
        throw std::runtime_error("EnumProcessModulesEx basarisiz");
    mods.resize(needed / sizeof(HMODULE));

    const auto targetBase = exePath.filename().wstring();
    for (HMODULE m : mods) {
        wchar_t buf[MAX_PATH] = {};
        if (::GetModuleFileNameExW(hProc, m, buf, MAX_PATH)) {
            std::filesystem::path p(buf);
            if (::_wcsicmp(p.filename().c_str(), targetBase.c_str()) == 0)
                return reinterpret_cast<std::uintptr_t>(m);
        }
    }
    if (!mods.empty()) return reinterpret_cast<std::uintptr_t>(mods[0]);
    throw std::runtime_error("Ana modul bulunamadi");
}

// =============================================================================
//  UNPACK akisi (worker thread)
// =============================================================================
void MainWindow::OnUnpack()
{
    if (m_busy.load()) return;

    const auto inputW  = GetEditText(m_editInput);
    const auto outputW = GetEditText(m_editOutput);
    if (inputW.empty() || outputW.empty()) {
        ::MessageBoxW(m_hwnd, L"Hedef ve cikti yollari zorunlu.",
                      L"Eksik girdi", MB_OK | MB_ICONWARNING);
        return;
    }

    SetBusy(true);
    // Worker thread'i baslat (UI thread bloklanmasin)
    if (m_worker.joinable()) m_worker.join();
    m_worker = std::thread(&MainWindow::RunPipelineWorker, this);
}

void MainWindow::RunPipelineWorker()
{
    bool success = false;
    try {
        const std::filesystem::path input  = GetEditText(m_editInput);
        const std::filesystem::path output = GetEditText(m_editOutput);

        const bool hasExec = (::SendMessageW(m_chkExecBp, BM_GETCHECK, 0, 0) == BST_CHECKED);
        const bool hasIAT  = (::SendMessageW(m_chkIAT,    BM_GETCHECK, 0, 0) == BST_CHECKED);

        auto parseHex = [](const std::wstring& w) -> std::uintptr_t {
            return static_cast<std::uintptr_t>(std::wcstoull(w.c_str(), nullptr, 0));
        };

        const std::uintptr_t execBpVA = hasExec ? parseHex(GetEditText(m_editExecBp)) : 0;
        const std::uintptr_t iatVA    = hasIAT  ? parseHex(GetEditText(m_editIatVA))  : 0;
        const SIZE_T         iatSize  = hasIAT  ? static_cast<SIZE_T>(parseHex(GetEditText(m_editIatSize))) : 0;

        LOG_INFO("====== EVRE 1: Statik PE analizi ======");
        PEParser parser(input);
        parser.PrintPEInfo();

        LOG_INFO("====== EVRE 2: Dinamik OEP tespiti ======");
        DebuggerEngine engine;

        std::exception_ptr engineError;
        std::thread engineThread([&] {
            try { engine.Run(input); }
            catch (...) { engineError = std::current_exception(); }
        });

        ::Sleep(200);
        if (hasExec) {
            try {
                engine.SetHardwareBreakpoint(execBpVA, BreakpointType::Execute);
                LOG_INFO("GUI: Execute BP set @ 0x{:X}", execBpVA);
            } catch (const std::exception& e) {
                LOG_WARN("Execute BP konulamadi: {}", e.what());
            }
        } else {
            LOG_WARN("Execute BP secili degil — OEP otomatik bulunmayabilir.");
        }

        engineThread.join();
        if (engineError) std::rethrow_exception(engineError);

        if (!engine.IsOEPFound()) {
            LOG_ERROR("OEP tespit edilemedi, cikti yazilmayacak.");
            throw std::runtime_error("OEP bulunamadi");
        }

        const std::uintptr_t oep = engine.GetOEP();
        ProcessManager&      pm  = engine.Process();
        const std::uintptr_t imageBase = FindMainModuleBase(pm.ProcessHandle(), input);
        const DWORD oepRva = static_cast<DWORD>(oep - imageBase);

        LOG_INFO("OEP={:#x}  ImageBase={:#x}  RVA={:#x}", oep, imageBase, oepRva);

        LOG_INFO("====== EVRE 4: Bellek dump ======");
        Dumper dumper(pm, imageBase);
        dumper.CaptureFromMemory();
        dumper.SetImageBase(imageBase);
        dumper.SetOEP(oepRva);

        if (hasIAT) {
            LOG_INFO("====== EVRE 5: IAT yeniden insa ======");
            IATRebuilder rb(pm, imageBase);
            rb.EnumerateAndCacheExports();
            rb.ResolveIAT(iatVA, iatSize);
            rb.InjectInto(dumper);
        } else {
            LOG_WARN("IAT yeniden insa kapali — cikti exe loader hatasi verebilir.");
        }

        LOG_INFO("====== EVRE 6: Diske yaz ======");
        dumper.SaveAs(output);

        LOG_INFO(">>> BASARILI: {} <<<", output.string());
        success = true;
    }
    catch (const std::exception& e) {
        LOG_ERROR("Pipeline hatasi: {}", e.what());
    }
    catch (...) {
        LOG_ERROR("Pipeline bilinmeyen hata");
    }

    ::PostMessageW(m_hwnd, WM_APP_DONE, success ? 1 : 0, 0);
}
