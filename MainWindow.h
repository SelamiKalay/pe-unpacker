#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <atomic>
#include <string>
#include <thread>

class MainWindow {
public:
    bool Create(HINSTANCE hInst, int nCmdShow);
    int  RunMessageLoop();

private:
    // ---- Win32 callback'leri ------------------------------------------------
    static LRESULT CALLBACK WndProcStatic(HWND, UINT, WPARAM, LPARAM);
    LRESULT WndProc(UINT msg, WPARAM wp, LPARAM lp);

    // ---- Olay isleyicileri --------------------------------------------------
    void OnCreate();
    void OnCommand(WORD id);
    void OnBrowseInput();
    void OnBrowseOutput();
    void OnAnalyze();
    void OnUnpack();
    void OnClear();

    // ---- Yardimcilar --------------------------------------------------------
    void AppendLog(int level, const std::wstring& text);
    void SetStatus(const std::wstring& text);
    void SetBusy(bool busy);
    std::wstring GetEditText(HWND hEdit) const;

    // Worker thread (heavy lift)
    void RunPipelineWorker();

    // ---- Pencere & kontroller ----------------------------------------------
    HINSTANCE m_hInst   = nullptr;
    HWND      m_hwnd    = nullptr;

    HWND m_editInput    = nullptr;
    HWND m_editOutput   = nullptr;

    HWND m_chkExecBp    = nullptr;
    HWND m_editExecBp   = nullptr;

    HWND m_chkIAT       = nullptr;
    HWND m_editIatVA    = nullptr;
    HWND m_editIatSize  = nullptr;

    HWND m_btnAnalyze   = nullptr;
    HWND m_btnUnpack    = nullptr;
    HWND m_btnClear     = nullptr;
    HWND m_btnBrowseIn  = nullptr;
    HWND m_btnBrowseOut = nullptr;

    HWND m_editLog      = nullptr;
    HWND m_status       = nullptr;

    HFONT m_font        = nullptr;
    HFONT m_fontMono    = nullptr;

    std::thread       m_worker;
    std::atomic<bool> m_busy{false};
};
