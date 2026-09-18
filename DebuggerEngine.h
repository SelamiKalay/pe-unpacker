#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "IUnpacker.h"
#include "ProcessManager.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <unordered_map>
#include <vector>

// =============================================================================
//  Breakpoint turleri
// =============================================================================
enum class BreakpointType {
    Execute,      // Adresteki kod calistirilirsa tetiklenir
    Write,        // Adrese yazma yapilirsa tetiklenir
    ReadWrite,    // Okuma veya yazma tetikler
    PageGuard     // PAGE_GUARD bayragi — sayfaya ilk erişim tetikler
};

// Bir donanim breakpoint'i icin metadata (DR0..DR3'ten birine baglanir)
struct HardwareBreakpoint {
    std::uintptr_t address = 0;
    BreakpointType type    = BreakpointType::Execute;
    int            length  = 1;     // 1, 2, 4 veya 8 (x64)
    int            drIndex = -1;    // 0..3
    bool           active  = false;
};

// PAGE_GUARD breakpoint'i; sayfa bazinda calisir
struct PageGuardBreakpoint {
    std::uintptr_t baseAddress = 0;
    SIZE_T         regionSize  = 0;
    DWORD          oldProtect  = 0;
    bool           active      = false;
};

// =============================================================================
//  DebuggerEngine
//
//  IUnpacker stratejilerinden biridir: hedef sureci CREATE_SUSPENDED ile dogurur,
//  DebugActiveProcess ile baglanir ve WaitForDebugEvent / ContinueDebugEvent
//  dongusunu kurar.
//
//  OEP tespit yontemleri:
//   1. Hardware Execute breakpoint  → DR0..DR3 register'larina yazilan adresler
//      tetiklendiginde EXCEPTION_SINGLE_STEP yakalanir.
//   2. Page Guard                   → VirtualProtectEx ile PAGE_GUARD bayragi
//      konan sayfaya ilk erişim STATUS_GUARD_PAGE_VIOLATION fırlatir; ardından
//      bayrak otomatik temizlenir (Windows davranisi).
//
//  Pratik unpacker yaklasimi: stub'un yazip atladigi hedef bolge yazilabilir
//  ve calistirilabilir (PAGE_EXECUTE_READWRITE) olur. Bu bolgelere PAGE_GUARD
//  koyup tetiklenen ilk adresi OEP olarak kaydederiz.
// =============================================================================
class DebuggerEngine : public IUnpacker {
public:
    DebuggerEngine();
    ~DebuggerEngine() override;

    DebuggerEngine(const DebuggerEngine&)            = delete;
    DebuggerEngine& operator=(const DebuggerEngine&) = delete;

    // ---- IUnpacker ----------------------------------------------------------
    void Run(const std::filesystem::path& targetExe) override;
    [[nodiscard]] bool          IsOEPFound() const noexcept override { return m_oepFound; }
    [[nodiscard]] std::uintptr_t GetOEP()    const noexcept override { return m_oep; }

    // ---- Breakpoint API -----------------------------------------------------

    // Donanim breakpoint'i ekler. drIndex < 0 ise ilk bos slot kullanilir.
    // type = Execute → "Break On Execution"
    // type = Write / ReadWrite → "Break On Access"
    void SetHardwareBreakpoint(std::uintptr_t address,
                               BreakpointType type,
                               int length = 1);

    // Belirtilen bolgeye PAGE_GUARD koyar (sayfa hizalanir).
    void SetPageGuardBreakpoint(std::uintptr_t address, SIZE_T size);

    // Tum donanim breakpoint'lerini temizler (DR0..DR3 ve DR7 sifirlanir).
    void ClearAllHardwareBreakpoints();

    // Run() OEP yakalayip dondukten sonra, surec ana iplikciktan suspend
    // edilmis halde durur. Bu accessor, Dumper / IATRebuilder gibi
    // bilesenlerin sureci kullanabilmesi icindir.
    [[nodiscard]] ProcessManager&       Process()       noexcept { return *m_process; }
    [[nodiscard]] const ProcessManager& Process() const noexcept { return *m_process; }

private:
    // ---- Debug Loop ---------------------------------------------------------
    void DebugLoop();
    DWORD HandleException(const DEBUG_EVENT& ev);
    DWORD HandleHardwareBreakpoint(DWORD threadId, std::uintptr_t addr);
    DWORD HandlePageGuard(DWORD threadId, std::uintptr_t faultAddr);

    // Yeni iplikciklere mevcut donanim breakpoint setini uygular
    void ApplyHardwareBreakpointsToThread(HANDLE hThread);

    // ---- DR7 / DR0..DR3 yardimcilari ----------------------------------------
    static void EncodeDR7(DWORD64& dr7, int slot, BreakpointType type, int length);
    static void ClearDR7Slot(DWORD64& dr7, int slot);
    int  AllocateDrSlot();

    // ---- Uye degiskenler ----------------------------------------------------
    std::unique_ptr<ProcessManager> m_process;

    // Debug oturumu durumu
    std::atomic<bool> m_running        { false };
    bool              m_oepFound       = false;
    std::uintptr_t    m_oep            = 0;
    bool              m_firstBreakpointSeen = false;   // loader'in INT3'unu atla

    // Surec/iplikcik tablolari (debug event'leri uretir)
    std::unordered_map<DWORD, HANDLE> m_threads;       // tid -> hThread

    // Aktif breakpoint kayıtları
    HardwareBreakpoint                m_hwBreakpoints[4]{};   // DR0..DR3
    std::vector<PageGuardBreakpoint>  m_pageGuards;
};
