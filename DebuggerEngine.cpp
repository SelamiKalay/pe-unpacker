#include "DebuggerEngine.h"
#include "Logger.h"

#include <stdexcept>
#include <string>

// =============================================================================
//  Sabitler
// =============================================================================
//  STATUS_GUARD_PAGE_VIOLATION = 0x80000001L
//  EXCEPTION_SINGLE_STEP        = 0x80000004L  (donanim BP'leri burada gelir)
//  EXCEPTION_BREAKPOINT         = 0x80000003L  (INT3 / yazilim BP)
//
//  windows.h bazi sürümlerinde STATUS_GUARD_PAGE_VIOLATION'i tanimlamiyor;
//  bu yuzden manuel tanimlama:
#ifndef STATUS_GUARD_PAGE_VIOLATION
#  define STATUS_GUARD_PAGE_VIOLATION ((DWORD)0x80000001L)
#endif

// =============================================================================
//  Kurucu / Yikici
// =============================================================================
DebuggerEngine::DebuggerEngine()
    : m_process(std::make_unique<ProcessManager>()) {}

DebuggerEngine::~DebuggerEngine()
{
    // Hala calisiyorsa once debug oturumunu kibarca kapat.
    if (m_running.load()) {
        m_running = false;
        if (m_process->IsRunning())
            ::DebugActiveProcessStop(m_process->ProcessId());
    }
    // Yedek thread handle'larini kapat
    for (auto& [tid, h] : m_threads) {
        if (h && h != INVALID_HANDLE_VALUE) ::CloseHandle(h);
    }
    // m_process destructor'i kalan tum kaynaklari temizler (RAII).
}

// =============================================================================
//  Run: hedef exe'yi yukle, debugger olarak bagla, dongu kur
// =============================================================================
//
//  Akis:
//   1. ProcessManager.Start() — CREATE_SUSPENDED ile dogar.
//   2. DebugActiveProcess(pid) — bizi resmi debugger yapar. Bundan sonra
//      surecten gelen tum exception'lar bize teslim edilir.
//   3. ProcessManager.Resume() — ana iplikcik calismaya baslar.
//   4. DebugLoop() — WaitForDebugEvent ile event tuketir.
// =============================================================================
void DebuggerEngine::Run(const std::filesystem::path& targetExe)
{
    LOG_INFO("Hedef yukleniyor: {}", targetExe.string());
    m_process->Start(targetExe);
    LOG_INFO("Surec olusturuldu (PID={}, TID={})",
             m_process->ProcessId(), m_process->ThreadId());

    if (!::DebugActiveProcess(m_process->ProcessId())) {
        throw std::runtime_error("DebugActiveProcess basarisiz");
    }
    LOG_INFO("Debugger baglandi (PID={})", m_process->ProcessId());

    // Debugger detach edildiginde, oturumu surec olumune bagla. Boylece
    // debugger crash olsa bile debuggee canli kalmaz.
    ::DebugSetProcessKillOnExit(TRUE);

    m_running = true;
    m_process->Resume();   // Artik kod akmaya basliyor → ilk event birazdan gelecek

    DebugLoop();
}

// =============================================================================
//  DebugLoop — kalp atisi
//
//  KURALLAR (yaygin hatalardan kacinmak icin):
//   1. WaitForDebugEvent / ContinueDebugEvent CIFTLERI esit sayida olmalidir.
//      Her event'e karsi MUTLAKA ContinueDebugEvent cagrilir, yoksa surec
//      donar.
//   2. Bu dongu, debugger oturumunu acan IPLIKCIK ile ayni iplikcikte
//      koşmalidir (Windows kurali). Bu yuzden Run() icinden cagrilir,
//      ayri bir thread'e tasinmaz.
//   3. EXCEPTION_DEBUG_EVENT icinde "first chance" exception, debugee'nin
//      kendi handler'ina ulasmamis demektir. Bizim isimize gelmeyenleri
//      DBG_EXCEPTION_NOT_HANDLED ile geri veririz; debugee SEH ile yakalar.
//   4. CREATE_PROCESS_DEBUG_EVENT ve LOAD_DLL_DEBUG_EVENT bize 'hFile'
//      acik handle teslim eder; KAPATMAMIZ gerekir, aksi halde HANDLE leak.
// =============================================================================
void DebuggerEngine::DebugLoop()
{
    while (m_running.load() && !m_oepFound) {
        DEBUG_EVENT ev{};

        // INFINITE bekleme — surecten event gelmedikce burada kaliriz.
        if (!::WaitForDebugEvent(&ev, INFINITE)) {
            LOG_ERROR("WaitForDebugEvent basarisiz: {}", ::GetLastError());
            break;
        }

        DWORD continueStatus = DBG_CONTINUE;

        switch (ev.dwDebugEventCode) {

        // --- Surec olusturuldu (ilk event, gelmeyi garanti eder) ------------
        case CREATE_PROCESS_DEBUG_EVENT: {
            const auto& info = ev.u.CreateProcessInfo;
            LOG_EVENT("CREATE_PROCESS @ 0x{:X}  ImageBase=0x{:X}",
                reinterpret_cast<std::uintptr_t>(info.lpStartAddress),
                reinterpret_cast<std::uintptr_t>(info.lpBaseOfImage));
            m_threads[ev.dwThreadId] = info.hThread;
            if (info.hFile) ::CloseHandle(info.hFile);  // leak onleme
            break;
        }

        // --- DLL yuklendi --------------------------------------------------
        case LOAD_DLL_DEBUG_EVENT: {
            const auto& info = ev.u.LoadDll;
            LOG_EVENT("LOAD_DLL @ 0x{:X}",
                reinterpret_cast<std::uintptr_t>(info.lpBaseOfDll));
            if (info.hFile) ::CloseHandle(info.hFile);
            break;
        }

        case UNLOAD_DLL_DEBUG_EVENT:
            LOG_EVENT("UNLOAD_DLL @ 0x{:X}",
                reinterpret_cast<std::uintptr_t>(ev.u.UnloadDll.lpBaseOfDll));
            break;

        // --- Yeni iplikcik dogdu → DR register'larimizi ona da uygula ------
        case CREATE_THREAD_DEBUG_EVENT: {
            const auto& info = ev.u.CreateThread;
            LOG_EVENT("CREATE_THREAD TID={} StartAddr=0x{:X}",
                ev.dwThreadId,
                reinterpret_cast<std::uintptr_t>(info.lpStartAddress));
            m_threads[ev.dwThreadId] = info.hThread;
            ApplyHardwareBreakpointsToThread(info.hThread);
            break;
        }

        case EXIT_THREAD_DEBUG_EVENT:
            LOG_EVENT("EXIT_THREAD TID={} code={}",
                ev.dwThreadId, ev.u.ExitThread.dwExitCode);
            m_threads.erase(ev.dwThreadId);
            break;

        // --- Surec sonlandi -------------------------------------------------
        case EXIT_PROCESS_DEBUG_EVENT:
            LOG_EVENT("EXIT_PROCESS code={}", ev.u.ExitProcess.dwExitCode);
            m_running = false;
            break;

        // --- Exception — bizim ana ilgi alanimiz ---------------------------
        case EXCEPTION_DEBUG_EVENT:
            continueStatus = HandleException(ev);
            break;

        case OUTPUT_DEBUG_STRING_EVENT:
            LOG_EVENT("OutputDebugString'ten mesaj (uzunluk={})",
                ev.u.DebugString.nDebugStringLength);
            break;

        default:
            LOG_WARN("Bilinmeyen debug event kodu: {}", ev.dwDebugEventCode);
            break;
        }

        // Her event icin ZORUNLU: ContinueDebugEvent
        if (!::ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, continueStatus)) {
            LOG_ERROR("ContinueDebugEvent basarisiz: {}", ::GetLastError());
            break;
        }
    }

    LOG_INFO("Debug dongusu sonlandi. OEP bulundu = {}", m_oepFound ? "EVET" : "HAYIR");
    if (m_oepFound)
        LOG_INFO("Tespit edilen OEP: 0x{:X}", m_oep);
}

// =============================================================================
//  HandleException — exception turune gore dallanır
// =============================================================================
DWORD DebuggerEngine::HandleException(const DEBUG_EVENT& ev)
{
    const auto& er    = ev.u.Exception.ExceptionRecord;
    const auto code   = er.ExceptionCode;
    const auto addr   = reinterpret_cast<std::uintptr_t>(er.ExceptionAddress);
    const bool first  = ev.u.Exception.dwFirstChance != 0;

    LOG_EVENT("EXCEPTION code=0x{:08X} addr=0x{:X} first-chance={}",
              static_cast<DWORD>(code), addr, first ? "evet" : "hayir");

    switch (code) {
    case EXCEPTION_BREAKPOINT:
        // Windows yukleyici, debugger bagliyken surec icinde bir kez
        // INT3 atar → bunu sessizce yutariz. Sonraki INT3'ler kullanici
        // breakpoint'leri sayilabilir.
        if (!m_firstBreakpointSeen) {
            m_firstBreakpointSeen = true;
            LOG_INFO("Loader'in initial INT3'u atlandi");
            return DBG_CONTINUE;
        }
        LOG_INFO("Yazilim breakpoint @ 0x{:X}", addr);
        return DBG_CONTINUE;

    case EXCEPTION_SINGLE_STEP:
        // Donanim breakpoint'leri SINGLE_STEP olarak gelir; DR6'da hangi
        // slotun tetiklendigi yazar.
        return HandleHardwareBreakpoint(ev.dwThreadId, addr);

    case STATUS_GUARD_PAGE_VIOLATION:
        // PAGE_GUARD bayragi bir kez tetiklendi → bayrak otomatik
        // kaldirildi. Hedef adres ExceptionInformation[1]'de.
        {
            const std::uintptr_t faultAddr = (er.NumberParameters >= 2)
                ? static_cast<std::uintptr_t>(er.ExceptionInformation[1])
                : addr;
            return HandlePageGuard(ev.dwThreadId, faultAddr);
        }

    case EXCEPTION_ACCESS_VIOLATION:
        LOG_WARN("Access Violation @ 0x{:X} — debugee'ye iletildi", addr);
        return DBG_EXCEPTION_NOT_HANDLED;

    default:
        // Tanimadigimiz exception'lari debugee'nin kendi handler'larina ilet.
        return DBG_EXCEPTION_NOT_HANDLED;
    }
}

// =============================================================================
//  HandleHardwareBreakpoint — DR6'yi okuyup hangi BP tetiklendigini bul
// =============================================================================
//  DR6 statusu:
//   bit 0 → DR0, bit 1 → DR1, bit 2 → DR2, bit 3 → DR3
//
//  Tetik adresimiz Execute tipinde ise: OEP adayidir → kaydet ve dur.
// =============================================================================
DWORD DebuggerEngine::HandleHardwareBreakpoint(DWORD threadId, std::uintptr_t addr)
{
    auto it = m_threads.find(threadId);
    if (it == m_threads.end()) return DBG_CONTINUE;

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!::GetThreadContext(it->second, &ctx)) {
        LOG_ERROR("GetThreadContext basarisiz (HW BP)");
        return DBG_CONTINUE;
    }

    const DWORD64 dr6 = ctx.Dr6;
    int hitSlot = -1;
    for (int i = 0; i < 4; ++i) {
        if (dr6 & (1ULL << i)) { hitSlot = i; break; }
    }

    if (hitSlot < 0) {
        LOG_WARN("SINGLE_STEP geldi ama DR6'da slot yok @ 0x{:X}", addr);
        return DBG_CONTINUE;
    }

    const auto& bp = m_hwBreakpoints[hitSlot];
    LOG_EVENT("HW Breakpoint tetik: DR{} type={} @ 0x{:X}",
              hitSlot, static_cast<int>(bp.type), addr);

    if (bp.type == BreakpointType::Execute) {
        m_oep = addr;
        m_oepFound = true;
        LOG_INFO(">>> OEP TESPIT EDILDI: 0x{:X} <<<", addr);

        // OEP yakalandi → DR'leri temizle (yoksa ContinueDebugEvent sonrasi
        // ayni anda tekrar tetiklenir) ve tum iplikcikleri suspend et ki
        // surec dump icin stabil kalsin.
        ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0;
        ctx.Dr7 = 0;
        for (auto& [tid, h] : m_threads) ::SuspendThread(h);
        m_running = false;
    }

    // DR6 bit'lerini debugger temizlemeli (CPU kendi temizlemez)
    ctx.Dr6 = 0;
    ::SetThreadContext(it->second, &ctx);

    return DBG_CONTINUE;
}

// =============================================================================
//  HandlePageGuard — sayfa korumasi tetiklendi → adres OEP adayi
// =============================================================================
DWORD DebuggerEngine::HandlePageGuard(DWORD threadId, std::uintptr_t faultAddr)
{
    LOG_EVENT("PAGE_GUARD tetik: 0x{:X}", faultAddr);

    // Windows PAGE_GUARD bayragini ZATEN otomatik kaldirdı.
    // Bu adres OEP adayidir — paketleyici, hedef bolgeye atladi.
    for (auto& pg : m_pageGuards) {
        if (faultAddr >= pg.baseAddress &&
            faultAddr <  pg.baseAddress + pg.regionSize)
        {
            pg.active = false;
            m_oep      = faultAddr;
            m_oepFound = true;
            LOG_INFO(">>> OEP TESPIT EDILDI (PageGuard): 0x{:X} <<<", faultAddr);
            // Bellek stabilizasyonu icin tum iplikcikleri suspend et
            for (auto& [tid, h] : m_threads) ::SuspendThread(h);
            m_running = false;
            return DBG_CONTINUE;
        }
    }

    LOG_WARN("Bilmedigimiz bir bolgeden PAGE_GUARD geldi");
    return DBG_CONTINUE;
}

// =============================================================================
//  Breakpoint API
// =============================================================================
void DebuggerEngine::SetHardwareBreakpoint(std::uintptr_t address,
                                           BreakpointType type,
                                           int length)
{
    // Execute icin Intel spec'i 1 byte length zorunlu kilar
    if (type == BreakpointType::Execute && length != 1) {
        LOG_WARN("Execute BP length=1 olmali, duzeltildi");
        length = 1;
    }
    // length yalnizca 1/2/4/8 olabilir
    if (length != 1 && length != 2 && length != 4 && length != 8)
        throw std::invalid_argument("Gecersiz HW breakpoint uzunlugu");

    const int slot = AllocateDrSlot();
    if (slot < 0)
        throw std::runtime_error("Bos DR slotu yok (en fazla 4 HW BP)");

    auto& bp = m_hwBreakpoints[slot];
    bp.address = address;
    bp.type    = type;
    bp.length  = length;
    bp.drIndex = slot;
    bp.active  = true;

    LOG_INFO("HW BP eklendi: DR{} addr=0x{:X} type={} len={}",
             slot, address, static_cast<int>(type), length);

    // Mevcut tum iplikciklere uygula
    for (auto& [tid, h] : m_threads) {
        ApplyHardwareBreakpointsToThread(h);
    }
}

void DebuggerEngine::SetPageGuardBreakpoint(std::uintptr_t address, SIZE_T size)
{
    if (!m_process->IsRunning())
        throw std::runtime_error("Surec aktif degil");

    // Sayfa hizalama
    SYSTEM_INFO si{};
    ::GetSystemInfo(&si);
    const SIZE_T pageSize = si.dwPageSize;
    const std::uintptr_t base = address & ~(pageSize - 1);
    const SIZE_T region = ((address + size - base + pageSize - 1) / pageSize) * pageSize;

    DWORD oldProtect = 0;

    // VirtualProtectEx ile PAGE_GUARD bayragini ekle.
    //
    // ONEMLI: PAGE_GUARD baska bir koruma bayragiyla BIRLIKTE kullanilir.
    // Yazilabilir+calistirilabilir bolgeler genelde PAGE_EXECUTE_READWRITE'tir
    // (packer'larin yazip atladigi tipik bolge); biz bunu degistirmeden
    // sadece bayragi ekliyoruz.
    DWORD newProtect = PAGE_EXECUTE_READWRITE | PAGE_GUARD;

    if (!::VirtualProtectEx(m_process->ProcessHandle(),
                            reinterpret_cast<LPVOID>(base),
                            region, newProtect, &oldProtect))
    {
        throw std::runtime_error(
            "VirtualProtectEx basarisiz (PAGE_GUARD): " +
            std::to_string(::GetLastError()));
    }

    PageGuardBreakpoint pg{};
    pg.baseAddress = base;
    pg.regionSize  = region;
    pg.oldProtect  = oldProtect;
    pg.active      = true;
    m_pageGuards.push_back(pg);

    LOG_INFO("PageGuard BP eklendi: 0x{:X}..0x{:X} (eskiKoruma=0x{:X})",
             base, base + region, oldProtect);
}

void DebuggerEngine::ClearAllHardwareBreakpoints()
{
    for (auto& bp : m_hwBreakpoints) {
        bp.active = false;
        bp.drIndex = -1;
    }
    for (auto& [tid, h] : m_threads) {
        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (::GetThreadContext(h, &ctx)) {
            ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0;
            ctx.Dr6 = ctx.Dr7 = 0;
            ::SetThreadContext(h, &ctx);
        }
    }
    LOG_INFO("Tum HW breakpoint'ler temizlendi");
}

// =============================================================================
//  ApplyHardwareBreakpointsToThread
//  Hedef iplikcigin CONTEXT_DEBUG_REGISTERS bolumunu m_hwBreakpoints'a gore
//  yeniden insa eder. (DR register'lari thread-local oldugu icin her iplikcige
//  ayri uygulanmasi gerekir.)
// =============================================================================
void DebuggerEngine::ApplyHardwareBreakpointsToThread(HANDLE hThread)
{
    if (!hThread) return;

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!::GetThreadContext(hThread, &ctx)) return;

    DWORD64 dr7 = 0;
    DWORD64 drAddrs[4] = {0,0,0,0};

    for (int i = 0; i < 4; ++i) {
        const auto& bp = m_hwBreakpoints[i];
        if (!bp.active) { ClearDR7Slot(dr7, i); continue; }
        drAddrs[i] = static_cast<DWORD64>(bp.address);
        EncodeDR7(dr7, i, bp.type, bp.length);
    }

    ctx.Dr0 = drAddrs[0];
    ctx.Dr1 = drAddrs[1];
    ctx.Dr2 = drAddrs[2];
    ctx.Dr3 = drAddrs[3];
    ctx.Dr7 = dr7;

    if (!::SetThreadContext(hThread, &ctx))
        LOG_ERROR("SetThreadContext basarisiz (DR uygulamasi)");
}

// =============================================================================
//  DR7 encoding — Intel SDM Vol.3, Section 17.2.4
// =============================================================================
//  Slot 'i' (0..3) icin:
//    bit (2*i)       → L[i]  (Local enable, biz Local kullaniyoruz)
//    bit 16 + 4*i    → R/W[i] (00=Exec, 01=Write, 11=R/W)
//    bit 16 + 4*i+2  → LEN[i] (00=1B, 01=2B, 11=4B, 10=8B)
// =============================================================================
void DebuggerEngine::EncodeDR7(DWORD64& dr7, int slot, BreakpointType type, int length)
{
    // Once mevcut bit'leri temizle
    ClearDR7Slot(dr7, slot);

    // Local enable
    dr7 |= (1ULL << (slot * 2));

    DWORD64 cond = 0;
    switch (type) {
        case BreakpointType::Execute:   cond = 0b00; break;
        case BreakpointType::Write:     cond = 0b01; break;
        case BreakpointType::ReadWrite: cond = 0b11; break;
        default: break;
    }

    DWORD64 lenBits = 0;
    switch (length) {
        case 1: lenBits = 0b00; break;
        case 2: lenBits = 0b01; break;
        case 4: lenBits = 0b11; break;
        case 8: lenBits = 0b10; break;  // yalnizca x64
        default: break;
    }

    dr7 |= (cond    << (16 + slot * 4));
    dr7 |= (lenBits << (16 + slot * 4 + 2));
}

void DebuggerEngine::ClearDR7Slot(DWORD64& dr7, int slot)
{
    dr7 &= ~(0x3ULL << (slot * 2));         // L/G enable
    dr7 &= ~(0xFULL << (16 + slot * 4));    // R/W + LEN
}

int DebuggerEngine::AllocateDrSlot()
{
    for (int i = 0; i < 4; ++i)
        if (!m_hwBreakpoints[i].active) return i;
    return -1;
}
