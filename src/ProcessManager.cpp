#include "ProcessManager.h"

#include <format>     // C++20
#include <utility>
#include <cstring>

// =============================================================================
//  Kurucu / Yikici
// =============================================================================
ProcessManager::ProcessManager() = default;

ProcessManager::~ProcessManager()
{
    // Surec hala ayakta ise (Resume cagrilmadi veya Terminate cagrilmadi),
    // RAII ile guvenli bir kapanis saglariz. Sessizce sonlandiririz cunku
    // destructor istisna firlatmamalidir.
    Terminate(/*exitCode=*/1);
}

// ---- Tasima ----------------------------------------------------------------
ProcessManager::ProcessManager(ProcessManager&& other) noexcept
    : m_processHandle(std::move(other.m_processHandle)),
      m_threadHandle (std::move(other.m_threadHandle)),
      m_processId    (std::exchange(other.m_processId, 0)),
      m_threadId     (std::exchange(other.m_threadId,  0)) {}

ProcessManager& ProcessManager::operator=(ProcessManager&& other) noexcept
{
    if (this != &other) {
        Terminate(1);   // Mevcut sureci kapat
        m_processHandle = std::move(other.m_processHandle);
        m_threadHandle  = std::move(other.m_threadHandle);
        m_processId     = std::exchange(other.m_processId, 0);
        m_threadId      = std::exchange(other.m_threadId,  0);
    }
    return *this;
}

// =============================================================================
//  Start: CREATE_SUSPENDED ile yeni bir surec olustur
// =============================================================================
//  Onemli Windows API: CreateProcessW
//  - lpApplicationName : Calistirilacak .exe yolu (tam yol)
//  - lpCommandLine     : Komut satiri (MODIFIYE EDILEBILIR tampon olmali!)
//  - dwCreationFlags   : CREATE_SUSPENDED → ana iplikcik ASKIYA ALINMIS dogar.
//                        Boylece exe'nin tek satir kodu dahi calistirilmadan
//                        bellegine yazma, register'larini degistirme imkanimiz
//                        olur — unpacker'in temel kaldiraci budur.
//  - lpProcessInformation: PROCESS_INFORMATION → surec & ana iplikcik
//                          handle'larini ve PID/TID'leri dondurur.
// =============================================================================
void ProcessManager::Start(const std::filesystem::path& exePath,
                           const std::wstring& commandLine)
{
    if (IsRunning())
        throw ProcessCreationException("Bu ProcessManager zaten aktif bir surece sahip", 0);

    if (!std::filesystem::exists(exePath))
        throw ProcessCreationException(
            "Calistirilacak dosya yok: " + exePath.string(), ERROR_FILE_NOT_FOUND);

    // CreateProcessW lpCommandLine'i DEGISTIREBILIR; sabit string verilemez.
    // Bu yuzden modifiye edilebilir bir tampon hazirliyoruz.
    std::wstring cmdLine = commandLine.empty()
        ? L"\"" + exePath.wstring() + L"\""
        : commandLine;
    std::vector<wchar_t> cmdBuffer(cmdLine.begin(), cmdLine.end());
    cmdBuffer.push_back(L'\0');

    STARTUPINFOW        si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);

    const BOOL ok = ::CreateProcessW(
        exePath.wstring().c_str(),  // lpApplicationName
        cmdBuffer.data(),           // lpCommandLine (yazilabilir tampon)
        nullptr,                    // lpProcessAttributes
        nullptr,                    // lpThreadAttributes
        FALSE,                      // bInheritHandles
        CREATE_SUSPENDED,           // <<<<<< ASKIYA ALINMIS BASLATMA
        nullptr,                    // lpEnvironment (parent'in environment'i)
        nullptr,                    // lpCurrentDirectory
        &si,
        &pi
    );

    if (!ok) {
        throw ProcessCreationException(
            "CreateProcessW basarisiz: " + exePath.string());
    }

    // Handle sahipligini hemen RAII'ye devret — sonraki adimda istisna
    // olursa bile sizinti olmaz.
    m_processHandle.reset(pi.hProcess);
    m_threadHandle .reset(pi.hThread);
    m_processId = pi.dwProcessId;
    m_threadId  = pi.dwThreadId;
}

// =============================================================================
//  Resume / Suspend / Terminate
// =============================================================================
//  ResumeThread / SuspendThread:
//    Iplikciklerin "suspend count" sayacini -1 / +1 yapar. CREATE_SUSPENDED
//    ile baslatilan surecin ana iplikcigi 1 sayisinda dogar; bir kere
//    ResumeThread cagrisi exe'nin calismaya baslamasi icin yeterlidir.
// =============================================================================
void ProcessManager::Resume()
{
    if (!IsRunning())
        throw ProcessException("Resume cagrildi ama aktif surec yok", 0);

    if (::ResumeThread(m_threadHandle.get()) == static_cast<DWORD>(-1))
        throw ProcessException("ResumeThread basarisiz");
}

void ProcessManager::Suspend()
{
    if (!IsRunning())
        throw ProcessException("Suspend cagrildi ama aktif surec yok", 0);

    if (::SuspendThread(m_threadHandle.get()) == static_cast<DWORD>(-1))
        throw ProcessException("SuspendThread basarisiz");
}

// TerminateProcess: Sureci en sert bicimde sonlandirir — DLL_PROCESS_DETACH
// gibi bildirimler tetiklenmez. Yikicidan da cagrildigi icin noexcept'tir.
void ProcessManager::Terminate(UINT exitCode) noexcept
{
    if (m_processHandle) {
        ::TerminateProcess(m_processHandle.get(), exitCode);
        // Sonlandirma asenkron olabilir; kisa bir WaitForSingleObject ile
        // surecin gercekten oldugundan emin oluyoruz (sonra handle kapanir).
        ::WaitForSingleObject(m_processHandle.get(), 1000);
    }
    // UniqueHandle reset → CloseHandle otomatik cagrilir.
    m_threadHandle .reset();
    m_processHandle.reset();
    m_processId = 0;
    m_threadId  = 0;
}

// =============================================================================
//  IProcessMemory: ReadMemory / WriteMemory
// =============================================================================
//  ReadProcessMemory  → baska bir surecin sanal bellek alanindan okur.
//  WriteProcessMemory → baska bir surecin sanal bellek alanina yazar.
//
//  Onemli: Yazma islemi sirasinda hedef sayfa PAGE_READONLY ise Windows
//  otomatik olarak kopya-yazarken (copy-on-write) davranisi gosterir veya
//  basarisiz olur. Gerektiginde VirtualProtectEx ile sayfa korumasi
//  degistirilmelidir (bu sinif kapsamı disinda — ayri bir sorumluluk).
// =============================================================================
void ProcessManager::ReadMemory(LPCVOID address, void* buffer, SIZE_T size) const
{
    if (!IsRunning())
        throw ProcessMemoryException("Surec aktif degil", 0);

    SIZE_T bytesRead = 0;
    const BOOL ok = ::ReadProcessMemory(
        m_processHandle.get(), address, buffer, size, &bytesRead);

    if (!ok || bytesRead != size) {
        throw ProcessMemoryException(std::format(
            "ReadProcessMemory basarisiz @ 0x{:p} ({} / {} byte okundu)",
            address, bytesRead, size));
    }
}

void ProcessManager::WriteMemory(LPVOID address, const void* buffer, SIZE_T size) const
{
    if (!IsRunning())
        throw ProcessMemoryException("Surec aktif degil", 0);

    SIZE_T bytesWritten = 0;
    const BOOL ok = ::WriteProcessMemory(
        m_processHandle.get(), address, buffer, size, &bytesWritten);

    if (!ok || bytesWritten != size) {
        throw ProcessMemoryException(std::format(
            "WriteProcessMemory basarisiz @ 0x{:p} ({} / {} byte yazildi)",
            address, bytesWritten, size));
    }

    // Cache tutarliligi: kod sayfalarina yazdiysak CPU instruction cache'inin
    // taze veriyi gormesi icin FlushInstructionCache cagrilmali.
    ::FlushInstructionCache(m_processHandle.get(), address, size);
}

std::vector<std::uint8_t> ProcessManager::ReadBuffer(LPCVOID address, SIZE_T size) const
{
    std::vector<std::uint8_t> buf(size);
    ReadMemory(address, buf.data(), size);
    return buf;
}

// =============================================================================
//  IThreadContext: GetContext / SetContext
// =============================================================================
//  GetThreadContext: Yalnizca SUSPENDED durumdaki iplikcikten guvenilir
//  register snapshot'i alinir. Calisan bir iplikciktan okumak yarış kosulu
//  doğurur — bu yuzden cagrilmadan once Suspend() onerilir.
//
//  CONTEXT.ContextFlags bayragi alinacak register grubunu belirler:
//   - CONTEXT_CONTROL     → SegSs, Rsp, SegCs, Rip, EFlags
//   - CONTEXT_INTEGER     → Rax, Rbx, Rcx, ... (ya da Eax, Ebx, ...)
//   - CONTEXT_FULL        → yukaridakilerin tamami (bizim varsayilanimiz)
// =============================================================================
CONTEXT ProcessManager::GetContext() const
{
    if (!IsRunning())
        throw ProcessContextException("Surec aktif degil", 0);

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_FULL;

    if (!::GetThreadContext(m_threadHandle.get(), &ctx))
        throw ProcessContextException("GetThreadContext basarisiz");

    return ctx;
}

void ProcessManager::SetContext(const CONTEXT& ctx) const
{
    if (!IsRunning())
        throw ProcessContextException("Surec aktif degil", 0);

    // const_cast: SetThreadContext non-const CONTEXT* alir ama mantiken
    // veriyi degistirmez. Cagrian sahip oldugu yerel kopyayi vermeli.
    CONTEXT copy = ctx;
    if (!::SetThreadContext(m_threadHandle.get(), &copy))
        throw ProcessContextException("SetThreadContext basarisiz");
}

// =============================================================================
//  Konfor metodlar — Instruction Pointer & Accumulator
//  Derleme zaminda x64/x86 secilir; cross-arch debug (WOW64) destegi yok.
// =============================================================================
std::uintptr_t ProcessManager::GetInstructionPointer() const
{
    const CONTEXT c = GetContext();
#ifdef _WIN64
    return static_cast<std::uintptr_t>(c.Rip);
#else
    return static_cast<std::uintptr_t>(c.Eip);
#endif
}

void ProcessManager::SetInstructionPointer(std::uintptr_t ip) const
{
    CONTEXT c = GetContext();
#ifdef _WIN64
    c.Rip = static_cast<DWORD64>(ip);
#else
    c.Eip = static_cast<DWORD>(ip);
#endif
    SetContext(c);
}

std::uintptr_t ProcessManager::GetAccumulator() const
{
    const CONTEXT c = GetContext();
#ifdef _WIN64
    return static_cast<std::uintptr_t>(c.Rax);
#else
    return static_cast<std::uintptr_t>(c.Eax);
#endif
}

void ProcessManager::SetAccumulator(std::uintptr_t v) const
{
    CONTEXT c = GetContext();
#ifdef _WIN64
    c.Rax = static_cast<DWORD64>(v);
#else
    c.Eax = static_cast<DWORD>(v);
#endif
    SetContext(c);
}
