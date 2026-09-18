#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>
#include <memory>
#include <type_traits>

// =============================================================================
//  Hata hiyerarsisi
// =============================================================================
class ProcessException : public std::runtime_error {
public:
    ProcessException(const std::string& msg, DWORD lastError = ::GetLastError())
        : std::runtime_error(msg + " (GetLastError=" + std::to_string(lastError) + ")"),
          m_lastError(lastError) {}
    DWORD LastError() const noexcept { return m_lastError; }
private:
    DWORD m_lastError;
};

class ProcessCreationException : public ProcessException { using ProcessException::ProcessException; };
class ProcessMemoryException   : public ProcessException { using ProcessException::ProcessException; };
class ProcessContextException  : public ProcessException { using ProcessException::ProcessException; };

// =============================================================================
//  HANDLE icin RAII sarmalayici
//  CloseHandle'i destructor'da otomatik cagirir; hicbir yerde manuel
//  CloseHandle/handle leak gerekmez. (SRP: tek sorumluluk = handle yasam dongusu)
// =============================================================================
struct HandleDeleter {
    void operator()(HANDLE h) const noexcept {
        if (h && h != INVALID_HANDLE_VALUE) ::CloseHandle(h);
    }
};
// unique_ptr<void, Deleter> kalibi — HANDLE = void* oldugu icin uyumlu.
using UniqueHandle = std::unique_ptr<std::remove_pointer_t<HANDLE>, HandleDeleter>;

// =============================================================================
//  Soyut arayuzler (ISP + DIP)
//  Tuketici kodlar (ornegin Unpacker motoru) somut ProcessManager yerine
//  bu dar arayuzlere bagimli olabilir → birim testlerde sahteleyebilirsiniz.
// =============================================================================
class IProcessMemory {
public:
    virtual ~IProcessMemory() = default;
    virtual void ReadMemory (LPCVOID address, void*       buffer, SIZE_T size) const = 0;
    virtual void WriteMemory(LPVOID  address, const void* buffer, SIZE_T size) const = 0;
};

class IThreadContext {
public:
    virtual ~IThreadContext() = default;
    virtual CONTEXT GetContext() const           = 0;
    virtual void    SetContext(const CONTEXT& c) const = 0;
};

// =============================================================================
//  ProcessManager
//
//  Sorumluluk (SRP): Bir Windows surecinin yasam dongusunu (start/suspend/
//  resume/terminate), uzaktan bellek erisimini ve ana iplikcik (thread)
//  baglamini yonetmek.
//
//  Tasarim notlari:
//   - Surec CREATE_SUSPENDED ile baslatilir → unpacker, OEP'ye ulasana kadar
//     iplikcige adim adim kontrol verebilir.
//   - Handle'lar UniqueHandle (RAII) ile tutulur; istisna durumunda dahi
//     sizinti olmaz.
//   - Kopyalama yasak (surec sahipligi tekildir), tasima serbesttir.
// =============================================================================
class ProcessManager : public IProcessMemory, public IThreadContext {
public:
    // ---- Yasam dongusu ------------------------------------------------------
    ProcessManager();
    ~ProcessManager() override;

    // Kopyalama yasak — surec/iplikcik sahipligi paylasilamaz.
    ProcessManager(const ProcessManager&)            = delete;
    ProcessManager& operator=(const ProcessManager&) = delete;

    // Tasima serbest (factory / container kullanimi icin).
    ProcessManager(ProcessManager&&) noexcept;
    ProcessManager& operator=(ProcessManager&&) noexcept;

    // ---- Surec kontrolu -----------------------------------------------------

    // CreateProcessW + CREATE_SUSPENDED ile yeni bir surec olusturur.
    // commandLine opsiyoneldir; bos ise sadece exePath kullanilir.
    void Start(const std::filesystem::path& exePath,
               const std::wstring& commandLine = L"");

    // ResumeThread → askiya alinmis ana iplikcigi calistirmaya baslatir.
    void Resume();

    // SuspendThread → calisan iplikcigi tekrar askiya alir.
    void Suspend();

    // TerminateProcess + handle temizligi → hata/iptal yolunda guvenli kapanis.
    void Terminate(UINT exitCode = 0) noexcept;

    // ---- IProcessMemory -----------------------------------------------------

    // ReadProcessMemory sarmalayicisi. SIZE_T bytesRead doğrulanir, eksik
    // okumalarda istisna firlatilir.
    void ReadMemory (LPCVOID address, void*       buffer, SIZE_T size) const override;
    void WriteMemory(LPVOID  address, const void* buffer, SIZE_T size) const override;

    // Tip guvenli sarmalayicilar — POD turleri icin.
    template<typename T>
    T ReadValue(LPCVOID address) const {
        static_assert(std::is_trivially_copyable_v<T>, "T trivially-copyable olmali");
        T value{};
        ReadMemory(address, &value, sizeof(T));
        return value;
    }

    template<typename T>
    void WriteValue(LPVOID address, const T& value) const {
        static_assert(std::is_trivially_copyable_v<T>, "T trivially-copyable olmali");
        WriteMemory(address, &value, sizeof(T));
    }

    // Hedef adres aralığını std::vector<uint8_t> olarak okur — bellek dump
    // veya bolum analizi icin pratiktir.
    std::vector<std::uint8_t> ReadBuffer(LPCVOID address, SIZE_T size) const;

    // ---- IThreadContext -----------------------------------------------------

    // CONTEXT_FULL bayragi ile GetThreadContext cagrisi.
    CONTEXT GetContext() const override;

    // SetThreadContext — register'lar modifiye edildikten sonra geri yazilir.
    void    SetContext(const CONTEXT& ctx) const override;

    // ---- Konfor metodlar: EIP/RIP ve EAX/RAX --------------------------------
    //
    //  Unpacker tipik kullanimda yalnizca bu iki register'la ilgilenir:
    //   - RIP/EIP: OEP (Original Entry Point) buraya yazilir.
    //   - RAX/EAX: PE basliginin ImageBase'i CreateProcess sonrasi burada
    //              tasinir (Windows yuklecisinin gelenegi).
    //
    // Derleme mimarisine gore (x64 / x86) dogru alan secilir.
    std::uintptr_t GetInstructionPointer() const;
    void           SetInstructionPointer(std::uintptr_t ip) const;

    std::uintptr_t GetAccumulator() const;          // RAX (x64) / EAX (x86)
    void           SetAccumulator(std::uintptr_t v) const;

    // ---- Erisimciler --------------------------------------------------------
    [[nodiscard]] bool   IsRunning()       const noexcept { return m_processHandle != nullptr; }
    [[nodiscard]] HANDLE ProcessHandle()   const noexcept { return m_processHandle.get(); }
    [[nodiscard]] HANDLE ThreadHandle()    const noexcept { return m_threadHandle.get();  }
    [[nodiscard]] DWORD  ProcessId()       const noexcept { return m_processId; }
    [[nodiscard]] DWORD  ThreadId()        const noexcept { return m_threadId;  }

private:
    UniqueHandle m_processHandle;
    UniqueHandle m_threadHandle;
    DWORD        m_processId = 0;
    DWORD        m_threadId  = 0;
};
