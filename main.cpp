// =============================================================================
//  Executable Unpacker — Orchestrator
//
//  Boru hatti:
//    [1] PEParser           → input dosyasinin statik analizi
//    [2] DebuggerEngine     → CREATE_SUSPENDED + debug loop, OEP tespit
//    [3] Dumper             → bellekten section'lari yakala, header guncelle
//    [4] IATRebuilder       → import tablosunu yeniden insa et (.scy0)
//    [5] Dumper.SaveAs      → diske yaz
//
//  Kullanim:
//    unpacker.exe <input.exe> <output.exe>
//                 [--bp-exec <VA>]   (OEP icin HW execute BP)
//                 [--page-guard <VA> <size>]  (OEP icin PageGuard)
//                 [--iat <VA> <size>]         (IAT yeniden insa icin bolge)
//
//  Ornek (sentetik):
//    unpacker.exe sample.exe unpacked.exe ^
//                 --bp-exec 0x401000 ^
//                 --iat     0x40A000 0x200
// =============================================================================

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <psapi.h>

#include "PEParser.h"
#include "ProcessManager.h"
#include "DebuggerEngine.h"
#include "Dumper.h"
#include "IATRebuilder.h"
#include "Logger.h"

#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>
#include <cwctype>
#include <cstdlib>

#pragma comment(lib, "psapi.lib")

// =============================================================================
//  CLI argümanlari
// =============================================================================
struct CliArgs {
    std::filesystem::path input;
    std::filesystem::path output;

    bool                  hasExecBp   = false;
    std::uintptr_t        execBpVA    = 0;

    bool                  hasPageGuard = false;
    std::uintptr_t        pgVA         = 0;
    SIZE_T                pgSize       = 0;

    bool                  hasIAT      = false;
    std::uintptr_t        iatVA       = 0;
    SIZE_T                iatSize     = 0;
};

static void PrintUsage()
{
    std::cerr <<
        "Kullanim: unpacker.exe <input.exe> <output.exe>\n"
        "          [--bp-exec   <VA>]            HW execute breakpoint @ VA\n"
        "          [--page-guard <VA> <size>]    PAGE_GUARD bolgesi\n"
        "          [--iat        <VA> <size>]    IAT bolgesi (yeniden insa icin)\n"
        "\n"
        "Tum sayisal degerler 0x ile hex veya ondalik kabul edilir.\n";
}

static std::uintptr_t ParseNumber(const char* s)
{
    return static_cast<std::uintptr_t>(std::strtoull(s, nullptr, 0));
}

static CliArgs ParseCli(int argc, char* argv[])
{
    if (argc < 3) { PrintUsage(); std::exit(1); }

    CliArgs a;
    a.input  = argv[1];
    a.output = argv[2];

    for (int i = 3; i < argc; ++i) {
        const std::string_view flag = argv[i];
        if (flag == "--bp-exec" && i + 1 < argc) {
            a.hasExecBp = true;
            a.execBpVA  = ParseNumber(argv[++i]);
        }
        else if (flag == "--page-guard" && i + 2 < argc) {
            a.hasPageGuard = true;
            a.pgVA   = ParseNumber(argv[++i]);
            a.pgSize = static_cast<SIZE_T>(ParseNumber(argv[++i]));
        }
        else if (flag == "--iat" && i + 2 < argc) {
            a.hasIAT  = true;
            a.iatVA   = ParseNumber(argv[++i]);
            a.iatSize = static_cast<SIZE_T>(ParseNumber(argv[++i]));
        }
        else {
            std::cerr << "Bilinmeyen argüman veya eksik deger: " << flag << "\n";
            PrintUsage();
            std::exit(1);
        }
    }
    return a;
}

// =============================================================================
//  Hedef surecte input.exe'nin yuklendigi base adresi bul
//  (ASLR varsa preferred ImageBase'ten farkli olabilir.)
// =============================================================================
static std::uintptr_t FindMainModuleBase(HANDLE hProc,
                                         const std::filesystem::path& exePath)
{
    std::vector<HMODULE> mods(512);
    DWORD needed = 0;
    if (!::EnumProcessModulesEx(hProc, mods.data(),
                                static_cast<DWORD>(mods.size() * sizeof(HMODULE)),
                                &needed, LIST_MODULES_ALL))
    {
        throw std::runtime_error("EnumProcessModulesEx basarisiz");
    }
    mods.resize(needed / sizeof(HMODULE));

    // Once dosya adina gore eslestir
    const auto targetBase = exePath.filename().wstring();
    for (HMODULE m : mods) {
        wchar_t buf[MAX_PATH] = {};
        if (::GetModuleFileNameExW(hProc, m, buf, MAX_PATH)) {
            std::filesystem::path p(buf);
            if (::_wcsicmp(p.filename().c_str(), targetBase.c_str()) == 0)
                return reinterpret_cast<std::uintptr_t>(m);
        }
    }
    // Yedek: ilk modul (genellikle exe'nin kendisidir)
    if (!mods.empty()) return reinterpret_cast<std::uintptr_t>(mods[0]);
    throw std::runtime_error("Ana modul bulunamadi");
}

// =============================================================================
//  Ana akis
// =============================================================================
int wmain_impl(const CliArgs& args)
{
    // ── EVRE 1: Statik analiz ──────────────────────────────────────────────
    LOG_INFO("====== EVRE 1: Statik PE analizi ======");
    PEParser parser(args.input);
    parser.PrintPEInfo();

    // ── EVRE 2: Debugger ile OEP tespiti ──────────────────────────────────
    LOG_INFO("====== EVRE 2: Dinamik OEP tespiti ======");
    DebuggerEngine engine;

    // DebuggerEngine.Run() icinde:
    //   1) ProcessManager CREATE_SUSPENDED ile sureci dogurur
    //   2) DebugActiveProcess ile baglanir
    //   3) Resume → debug dongusu baslar
    //
    // Kullanici BP'lerini Run() oncesi koymaliyiz ki sistem ilk INT3'una
    // gelene kadar etkili olsunlar. Ne yazik ki Run() bloklayicidir; bu
    // yuzden Run icinde once "first chance" event'i bekliyoruz: ilk INT3
    // sonrasi (loader breakpoint) BP'leri kuruyoruz.
    //
    // Burada basit yontem: dogrudan iletecegimiz icin Run'a girmeden
    // breakpoint metodlarini engine icinden sonra cagiramayiz. Pratikte
    // bu API'yi Attach()+Pump() seklinde ikiye bolmek istersiniz; egitsel
    // basitlik icin loader-BP sonrasi engine ic mekanigi BP'leri kabul edecek
    // sekilde tasarlandi (SetHardwareBreakpoint mevcut thread'lere uygular).
    //
    // Dolayisiyla CLI'dan gelen BP istekleri dongu sirasinda set edilemez.
    // Egitsel demo icin sunlardan birini secin:
    //   A) Run'i ayri thread'de baslat, kisa bir gecikme ardindan BP koy
    //   B) DebuggerEngine'i Attach() + Pump() seklinde refactor et
    //
    // Bu orchestrator (A) varyantini secer:
    std::exception_ptr engineError;
    std::thread engineThread([&] {
        try { engine.Run(args.input); }
        catch (...) { engineError = std::current_exception(); }
    });

    // 200ms bekle → loader baslangic kismini gecsin, ana iplikcik ayakta olsun
    ::Sleep(200);

    if (args.hasExecBp) {
        try {
            engine.SetHardwareBreakpoint(args.execBpVA, BreakpointType::Execute);
            LOG_INFO("CLI: Execute BP set @ 0x{:X}", args.execBpVA);
        } catch (const std::exception& e) {
            LOG_WARN("Execute BP konulamadi: {}", e.what());
        }
    }
    if (args.hasPageGuard) {
        try {
            engine.SetPageGuardBreakpoint(args.pgVA, args.pgSize);
            LOG_INFO("CLI: PAGE_GUARD set @ 0x{:X} ({} byte)", args.pgVA, args.pgSize);
        } catch (const std::exception& e) {
            LOG_WARN("PAGE_GUARD konulamadi: {}", e.what());
        }
    }
    if (!args.hasExecBp && !args.hasPageGuard) {
        LOG_WARN("Hicbir OEP tetigi belirtilmedi → engine yalnizca debug "
                 "olaylarini izleyecek, OEP tespit edilmeyebilir.");
    }

    engineThread.join();
    if (engineError) std::rethrow_exception(engineError);

    if (!engine.IsOEPFound()) {
        LOG_ERROR("OEP tespit edilemedi, dump yapilmayacak.");
        return 2;
    }

    const std::uintptr_t oep = engine.GetOEP();
    ProcessManager&      pm  = engine.Process();
    LOG_INFO("OEP (mutlak VA) = 0x{:X}", oep);

    // ── EVRE 3: ImageBase tespiti ─────────────────────────────────────────
    LOG_INFO("====== EVRE 3: ImageBase tespiti ======");
    const std::uintptr_t imageBase =
        FindMainModuleBase(pm.ProcessHandle(), args.input);
    LOG_INFO("Hedefin ImageBase = 0x{:X}", imageBase);

    if (oep < imageBase) {
        LOG_ERROR("OEP, ImageBase'in altinda — RVA hesabi gecersiz");
        return 3;
    }
    const DWORD oepRva = static_cast<DWORD>(oep - imageBase);

    // ── EVRE 4: Bellek dump ───────────────────────────────────────────────
    LOG_INFO("====== EVRE 4: Bellek dump ======");
    Dumper dumper(pm, imageBase);
    dumper.CaptureFromMemory();
    dumper.SetImageBase(imageBase);
    dumper.SetOEP(oepRva);

    // ── EVRE 5: IAT yeniden insa (opsiyonel) ──────────────────────────────
    if (args.hasIAT) {
        LOG_INFO("====== EVRE 5: IAT yeniden insa ======");
        IATRebuilder rb(pm, imageBase);
        rb.EnumerateAndCacheExports();
        rb.ResolveIAT(args.iatVA, args.iatSize);
        rb.InjectInto(dumper);
    } else {
        LOG_WARN("--iat belirtilmedi → import tablosu eski haliyle birakildi. "
                 "Cikti exe Windows loader tarafindan kabul edilmeyebilir.");
    }

    // ── EVRE 6: Diske yaz ─────────────────────────────────────────────────
    LOG_INFO("====== EVRE 6: Diske yaz ======");
    dumper.SaveAs(args.output);

    LOG_INFO(">>> BASARILI: {} <<<", args.output.string());
    return 0;
}

// =============================================================================
//  Giris noktasi + global istisna kalkani
// =============================================================================
int main(int argc, char* argv[])
{
    try {
        const auto args = ParseCli(argc, argv);
        return wmain_impl(args);
    }
    catch (const PEException& e) {
        std::cerr << "[PEParser]   " << e.what() << "\n"; return 10;
    }
    catch (const ProcessException& e) {
        std::cerr << "[Process]    " << e.what() << "\n"; return 11;
    }
    catch (const DumperException& e) {
        std::cerr << "[Dumper]     " << e.what() << "\n"; return 12;
    }
    catch (const IATRebuilderException& e) {
        std::cerr << "[IATRebuild] " << e.what() << "\n"; return 13;
    }
    catch (const std::exception& e) {
        std::cerr << "[FATAL]      " << e.what() << "\n"; return 99;
    }
}
