#include "IATRebuilder.h"
#include "Logger.h"

#include <psapi.h>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <format>

#pragma comment(lib, "psapi.lib")

// =============================================================================
//  Kurucu
// =============================================================================
IATRebuilder::IATRebuilder(const ProcessManager& target, std::uintptr_t imageBase)
    : m_target(target), m_imageBase(imageBase)
{
#ifdef _WIN64
    m_is64bit = true;
#else
    m_is64bit = false;
#endif
}

std::size_t IATRebuilder::ResolvedCount() const noexcept
{
    std::size_t n = 0;
    for (const auto& c : m_chunks) n += c.entries.size();
    return n;
}

// =============================================================================
//  ADIM 1 + 2: EnumerateAndCacheExports
//
//  Kritik Windows API'leri:
//   - EnumProcessModulesEx(hProcess, LIST_MODULES_ALL): hedefe yuklenmis tum
//     modullerin HMODULE listesini doner. HMODULE = modulun base address'i.
//   - GetModuleFileNameExW(hProcess, hMod, ...): modul tam yolu.
//   - GetModuleInformation(hProcess, hMod, ...): MODULEINFO.SizeOfImage.
//
//  Export tablosu okuma:
//   - Hedef PE basligini ReadProcessMemory ile bizim adres uzayimiza al.
//   - DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] → IMAGE_EXPORT_DIRECTORY.
//   - AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals dizilerini
//     toplu olarak oku ve birlestir:
//        addressMap[base + funcRVA] = "DllName!FunctionName"
// =============================================================================
void IATRebuilder::EnumerateAndCacheExports()
{
    HANDLE hProc = m_target.ProcessHandle();
    if (!hProc) throw IATRebuilderException("Hedef surec handle bos");

    // Once gerekli buffer boyutunu ogren
    DWORD needed = 0;
    if (!::EnumProcessModulesEx(hProc, nullptr, 0, &needed, LIST_MODULES_ALL) || needed == 0)
        throw IATRebuilderException("EnumProcessModulesEx (probe) basarisiz");

    std::vector<HMODULE> mods(needed / sizeof(HMODULE));
    if (!::EnumProcessModulesEx(hProc, mods.data(), needed, &needed, LIST_MODULES_ALL))
        throw IATRebuilderException("EnumProcessModulesEx basarisiz");
    mods.resize(needed / sizeof(HMODULE));

    LOG_INFO("IATRebuilder: hedefde {} modul bulundu", mods.size());

    for (HMODULE hMod : mods) {
        wchar_t pathW[MAX_PATH] = {};
        if (!::GetModuleFileNameExW(hProc, hMod, pathW, MAX_PATH)) continue;

        MODULEINFO mi{};
        if (!::GetModuleInformation(hProc, hMod, &mi, sizeof(mi))) continue;

        // Modul dosya adini kucuk harfli ascii'ye cevir (kıyaslama icin)
        std::wstring wpath(pathW);
        const auto slash = wpath.find_last_of(L"\\/");
        std::wstring wname = (slash == std::wstring::npos) ? wpath : wpath.substr(slash + 1);

        std::string name;
        name.reserve(wname.size());
        for (wchar_t wc : wname) name.push_back(static_cast<char>(std::tolower(wc & 0xFF)));

        ModuleInfo info;
        info.name = name;
        info.base = reinterpret_cast<std::uintptr_t>(hMod);
        info.size = mi.SizeOfImage;
        m_modules.push_back(info);

        // Bu modulun export'larini onbellege al
        CacheModuleExports(hMod);
    }

    LOG_INFO("IATRebuilder: toplam {} adresli export onbelleklendi",
             m_addressMap.size());
}

// =============================================================================
//  CacheModuleExports — tek modulun export tablosunu oku
// =============================================================================
void IATRebuilder::CacheModuleExports(HMODULE hMod)
{
    const auto base = reinterpret_cast<std::uintptr_t>(hMod);

    // PE basligini hedef bellekten oku
    IMAGE_DOS_HEADER dos{};
    try { m_target.ReadMemory(reinterpret_cast<LPCVOID>(base), &dos, sizeof(dos)); }
    catch (...) { return; }
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return;

    // NT headers (Optional Header magic ile 32/64 ayrim)
    IMAGE_NT_HEADERS64 nt64{};
    IMAGE_NT_HEADERS32 nt32{};
    DWORD exportRVA = 0, exportSize = 0;
    bool is64 = false;

    DWORD sig = 0;
    try {
        m_target.ReadMemory(reinterpret_cast<LPCVOID>(base + dos.e_lfanew), &sig, sizeof(sig));
    } catch (...) { return; }
    if (sig != IMAGE_NT_SIGNATURE) return;

    // Magic'i okumak icin oncesinde FileHeader'i atla
    WORD optMagic = 0;
    try {
        m_target.ReadMemory(
            reinterpret_cast<LPCVOID>(base + dos.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER)),
            &optMagic, sizeof(optMagic));
    } catch (...) { return; }

    if (optMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        try { m_target.ReadMemory(reinterpret_cast<LPCVOID>(base + dos.e_lfanew),
                                  &nt64, sizeof(nt64)); }
        catch (...) { return; }
        is64 = true;
        exportRVA  = nt64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        exportSize = nt64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    } else if (optMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        try { m_target.ReadMemory(reinterpret_cast<LPCVOID>(base + dos.e_lfanew),
                                  &nt32, sizeof(nt32)); }
        catch (...) { return; }
        exportRVA  = nt32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        exportSize = nt32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    } else return;

    (void)is64;
    if (!exportRVA || !exportSize) return;

    IMAGE_EXPORT_DIRECTORY exp{};
    try { m_target.ReadMemory(reinterpret_cast<LPCVOID>(base + exportRVA),
                              &exp, sizeof(exp)); }
    catch (...) { return; }

    // Modul kendi adini export tablosunda tasir (exp.Name → ASCII)
    std::string moduleName;
    if (exp.Name) {
        char buf[260] = {};
        try { m_target.ReadMemory(reinterpret_cast<LPCVOID>(base + exp.Name),
                                  buf, sizeof(buf) - 1); }
        catch (...) {}
        moduleName.assign(buf);
        // küçük harfe çevir
        std::transform(moduleName.begin(), moduleName.end(), moduleName.begin(),
                       [](unsigned char c){ return std::tolower(c); });
    }
    if (moduleName.empty()) return;

    // Uc paralel diziyi toplu oku
    std::vector<DWORD> funcRVAs(exp.NumberOfFunctions);
    std::vector<DWORD> nameRVAs(exp.NumberOfNames);
    std::vector<WORD>  nameOrds(exp.NumberOfNames);

    try {
        if (exp.NumberOfFunctions)
            m_target.ReadMemory(reinterpret_cast<LPCVOID>(base + exp.AddressOfFunctions),
                                funcRVAs.data(),
                                exp.NumberOfFunctions * sizeof(DWORD));
        if (exp.NumberOfNames) {
            m_target.ReadMemory(reinterpret_cast<LPCVOID>(base + exp.AddressOfNames),
                                nameRVAs.data(),
                                exp.NumberOfNames * sizeof(DWORD));
            m_target.ReadMemory(reinterpret_cast<LPCVOID>(base + exp.AddressOfNameOrdinals),
                                nameOrds.data(),
                                exp.NumberOfNames * sizeof(WORD));
        }
    } catch (...) { return; }

    // 1. Once isimli export'lar
    for (DWORD i = 0; i < exp.NumberOfNames; ++i) {
        const WORD  ordIndex = nameOrds[i];
        if (ordIndex >= funcRVAs.size()) continue;
        const DWORD funcRVA  = funcRVAs[ordIndex];
        if (!funcRVA) continue;

        // Forwarded export (RVA export directory icinde) ise atla
        if (funcRVA >= exportRVA && funcRVA < exportRVA + exportSize) continue;

        char nameBuf[256] = {};
        try { m_target.ReadMemory(reinterpret_cast<LPCVOID>(base + nameRVAs[i]),
                                  nameBuf, sizeof(nameBuf) - 1); }
        catch (...) { continue; }

        ResolvedImport ri;
        ri.moduleName   = moduleName;
        ri.functionName = nameBuf;
        ri.ordinal      = static_cast<WORD>(ordIndex + exp.Base);
        ri.byOrdinal    = false;
        m_addressMap[base + funcRVA] = ri;
    }

    // 2. Yalniz ordinal export'lar (isim tablosunda yer almayanlar)
    //    NumberOfFunctions kadar dolas; isimli olanlar zaten yukarida isaretli.
    for (DWORD i = 0; i < exp.NumberOfFunctions; ++i) {
        const DWORD funcRVA = funcRVAs[i];
        if (!funcRVA) continue;
        if (funcRVA >= exportRVA && funcRVA < exportRVA + exportSize) continue;

        const std::uintptr_t va = base + funcRVA;
        if (m_addressMap.find(va) != m_addressMap.end()) continue;  // zaten isimli

        ResolvedImport ri;
        ri.moduleName = moduleName;
        ri.ordinal    = static_cast<WORD>(i + exp.Base);
        ri.byOrdinal  = true;
        m_addressMap[va] = ri;
    }
}

// =============================================================================
//  LookupAddress
// =============================================================================
bool IATRebuilder::LookupAddress(std::uintptr_t va, ResolvedImport& out) const
{
    const auto it = m_addressMap.find(va);
    if (it == m_addressMap.end()) return false;
    out = it->second;
    return true;
}

// =============================================================================
//  ADIM 3 + 4: ResolveIAT
//
//  Algoritma:
//   - iatStartVA'dan baslayarak pointer-pointer yuru.
//   - x64 → 8 byte, x86 → 4 byte step.
//   - Gecerli bir export adresine isaret eden her pointer'i o anki "chunk"a ekle.
//   - NULL pointer = chunk terminator (yeni DLL chunk'i basliyor).
//   - Onceki chunk'tan farkli modul → yeni chunk olarak ayir.
//   - Cözumlenemeyen ama NULL olmayan pointer'lar (paketleyici çöpu veya
//     redirected import) hala chunk parcasi olarak korunur — bu durumda
//     "missing" sayilir; pratikte Scylla'da kullanici manuel duzeltir.
//     Bizim implementasyonumuzda bu girisler atlanir ve uyari basilir.
// =============================================================================
void IATRebuilder::ResolveIAT(std::uintptr_t iatStartVA, SIZE_T iatSize)
{
    const SIZE_T step = m_is64bit ? 8 : 4;
    if (iatSize % step != 0)
        throw IATRebuilderException("iatSize, pointer boyutuna bolunmuyor");

    // IAT bolgesini topluca oku
    std::vector<std::uint8_t> raw(iatSize, 0);
    try { m_target.ReadMemory(reinterpret_cast<LPCVOID>(iatStartVA),
                              raw.data(), iatSize); }
    catch (...) { throw IATRebuilderException("IAT bolgesi okunamadi"); }

    ImportChunk current;
    auto flushCurrent = [&]() {
        if (!current.entries.empty()) {
            m_chunks.push_back(std::move(current));
            current = ImportChunk{};
        }
    };

    for (SIZE_T off = 0; off < iatSize; off += step) {
        std::uintptr_t ptr = 0;
        std::memcpy(&ptr, raw.data() + off, step);

        if (ptr == 0) {
            // NULL = chunk sonu
            flushCurrent();
            continue;
        }

        ResolvedImport ri;
        if (!LookupAddress(ptr, ri)) {
            LOG_WARN("IAT@0x{:X} +0x{:X}: 0x{:X} cozumlenemedi, atlandi",
                     iatStartVA, off, ptr);
            // Bu girisi atla; chunk butunlugunu korumak icin pad eklemek
            // gerekirse Scylla'nin "missing" tedavisi uygulanmalidir.
            continue;
        }

        // Modul degisti mi? → yeni chunk
        if (current.moduleName.empty()) {
            current.moduleName   = ri.moduleName;
            current.firstThunkVA = iatStartVA + off;
        } else if (current.moduleName != ri.moduleName) {
            flushCurrent();
            current.moduleName   = ri.moduleName;
            current.firstThunkVA = iatStartVA + off;
        }
        current.entries.push_back(ri);
    }
    flushCurrent();

    LOG_INFO("IATRebuilder: {} chunk, {} fonksiyon cozumlendi",
             m_chunks.size(), ResolvedCount());
    for (const auto& c : m_chunks) {
        LOG_INFO("  - {} @ FT=0x{:X}  ({} fonksiyon)",
                 c.moduleName, c.firstThunkVA, c.entries.size());
    }
}

// =============================================================================
//  ADIM 5 + 6: InjectInto
//
//  Olusturulacak section yerlesimi (ardisik bloklar):
//   [A] IMAGE_IMPORT_DESCRIPTOR[ chunks + 1 (zero terminator) ]
//   [B] Her chunk icin: IMAGE_THUNK_DATA[entries+1] (INT)
//       (FirstThunk orijinal IAT'i isaret ettigi icin yeni FT yazmiyoruz.)
//   [C] Her import icin: IMAGE_IMPORT_BY_NAME { hint; name; }
//   [D] DLL adi stringleri
//
//  Tum offset'ler section_RVA-rölatif → mutlak RVA'ya cevrilirken
//  section_RVA + ofset toplanir.
// =============================================================================
void IATRebuilder::InjectInto(Dumper& dumper)
{
    if (m_chunks.empty()) {
        LOG_WARN("InjectInto: cozulmus chunk yok, islem yapilmadi");
        return;
    }

    const SIZE_T thunkSize = m_is64bit ? sizeof(IMAGE_THUNK_DATA64)
                                       : sizeof(IMAGE_THUNK_DATA32);

    // ---- 1) Section RVA'sini onceden ogren ----
    // (Once tahmin, sonra dolduruyoruz; RVA'yi blob icindeki yapilara gomebilelim.)
    const DWORD sectionRVA = dumper.PredictNextSectionRVA();
    LOG_INFO("IATRebuilder: yeni section RVA tahmini = 0x{:X}", sectionRVA);

    // ---- 2) Layout'u hesapla: tum bloklarin section-rölatif offset'leri ----
    std::size_t off = 0;

    // [A] IMAGE_IMPORT_DESCRIPTOR dizisi (sonda zero terminator)
    const std::size_t descTableOffset = off;
    off += (m_chunks.size() + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR);

    // [B] INT (Import Name Table) — her chunk icin (+1 terminator)
    std::vector<std::size_t> intOffsets(m_chunks.size());
    for (std::size_t i = 0; i < m_chunks.size(); ++i) {
        intOffsets[i] = off;
        off += (m_chunks[i].entries.size() + 1) * thunkSize;
    }

    // [C] IMAGE_IMPORT_BY_NAME bloku — sadece isimli importlar icin
    std::vector<std::vector<std::size_t>> nameOffsets(m_chunks.size());
    for (std::size_t i = 0; i < m_chunks.size(); ++i) {
        nameOffsets[i].resize(m_chunks[i].entries.size(), 0);
        for (std::size_t j = 0; j < m_chunks[i].entries.size(); ++j) {
            if (m_chunks[i].entries[j].byOrdinal) continue;
            nameOffsets[i][j] = off;
            off += sizeof(WORD)
                 + m_chunks[i].entries[j].functionName.size() + 1;
            if (off & 1) ++off;   // WORD hizalama
        }
    }

    // [D] DLL adlari (ascii, null-terminated)
    std::vector<std::size_t> dllNameOffsets(m_chunks.size());
    for (std::size_t i = 0; i < m_chunks.size(); ++i) {
        dllNameOffsets[i] = off;
        off += m_chunks[i].moduleName.size() + 1;
    }

    // ---- 3) Blob'u doldur ----
    std::vector<std::uint8_t> blob(off, 0);

    // [D] DLL adlari
    for (std::size_t i = 0; i < m_chunks.size(); ++i) {
        std::memcpy(blob.data() + dllNameOffsets[i],
                    m_chunks[i].moduleName.data(),
                    m_chunks[i].moduleName.size());
    }

    // [C] IMAGE_IMPORT_BY_NAME (WORD hint + ASCIIZ name)
    for (std::size_t i = 0; i < m_chunks.size(); ++i) {
        for (std::size_t j = 0; j < m_chunks[i].entries.size(); ++j) {
            const auto& e = m_chunks[i].entries[j];
            if (e.byOrdinal) continue;
            const std::size_t pos = nameOffsets[i][j];
            *reinterpret_cast<WORD*>(blob.data() + pos) = e.ordinal;
            std::memcpy(blob.data() + pos + sizeof(WORD),
                        e.functionName.data(),
                        e.functionName.size());
        }
    }

    // [B] INT girisleri — her thunk:
    //      - byOrdinal → high-bit set + ordinal numarasi
    //      - byName    → IMAGE_IMPORT_BY_NAME'in RVA'si
    //   FirstThunk YENI YERE TASINMIYOR; orijinal IAT VA'sini koruyoruz.
    //   Boylece loader, calistirma aninda eski IAT bolgesini doldurur, ve
    //   dump edilmis kod (ki o IAT'yi referansliyor) sorunsuz calisir.
    auto writeThunk = [&](std::size_t pos, std::uint64_t value) {
        if (m_is64bit) std::memcpy(blob.data() + pos, &value, sizeof(std::uint64_t));
        else {
            const std::uint32_t v32 = static_cast<std::uint32_t>(value);
            std::memcpy(blob.data() + pos, &v32, sizeof(std::uint32_t));
        }
    };
    const std::uint64_t ordinalFlag = m_is64bit
        ? IMAGE_ORDINAL_FLAG64
        : IMAGE_ORDINAL_FLAG32;

    for (std::size_t i = 0; i < m_chunks.size(); ++i) {
        std::size_t pos = intOffsets[i];
        for (std::size_t j = 0; j < m_chunks[i].entries.size(); ++j) {
            const auto& e = m_chunks[i].entries[j];
            std::uint64_t thunkVal = 0;
            if (e.byOrdinal) {
                thunkVal = ordinalFlag | static_cast<std::uint64_t>(e.ordinal);
            } else {
                thunkVal = static_cast<std::uint64_t>(
                    sectionRVA + nameOffsets[i][j]);  // RVA of IMAGE_IMPORT_BY_NAME
            }
            writeThunk(pos, thunkVal);
            pos += thunkSize;
        }
        // Sonda NULL terminator (zaten 0)
    }

    // [A] IMAGE_IMPORT_DESCRIPTOR'leri yaz
    //
    //   - OriginalFirstThunk → INT (section'da, bizim ureticimiz)
    //   - FirstThunk         → orijinal IAT VA'si (process baseline RVA olarak)
    //   - Name               → DLL adi stringi (section'da)
    //   - TimeDateStamp      → 0 (bound olmayan import)
    //   - ForwarderChain     → 0
    for (std::size_t i = 0; i < m_chunks.size(); ++i) {
        IMAGE_IMPORT_DESCRIPTOR desc{};
        desc.OriginalFirstThunk = static_cast<DWORD>(sectionRVA + intOffsets[i]);
        desc.TimeDateStamp      = 0;
        desc.ForwarderChain     = 0;
        desc.Name               = static_cast<DWORD>(sectionRVA + dllNameOffsets[i]);
        // FirstThunk = orijinal IAT'in RVA'si (VA - ImageBase)
        desc.FirstThunk         = static_cast<DWORD>(
            m_chunks[i].firstThunkVA - m_imageBase);
        std::memcpy(blob.data() + descTableOffset
                                + i * sizeof(IMAGE_IMPORT_DESCRIPTOR),
                    &desc, sizeof(desc));
    }
    // Son IMAGE_IMPORT_DESCRIPTOR kayıtı zaten zero (terminator).

    // ---- 4) Section'i Dumper'a ekle ----
    const DWORD actualRVA = dumper.AddSection(
        ".scy0",
        blob,
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);

    if (actualRVA != sectionRVA) {
        // Tahmin yanlissa veriyi yeniden uretmek gerekirdi; bu durum normalde
        // olmamali (AddSection deterministik), ama defansif kontrol.
        throw IATRebuilderException(
            "Section RVA tahmini fiili degerden farkli; offset'ler bozulur");
    }

    // ---- 5) OptionalHeader.DataDirectory[IMPORT] guncelle ----
    dumper.SetDataDirectory(
        IMAGE_DIRECTORY_ENTRY_IMPORT,
        sectionRVA + static_cast<DWORD>(descTableOffset),
        static_cast<DWORD>((m_chunks.size() + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR)));

    // (Opsiyonel) DataDirectory[IAT]'yi de orijinal IAT'ye isaret edecek
    // sekilde bos birakmak gerekirse, Scylla genelde temizler. Burada
    // dokunmuyoruz — varsa eski deger korunur, yoksa 0 kalir.

    LOG_INFO("IATRebuilder: .scy0 section enjekte edildi, IMPORT directory guncellendi");
}
