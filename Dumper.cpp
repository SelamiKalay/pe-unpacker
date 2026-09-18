#include "Dumper.h"
#include "Logger.h"

#include <fstream>
#include <cstring>
#include <format>

// =============================================================================
//  Kurucu
// =============================================================================
Dumper::Dumper(const IProcessMemory& mem, std::uintptr_t imageBase)
    : m_mem(mem), m_imageBase(imageBase) {}

// =============================================================================
//  CaptureFromMemory
//
//  ADIM 1: Hedef surecten DOS + NT + Section tablosunu icine alacak kadar
//          (en az SizeOfHeaders) byte oku. Bu PE basligidir.
//  ADIM 2: Optional Header magic'ten 32/64-bit tespit et.
//  ADIM 3: Her bir section icin VirtualAddress'ten VirtualSize byte oku.
//  ADIM 4: Memory-aligned layout icin section header'lari yeniden yaz:
//            PointerToRawData = VirtualAddress
//            SizeOfRawData    = align(VirtualSize, FileAlignment)
//          FileAlignment'i SectionAlignment'a esitle.
// =============================================================================
//  Kritik Windows API'leri:
//   - ReadProcessMemory (IProcessMemory.ReadMemory ile sarmalanmis)
//   - VirtualQueryEx    : (bu siniftta kullanılmıyor ama production'da
//                          okunamayan sayfalari atlamak icin gerekli)
// =============================================================================
void Dumper::CaptureFromMemory()
{
    // --- ADIM 1: DOS header oku ---
    IMAGE_DOS_HEADER dos{};
    m_mem.ReadMemory(reinterpret_cast<LPCVOID>(m_imageBase), &dos, sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE)
        throw DumperException("Hedef belleğinde MZ imzasi yok");

    // --- ADIM 2: NT Headers oku (sirf imzayi + file header'i okumak yeterli) ---
    const std::uintptr_t ntAddr = m_imageBase + dos.e_lfanew;

    DWORD ntSignature = 0;
    m_mem.ReadMemory(reinterpret_cast<LPCVOID>(ntAddr), &ntSignature, sizeof(ntSignature));
    if (ntSignature != IMAGE_NT_SIGNATURE)
        throw DumperException("Hedef belleğinde PE\\0\\0 imzasi yok");

    IMAGE_FILE_HEADER fh{};
    m_mem.ReadMemory(reinterpret_cast<LPCVOID>(ntAddr + sizeof(DWORD)), &fh, sizeof(fh));

    // Magic ile 32/64 ayrimi
    WORD optMagic = 0;
    m_mem.ReadMemory(reinterpret_cast<LPCVOID>(ntAddr + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)),
                     &optMagic, sizeof(optMagic));
    m_is64bit = (optMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    // SizeOfHeaders'i ogrenmek icin OptionalHeader'i bir kere oku
    DWORD sizeOfHeaders = 0;
    if (m_is64bit) {
        IMAGE_OPTIONAL_HEADER64 oh{};
        m_mem.ReadMemory(reinterpret_cast<LPCVOID>(ntAddr + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)),
                         &oh, sizeof(oh));
        sizeOfHeaders = oh.SizeOfHeaders;
    } else {
        IMAGE_OPTIONAL_HEADER32 oh{};
        m_mem.ReadMemory(reinterpret_cast<LPCVOID>(ntAddr + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)),
                         &oh, sizeof(oh));
        sizeOfHeaders = oh.SizeOfHeaders;
    }

    // Tum headers blogunu yuklemek icin yeterli boyut
    m_headers.assign(sizeOfHeaders, 0);
    m_mem.ReadMemory(reinterpret_cast<LPCVOID>(m_imageBase),
                     m_headers.data(), sizeOfHeaders);

    // --- ADIM 3: Her bolumu oku ---
    auto* sects = SectionTable();
    const WORD nSects = NumberOfSectionsRef();
    LOG_INFO("Dumper: {} section yakalandi (mimari: {})",
             nSects, m_is64bit ? "x64" : "x86");

    m_sectionData.clear();
    m_sectionData.reserve(nSects);

    const DWORD secAlign = SectionAlignmentRef();
    for (WORD i = 0; i < nSects; ++i) {
        const auto& sec = sects[i];
        // VirtualSize bazen FileAlignment kalibinda 0 olabilir → SizeOfRawData kullan
        const DWORD vSize = sec.Misc.VirtualSize ? sec.Misc.VirtualSize
                                                 : sec.SizeOfRawData;
        const DWORD padded = Align(vSize, secAlign);

        std::vector<std::uint8_t> buf(padded, 0);

        // Bellek bolge erisilebilir olmayabilir (ornegin .bss zero-fill).
        // Okuma basarisiz olursa sıfır dolu bırakırız.
        try {
            m_mem.ReadMemory(reinterpret_cast<LPCVOID>(m_imageBase + sec.VirtualAddress),
                             buf.data(), vSize);
        } catch (const std::exception&) {
            LOG_WARN("Section '{}' okunamadi, sifir ile doldurulacak",
                     std::string(reinterpret_cast<const char*>(sec.Name), 8));
        }

        m_sectionData.push_back(std::move(buf));
    }

    // --- ADIM 4: Memory-aligned layout icin headers'i normalize et ---
    NormalizeHeadersForMemoryDump();
}

// =============================================================================
//  NormalizeHeadersForMemoryDump
//  FileAlignment = SectionAlignment yapilir; tum section headers'in
//  PointerToRawData / SizeOfRawData alanlari memory layout'a gore yeniden yazilir.
// =============================================================================
void Dumper::NormalizeHeadersForMemoryDump()
{
    const DWORD secAlign = SectionAlignmentRef();
    FileAlignmentRef() = secAlign;

    auto* sects = SectionTable();
    const WORD n = NumberOfSectionsRef();

    for (WORD i = 0; i < n; ++i) {
        auto& s = sects[i];
        const DWORD vSize = s.Misc.VirtualSize ? s.Misc.VirtualSize : s.SizeOfRawData;
        s.PointerToRawData = s.VirtualAddress;
        s.SizeOfRawData    = Align(vSize, secAlign);
    }
}

// =============================================================================
//  Optional Header guncellemeleri
// =============================================================================
void Dumper::SetOEP(DWORD newOepRva)
{
    if (m_is64bit) Nt64()->OptionalHeader.AddressOfEntryPoint = newOepRva;
    else           Nt32()->OptionalHeader.AddressOfEntryPoint = newOepRva;
    LOG_INFO("Dumper: yeni OEP RVA=0x{:X}", newOepRva);
}

void Dumper::SetImageBase(std::uintptr_t newBase)
{
    if (m_is64bit) Nt64()->OptionalHeader.ImageBase = static_cast<ULONGLONG>(newBase);
    else           Nt32()->OptionalHeader.ImageBase = static_cast<DWORD>(newBase);
    m_imageBase = newBase;
    LOG_INFO("Dumper: ImageBase=0x{:X}", newBase);
}

void Dumper::SetDataDirectory(DWORD index, DWORD rva, DWORD size)
{
    if (index >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
        throw DumperException("Gecersiz DataDirectory indeksi");
    auto* dd = DataDirectories();
    dd[index].VirtualAddress = rva;
    dd[index].Size           = size;
    LOG_INFO("Dumper: DataDirectory[{}] = (RVA=0x{:X}, Size=0x{:X})",
             index, rva, size);
}

// =============================================================================
//  AddSection — yeni bir bolum ekler, header tablosunda yer acar
//
//  ADIMlar:
//   1. SizeOfHeaders icinde yeni IMAGE_SECTION_HEADER icin yer var mi kontrol et.
//   2. SizeOfImage'i artir: yeni section sona yerlesir, VA'si = align(prevEnd).
//   3. NumberOfSections'i +1 yap.
//   4. m_sectionData listesine yeni veri tamponunu ekle.
// =============================================================================
DWORD Dumper::PredictNextSectionRVA() const noexcept
{
    auto* self = const_cast<Dumper*>(this);
    const DWORD secAlign = self->SectionAlignmentRef();
    auto* sects = self->SectionTable();
    const WORD n = self->NumberOfSectionsRef();

    DWORD nextRVA = 0;
    for (WORD i = 0; i < n; ++i) {
        const DWORD end = sects[i].VirtualAddress + sects[i].SizeOfRawData;
        if (end > nextRVA) nextRVA = end;
    }
    return Align(nextRVA, secAlign);
}

DWORD Dumper::AddSection(const char nameAscii8[8],
                         const std::vector<std::uint8_t>& data,
                         DWORD characteristics)
{
    const DWORD secAlign = SectionAlignmentRef();
    auto* sects = SectionTable();
    WORD& nSects = NumberOfSectionsRef();

    // Yeni section header icin headers icinde alan var mi?
    const std::size_t sectTableEnd =
        reinterpret_cast<std::uint8_t*>(&sects[nSects + 1]) - m_headers.data();
    if (sectTableEnd > m_headers.size())
        throw DumperException("Header'da yeni section header icin yer yok");

    const DWORD nextRVA = PredictNextSectionRVA();

    const DWORD paddedSize = Align(static_cast<DWORD>(data.size()), secAlign);

    auto& newHdr = sects[nSects];
    std::memset(&newHdr, 0, sizeof(newHdr));
    std::memcpy(newHdr.Name, nameAscii8, 8);
    newHdr.VirtualAddress    = nextRVA;
    newHdr.Misc.VirtualSize  = static_cast<DWORD>(data.size());
    newHdr.PointerToRawData  = nextRVA;     // memory-aligned dump
    newHdr.SizeOfRawData     = paddedSize;
    newHdr.Characteristics   = characteristics;

    // Veri tamponunu olustur (paddedSize'a kadar sifir doldur)
    std::vector<std::uint8_t> buf(paddedSize, 0);
    std::memcpy(buf.data(), data.data(), data.size());
    m_sectionData.push_back(std::move(buf));

    ++nSects;

    // SizeOfImage = bitis adresi, secAlign'a hizali
    SizeOfImageRef() = nextRVA + paddedSize;

    LOG_INFO("Dumper: yeni section '{}' eklendi RVA=0x{:X} Size=0x{:X}",
             std::string(nameAscii8, 8), nextRVA, paddedSize);
    return nextRVA;
}

// =============================================================================
//  SaveAs — diske yaz
// =============================================================================
void Dumper::SaveAs(const std::filesystem::path& path)
{
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) throw DumperException("Cikti dosyasi acilamadi: " + path.string());

    // 1. Header bloku (SizeOfHeaders kadar)
    f.write(reinterpret_cast<const char*>(m_headers.data()),
            static_cast<std::streamsize>(m_headers.size()));

    // 2. Her bolumun verisi, PointerToRawData ofsetinde yazilmali.
    //    memory-aligned layoutta PointerToRawData = VirtualAddress, sirayla artar.
    auto* sects = SectionTable();
    const WORD n = NumberOfSectionsRef();
    for (WORD i = 0; i < n; ++i) {
        const auto& s = sects[i];
        // Bolum baslangicina kadar pad
        const std::streampos cur = f.tellp();
        if (static_cast<DWORD>(cur) < s.PointerToRawData) {
            const DWORD padBytes = s.PointerToRawData - static_cast<DWORD>(cur);
            std::vector<char> pad(padBytes, 0);
            f.write(pad.data(), padBytes);
        }
        f.write(reinterpret_cast<const char*>(m_sectionData[i].data()),
                static_cast<std::streamsize>(m_sectionData[i].size()));
    }

    LOG_INFO("Dumper: {} basariyla yazildi", path.string());
}

// =============================================================================
//  Yardimci erisimciler (headers tamponu icine pointer veriyorlar)
// =============================================================================
IMAGE_NT_HEADERS32* Dumper::Nt32() noexcept {
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(m_headers.data());
    return reinterpret_cast<IMAGE_NT_HEADERS32*>(m_headers.data() + dos->e_lfanew);
}
IMAGE_NT_HEADERS64* Dumper::Nt64() noexcept {
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(m_headers.data());
    return reinterpret_cast<IMAGE_NT_HEADERS64*>(m_headers.data() + dos->e_lfanew);
}
IMAGE_SECTION_HEADER* Dumper::SectionTable() noexcept {
    if (m_is64bit) return IMAGE_FIRST_SECTION(Nt64());
    else           return IMAGE_FIRST_SECTION(Nt32());
}
IMAGE_DATA_DIRECTORY* Dumper::DataDirectories() noexcept {
    return m_is64bit ? Nt64()->OptionalHeader.DataDirectory
                     : Nt32()->OptionalHeader.DataDirectory;
}
WORD&  Dumper::NumberOfSectionsRef() noexcept {
    return m_is64bit ? Nt64()->FileHeader.NumberOfSections
                     : Nt32()->FileHeader.NumberOfSections;
}
DWORD& Dumper::SizeOfImageRef() noexcept {
    return m_is64bit ? Nt64()->OptionalHeader.SizeOfImage
                     : Nt32()->OptionalHeader.SizeOfImage;
}
DWORD& Dumper::SizeOfHeadersRef() noexcept {
    return m_is64bit ? Nt64()->OptionalHeader.SizeOfHeaders
                     : Nt32()->OptionalHeader.SizeOfHeaders;
}
DWORD& Dumper::FileAlignmentRef() noexcept {
    return m_is64bit ? Nt64()->OptionalHeader.FileAlignment
                     : Nt32()->OptionalHeader.FileAlignment;
}
DWORD& Dumper::SectionAlignmentRef() noexcept {
    return m_is64bit ? Nt64()->OptionalHeader.SectionAlignment
                     : Nt32()->OptionalHeader.SectionAlignment;
}
DWORD Dumper::SizeOfImage() const noexcept {
    return m_is64bit
        ? const_cast<Dumper*>(this)->Nt64()->OptionalHeader.SizeOfImage
        : const_cast<Dumper*>(this)->Nt32()->OptionalHeader.SizeOfImage;
}
DWORD Dumper::SectionAlign() const noexcept {
    return m_is64bit
        ? const_cast<Dumper*>(this)->Nt64()->OptionalHeader.SectionAlignment
        : const_cast<Dumper*>(this)->Nt32()->OptionalHeader.SectionAlignment;
}
