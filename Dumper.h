#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "ProcessManager.h"   // IProcessMemory

#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>

// =============================================================================
//  Dumper hatalari
// =============================================================================
class DumperException : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

// =============================================================================
//  Dumper
//
//  Gorev: Calisan (unpack edilmis) bir surecin bellek goruntusunden ham bir
//  PE dosyasi uretmek.
//
//  Temel zorluk:
//    Diskte sectionlar FileAlignment (genelde 0x200) ile,
//    bellekte ise   SectionAlignment (genelde 0x1000) ile hizalanir.
//    Bellekten dump aldigimizda artik orijinal file layout'u bilmiyoruz;
//    bu nedenle "memory-aligned dump" yontemini uygularız:
//      FileAlignment = SectionAlignment
//      PointerToRawData[i] = VirtualAddress[i]
//      SizeOfRawData[i]    = align(VirtualSize[i], FileAlignment)
//    Bu Scylla'nin varsayilan davranisidir; PE spec'e gore tamamen gecerlidir.
//
//  Tek bir Dumper ornegi:
//   1. CaptureFromMemory()  → bellekten oku
//   2. (opsiyonel) SetOEP() / SetImageBase() / AddSection() / SetDataDirectory()
//   3. SaveAs(path)         → diske yaz
// =============================================================================
class Dumper {
public:
    Dumper(const IProcessMemory& mem, std::uintptr_t imageBase);

    // Headers + tum section icerikleri hedef surecin belleginden okunur.
    void CaptureFromMemory();

    // OptionalHeader.AddressOfEntryPoint guncellenir (OEP RVA olarak verilir).
    void SetOEP(DWORD newOepRva);

    // OptionalHeader.ImageBase guncellenir (ASLR'siz dump icin onerilir).
    void SetImageBase(std::uintptr_t newBase);

    // Bir sonraki AddSection cagrisinda kullanilacak RVA'yi onceden hesaplar.
    // IATRebuilder bunu kullanir: section icindeki descriptor'lara mutlak RVA
    // gomebilmek icin once tahmini RVA'yi alir, blob'u hazirlar, sonra ekler.
    [[nodiscard]] DWORD PredictNextSectionRVA() const noexcept;

    // Yeni bir bolum (section) ekler ve bunun ham veri RVA'sini dondurur.
    // IATRebuilder bu metodu yeni import tablosunu enjekte etmek icin kullanir.
    DWORD AddSection(const char nameAscii8[8],
                     const std::vector<std::uint8_t>& data,
                     DWORD characteristics);

    // OptionalHeader.DataDirectory[index] = {rva, size}
    void SetDataDirectory(DWORD index, DWORD rva, DWORD size);

    // Bellekteki imajdan derlenen PE'yi diske yazar (memory-aligned layout).
    void SaveAs(const std::filesystem::path& path);

    // Sorgulama
    [[nodiscard]] std::uintptr_t ImageBase()    const noexcept { return m_imageBase; }
    [[nodiscard]] DWORD          SizeOfImage()  const noexcept;
    [[nodiscard]] bool           Is64Bit()      const noexcept { return m_is64bit; }
    [[nodiscard]] DWORD          SectionAlign() const noexcept;

private:
    // ---- Yardimcilar --------------------------------------------------------
    void ParseHeaders();
    void NormalizeHeadersForMemoryDump();

    IMAGE_NT_HEADERS32* Nt32() noexcept;
    IMAGE_NT_HEADERS64* Nt64() noexcept;
    IMAGE_SECTION_HEADER* SectionTable() noexcept;
    IMAGE_DATA_DIRECTORY* DataDirectories() noexcept;
    WORD&  NumberOfSectionsRef() noexcept;
    DWORD& SizeOfImageRef() noexcept;
    DWORD& SizeOfHeadersRef() noexcept;
    DWORD& FileAlignmentRef() noexcept;
    DWORD& SectionAlignmentRef() noexcept;

    static DWORD Align(DWORD value, DWORD alignment) {
        return (value + alignment - 1) & ~(alignment - 1);
    }

    // ---- Uye degiskenler ----------------------------------------------------
    const IProcessMemory& m_mem;
    std::uintptr_t        m_imageBase;
    bool                  m_is64bit = false;

    // Headers (DOS + NT + section table) ham bytes
    std::vector<std::uint8_t> m_headers;

    // Her bolumun ham bytelari (memory-aligned, padded)
    std::vector<std::vector<std::uint8_t>> m_sectionData;
};
