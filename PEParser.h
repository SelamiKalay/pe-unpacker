#pragma once

// Gerekli Windows makrolarini minimize et
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>
#include <stdexcept>

// =============================================================================
//  Hata hiyerarsisi
//  Her hata turu ayri bir sinifla temsil edilir; catch bloklari buna gore
//  ozellestirilebilir.
// =============================================================================
class PEException : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class PEFileNotFoundException : public PEException {
public:
    explicit PEFileNotFoundException(const std::filesystem::path& p)
        : PEException("Dosya bulunamadi: " + p.string()) {}
};

class PEInvalidFormatException : public PEException {
public:
    explicit PEInvalidFormatException(const std::string& reason)
        : PEException("Gecersiz PE formati: " + reason) {}
};

// =============================================================================
//  PEParser
//
//  Mimari ozeti:
//    1. Ham dosya icerigi tek seferinde m_rawData'ya yuklenir (sahiplik buradadir).
//    2. m_dosHeader / m_ntHeaders32 / m_ntHeaders64, m_rawData icine
//       SAHIPSIZ (non-owning) isaret eder; kopya veya tasima islemi yapilmaz.
//    3. BoundedCast<T>() her erisimde tampon sinirini dogrular; gecersiz
//       offset'lerde PEInvalidFormatException firlatir.
//    4. 32-bit (PE32) ve 64-bit (PE32+) dosyalar desteklenir.
// =============================================================================
class PEParser {
public:
    // Dosyayi diskten okur ve tamamen ayristirir.
    // Hata durumunda uygun PEException turevi firlatir.
    explicit PEParser(const std::filesystem::path& filePath);

    // Tum PE bilgilerini formatlı sekilde stdout'a yazar
    void PrintPEInfo() const;

    // --------------- Erisimciler ---------------
    [[nodiscard]] bool        Is64Bit()     const noexcept { return m_is64bit; }
    [[nodiscard]] std::size_t FileSize()    const noexcept { return m_rawData.size(); }
    [[nodiscard]] const std::vector<IMAGE_SECTION_HEADER>& GetSections() const noexcept
        { return m_sections; }

    // Ham tampona erisim (ileri asamali analiz icin)
    [[nodiscard]] const std::uint8_t* RawData() const noexcept { return m_rawData.data(); }

private:
    // --------------- Ic metodlar ---------------
    void LoadFile();
    void Parse();
    void ParseSections(DWORD count, std::size_t tableOffset);

    // Tampon siniri kontrollu isaretci donusumu
    template<typename T>
    [[nodiscard]] const T* BoundedCast(std::size_t offset) const;

    // --------------- Yazdirma yardimcilari -----
    static std::string MachineTypeToString(WORD machine);
    static std::string SubsystemToString(WORD subsystem);
    static std::string CharacteristicsToString(WORD chars);
    static std::string DllCharacteristicsToString(WORD chars);
    static std::string SectionCharacteristicsToString(DWORD chars);
    static std::string TimestampToString(DWORD timestamp);

    // --------------- Uye degiskenler -----------
    std::filesystem::path             m_filePath;
    std::vector<std::uint8_t>         m_rawData;       // Ham dosya icerigi (sahip)

    // m_rawData icine SAHIPSIZ isaretciler:
    const IMAGE_DOS_HEADER*           m_dosHeader   = nullptr;
    const IMAGE_NT_HEADERS32*         m_ntHeaders32 = nullptr;
    const IMAGE_NT_HEADERS64*         m_ntHeaders64 = nullptr;

    std::vector<IMAGE_SECTION_HEADER> m_sections;
    bool                              m_is64bit     = false;
};
