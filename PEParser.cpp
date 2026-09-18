#include "PEParser.h"

#include <fstream>
#include <iostream>
#include <iomanip>
#include <format>      // C++20 — MSVC: /std:c++20
#include <ctime>
#include <cstring>
#include <sstream>

// =============================================================================
//  Kurucu: dosyayi yukle ve ayristir
// =============================================================================
PEParser::PEParser(const std::filesystem::path& filePath)
    : m_filePath(filePath)
{
    LoadFile();   // 1. Ham byte'lari m_rawData'ya al
    Parse();      // 2. Yapilari ayristir
}

// =============================================================================
//  LoadFile: dosyayi ikili kipte okur
// =============================================================================
void PEParser::LoadFile()
{
    std::error_code ec;
    if (!std::filesystem::exists(m_filePath, ec))
        throw PEFileNotFoundException(m_filePath);

    const auto fileSize = std::filesystem::file_size(m_filePath, ec);
    if (ec || fileSize < sizeof(IMAGE_DOS_HEADER))
        throw PEInvalidFormatException(
            "Dosya boyutu DOS header icin bile yetersiz");

    std::ifstream file(m_filePath, std::ios::binary);
    if (!file.is_open())
        throw PEFileNotFoundException(m_filePath);

    m_rawData.resize(static_cast<std::size_t>(fileSize));
    file.read(reinterpret_cast<char*>(m_rawData.data()),
              static_cast<std::streamsize>(fileSize));

    if (!file)
        throw PEException("Dosya okuma hatasi: " + m_filePath.string());
}

// =============================================================================
//  BoundedCast<T>: offset + sizeof(T) tampon icindeyse isaretci dondur
// =============================================================================
template<typename T>
const T* PEParser::BoundedCast(std::size_t offset) const
{
    if (offset + sizeof(T) > m_rawData.size())
        throw PEInvalidFormatException(
            std::format("Offset 0x{:X} + {} byte tampon sinirini asiyor (dosya: {} byte)",
                offset, sizeof(T), m_rawData.size()));

    return reinterpret_cast<const T*>(m_rawData.data() + offset);
}

// =============================================================================
//  Parse: DOS Header -> NT Signature -> Optional Header magic -> Sections
// =============================================================================
void PEParser::Parse()
{
    // ── 1. DOS Header ────────────────────────────────────────────────────────
    m_dosHeader = BoundedCast<IMAGE_DOS_HEADER>(0);

    if (m_dosHeader->e_magic != IMAGE_DOS_SIGNATURE)   // 'MZ' = 0x5A4D
        throw PEInvalidFormatException("DOS magic 'MZ' bulunamadi");

    // ── 2. NT Signature ('PE\0\0') ───────────────────────────────────────────
    const std::size_t ntOffset = static_cast<std::size_t>(m_dosHeader->e_lfanew);
    if (ntOffset < sizeof(IMAGE_DOS_HEADER))
        throw PEInvalidFormatException("e_lfanew gecersiz (cok kucuk)");

    const auto* sig = BoundedCast<DWORD>(ntOffset);
    if (*sig != IMAGE_NT_SIGNATURE)                    // 0x00004550
        throw PEInvalidFormatException("NT signature 'PE\\0\\0' bulunamadi");

    // ── 3. PE32 / PE32+ ayrimi ───────────────────────────────────────────────
    //  File Header'dan sonra gelen ilk WORD Optional Header magic'idir.
    const std::size_t optOffset = ntOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    const auto* optMagic = BoundedCast<WORD>(optOffset);

    if (*optMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {       // 0x020B -> PE32+
        m_is64bit     = true;
        m_ntHeaders64 = BoundedCast<IMAGE_NT_HEADERS64>(ntOffset);
        ParseSections(m_ntHeaders64->FileHeader.NumberOfSections,
                      ntOffset + sizeof(IMAGE_NT_HEADERS64));

    } else if (*optMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) { // 0x010B -> PE32
        m_is64bit     = false;
        m_ntHeaders32 = BoundedCast<IMAGE_NT_HEADERS32>(ntOffset);
        ParseSections(m_ntHeaders32->FileHeader.NumberOfSections,
                      ntOffset + sizeof(IMAGE_NT_HEADERS32));

    } else {
        throw PEInvalidFormatException(
            std::format("Bilinmeyen Optional Header magic: 0x{:04X}", *optMagic));
    }
}

// =============================================================================
//  ParseSections: section header dizisini m_sections'a kopyalar
// =============================================================================
void PEParser::ParseSections(DWORD count, std::size_t tableOffset)
{
    if (count == 0) return;

    // PE spesifikasyonuna gore maksimum section sayisi 96'dir
    if (count > 96)
        throw PEInvalidFormatException(
            std::format("Anormal section sayisi: {} (maks 96)", count));

    m_sections.reserve(count);
    for (DWORD i = 0; i < count; ++i) {
        const std::size_t off = tableOffset + i * sizeof(IMAGE_SECTION_HEADER);
        m_sections.push_back(*BoundedCast<IMAGE_SECTION_HEADER>(off));
    }
}

// =============================================================================
//  PrintPEInfo: formatlı konsol ciktisi
// =============================================================================
void PEParser::PrintPEInfo() const
{
    const std::string SEP(60, '=');
    const std::string THN(60, '-');

    std::cout << SEP << "\n"
              << std::format("  PE ANALIZ RAPORU : {}\n", m_filePath.filename().string())
              << std::format("  Dosya Boyutu     : {} byte ({:.2f} KB)\n",
                    m_rawData.size(), m_rawData.size() / 1024.0)
              << std::format("  Mimari           : {}\n", m_is64bit ? "PE32+ (64-bit)" : "PE32 (32-bit)")
              << SEP << "\n\n";

    // ── DOS Header ──────────────────────────────────────────────────────────
    std::cout << "[ DOS HEADER ]\n" << THN << "\n"
              << std::format("  e_magic    : 0x{:04X}  (MZ)\n", m_dosHeader->e_magic)
              << std::format("  e_lfanew   : 0x{:08X}\n",
                    static_cast<DWORD>(m_dosHeader->e_lfanew))
              << "\n";

    // ── File Header ─────────────────────────────────────────────────────────
    const IMAGE_FILE_HEADER* fh = m_is64bit
        ? &m_ntHeaders64->FileHeader
        : &m_ntHeaders32->FileHeader;

    std::cout << "[ FILE HEADER ]\n" << THN << "\n"
              << std::format("  Machine           : 0x{:04X}  ({})\n",
                    fh->Machine, MachineTypeToString(fh->Machine))
              << std::format("  NumberOfSections  : {}\n",
                    fh->NumberOfSections)
              << std::format("  TimeDateStamp     : 0x{:08X}  ({})\n",
                    fh->TimeDateStamp, TimestampToString(fh->TimeDateStamp))
              << std::format("  SizeOfOptHdr      : {} byte\n",
                    fh->SizeOfOptionalHeader)
              << std::format("  Characteristics   : 0x{:04X}  [{}]\n",
                    fh->Characteristics, CharacteristicsToString(fh->Characteristics))
              << "\n";

    // ── Optional Header ─────────────────────────────────────────────────────
    std::cout << std::format("[ OPTIONAL HEADER ({}) ]\n",
                    m_is64bit ? "PE32+" : "PE32") << THN << "\n";

    // Lambda ile tekrari azalt
    auto printCommon = [&](auto magic, auto imageBase, DWORD ep,
                           DWORD sizeOfImage, DWORD sizeOfHdrs,
                           WORD subsystem, WORD dllChars,
                           WORD majOS, WORD minOS, DWORD checksum)
    {
        std::cout << std::format("  Magic             : 0x{:04X}\n",  magic)
                  << std::format("  ImageBase         : 0x{:016X}\n", static_cast<ULONGLONG>(imageBase))
                  << std::format("  AddressOfEP (RVA) : 0x{:08X}\n", ep)
                  << std::format("  SizeOfImage       : 0x{:08X}  ({} byte)\n",
                        sizeOfImage, sizeOfImage)
                  << std::format("  SizeOfHeaders     : 0x{:08X}\n", sizeOfHdrs)
                  << std::format("  Subsystem         : {}  ({})\n",
                        subsystem, SubsystemToString(subsystem))
                  << std::format("  DllCharacteristics: 0x{:04X}  [{}]\n",
                        dllChars, DllCharacteristicsToString(dllChars))
                  << std::format("  OS Version        : {}.{}\n",    majOS, minOS)
                  << std::format("  CheckSum          : 0x{:08X}\n", checksum);
    };

    if (m_is64bit) {
        const auto& oh = m_ntHeaders64->OptionalHeader;
        printCommon(oh.Magic, oh.ImageBase, oh.AddressOfEntryPoint,
                    oh.SizeOfImage, oh.SizeOfHeaders, oh.Subsystem,
                    oh.DllCharacteristics,
                    oh.MajorOperatingSystemVersion, oh.MinorOperatingSystemVersion,
                    oh.CheckSum);
    } else {
        const auto& oh = m_ntHeaders32->OptionalHeader;
        printCommon(oh.Magic, oh.ImageBase, oh.AddressOfEntryPoint,
                    oh.SizeOfImage, oh.SizeOfHeaders, oh.Subsystem,
                    oh.DllCharacteristics,
                    oh.MajorOperatingSystemVersion, oh.MinorOperatingSystemVersion,
                    oh.CheckSum);
    }
    std::cout << "\n";

    // ── Section Table ────────────────────────────────────────────────────────
    std::cout << "[ SECTION TABLE ]\n" << THN << "\n"
              << std::format("  {:<10} {:>10} {:>10} {:>10} {:>10}  {}\n",
                    "Name", "VirtAddr", "VirtSize", "RawOff", "RawSize", "Flags")
              << "  " << std::string(60, '-') << "\n";

    for (const auto& sec : m_sections) {
        char name[9] = {};
        std::memcpy(name, sec.Name, 8);   // null-terminate garantisi icin
        std::cout << std::format("  {:<10} 0x{:08X} 0x{:08X} 0x{:08X} 0x{:08X}  [{}]\n",
            name,
            sec.VirtualAddress,
            sec.Misc.VirtualSize,
            sec.PointerToRawData,
            sec.SizeOfRawData,
            SectionCharacteristicsToString(sec.Characteristics));
    }

    std::cout << "\n" << SEP << "\n";
}

// =============================================================================
//  Yardimci: Machine type
// =============================================================================
std::string PEParser::MachineTypeToString(WORD machine)
{
    switch (machine) {
    case IMAGE_FILE_MACHINE_I386:   return "x86 (i386)";
    case IMAGE_FILE_MACHINE_AMD64:  return "x64 (AMD64)";
    case IMAGE_FILE_MACHINE_ARM:    return "ARM (Thumb2)";
    case IMAGE_FILE_MACHINE_ARM64:  return "ARM64 (AArch64)";
    case IMAGE_FILE_MACHINE_IA64:   return "Intel Itanium";
    case IMAGE_FILE_MACHINE_UNKNOWN:return "Unknown";
    default:
        return std::format("0x{:04X}", machine);
    }
}

// =============================================================================
//  Yardimci: Subsystem
// =============================================================================
std::string PEParser::SubsystemToString(WORD subsystem)
{
    switch (subsystem) {
    case IMAGE_SUBSYSTEM_NATIVE:                  return "Native";
    case IMAGE_SUBSYSTEM_WINDOWS_GUI:             return "Windows GUI";
    case IMAGE_SUBSYSTEM_WINDOWS_CUI:             return "Windows Console (CUI)";
    case IMAGE_SUBSYSTEM_OS2_CUI:                 return "OS/2 Console";
    case IMAGE_SUBSYSTEM_POSIX_CUI:               return "POSIX Console";
    case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:          return "Windows CE GUI";
    case IMAGE_SUBSYSTEM_EFI_APPLICATION:         return "EFI Application";
    case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: return "EFI Boot Service Driver";
    case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:      return "EFI Runtime Driver";
    case IMAGE_SUBSYSTEM_EFI_ROM:                 return "EFI ROM";
    case IMAGE_SUBSYSTEM_XBOX:                    return "Xbox";
    default:
        return std::format("Unknown ({})", subsystem);
    }
}

// =============================================================================
//  Yardimci: File Characteristics (bit bayraklari)
// =============================================================================
std::string PEParser::CharacteristicsToString(WORD chars)
{
    std::string result;
    auto add = [&](WORD flag, const char* label) {
        if (chars & flag) {
            if (!result.empty()) result += " | ";
            result += label;
        }
    };
    add(IMAGE_FILE_RELOCS_STRIPPED,         "RELOCS_STRIPPED");
    add(IMAGE_FILE_EXECUTABLE_IMAGE,        "EXECUTABLE");
    add(IMAGE_FILE_LINE_NUMS_STRIPPED,      "LINE_NUMS_STRIPPED");
    add(IMAGE_FILE_LOCAL_SYMS_STRIPPED,     "LOCAL_SYMS_STRIPPED");
    add(IMAGE_FILE_LARGE_ADDRESS_AWARE,     "LARGE_ADDRESS_AWARE");
    add(IMAGE_FILE_32BIT_MACHINE,           "32BIT_MACHINE");
    add(IMAGE_FILE_DEBUG_STRIPPED,          "DEBUG_STRIPPED");
    add(IMAGE_FILE_DLL,                     "DLL");
    add(IMAGE_FILE_SYSTEM,                  "SYSTEM");
    return result.empty() ? "NONE" : result;
}

// =============================================================================
//  Yardimci: DLL Characteristics (guvenlik ozellikleri)
// =============================================================================
std::string PEParser::DllCharacteristicsToString(WORD chars)
{
    std::string result;
    auto add = [&](WORD flag, const char* label) {
        if (chars & flag) {
            if (!result.empty()) result += " | ";
            result += label;
        }
    };
    add(IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA,     "HIGH_ENTROPY_VA");
    add(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,        "ASLR");
    add(IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY,     "FORCE_INTEGRITY");
    add(IMAGE_DLLCHARACTERISTICS_NX_COMPAT,           "DEP/NX");
    add(IMAGE_DLLCHARACTERISTICS_NO_ISOLATION,        "NO_ISOLATION");
    add(IMAGE_DLLCHARACTERISTICS_NO_SEH,              "NO_SEH");
    add(IMAGE_DLLCHARACTERISTICS_NO_BIND,             "NO_BIND");
    add(IMAGE_DLLCHARACTERISTICS_APPCONTAINER,        "APPCONTAINER");
    add(IMAGE_DLLCHARACTERISTICS_WDM_DRIVER,          "WDM_DRIVER");
    add(IMAGE_DLLCHARACTERISTICS_GUARD_CF,            "CFG");
    add(IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE,"TS_AWARE");
    return result.empty() ? "NONE" : result;
}

// =============================================================================
//  Yardimci: Section Characteristics (R/W/X ve icerik tipi)
// =============================================================================
std::string PEParser::SectionCharacteristicsToString(DWORD chars)
{
    std::string result;
    auto add = [&](DWORD flag, const char* label) {
        if (chars & flag) {
            if (!result.empty()) result += "|";
            result += label;
        }
    };
    add(IMAGE_SCN_CNT_CODE,               "CODE");
    add(IMAGE_SCN_CNT_INITIALIZED_DATA,   "INIT_DATA");
    add(IMAGE_SCN_CNT_UNINITIALIZED_DATA, "UNINIT_DATA");
    add(IMAGE_SCN_MEM_EXECUTE,            "EXEC");
    add(IMAGE_SCN_MEM_READ,               "READ");
    add(IMAGE_SCN_MEM_WRITE,              "WRITE");
    add(IMAGE_SCN_MEM_DISCARDABLE,        "DISCARD");
    add(IMAGE_SCN_MEM_NOT_CACHED,         "NO_CACHE");
    add(IMAGE_SCN_MEM_SHARED,             "SHARED");
    return result.empty() ? "NONE" : result;
}

// =============================================================================
//  Yardimci: DWORD timestamp -> UTC tarih/saat
// =============================================================================
std::string PEParser::TimestampToString(DWORD timestamp)
{
    const std::time_t t = static_cast<std::time_t>(timestamp);
    std::tm tm_buf{};
    gmtime_s(&tm_buf, &t);   // Windows-safe, thread-safe

    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", &tm_buf);
    return buf;
}
