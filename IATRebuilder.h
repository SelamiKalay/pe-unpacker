#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "ProcessManager.h"
#include "Dumper.h"

#include <cstdint>
#include <map>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

class IATRebuilderException : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

// =============================================================================
//  IATRebuilder — Scylla-tarzi import tablosu onarici
//
//  TEMEL ALGORITMA:
//   1. Hedef surece yuklenmis butun DLL'leri kesfet (EnumProcessModules).
//   2. Her DLL icin export tablosunu PROCESS BELLEGI uzerinden oku
//      (LoadLibrary GEREKMEZ — hedef ve bizim adres uzayimiz farklidir).
//      Bunun sonucunda: address -> "DllName!FunctionName" haritası elde edilir.
//   3. Verilen IAT bolgesini sirayla pointer pointer tara. Her pointer:
//        - Bir modul aralığına dusuyor mu?
//        - Modulun export'larindan birine isabet ediyor mu?
//      ise gecerli bir IAT girisi sayilir.
//   4. NULL terminator gorulene veya gecersiz girise rastlanana kadar olan
//      ardisik girisler tek bir "import chunk" (= bir DLL'in tum import'lari)
//      olarak gruplanir.
//   5. Bu gruplardan IMAGE_IMPORT_DESCRIPTOR + INT (Import Name Table) +
//      IMAGE_IMPORT_BY_NAME + DLL adi stringleri olusturulur.
//   6. Tum bunlar tek bir yeni section ('.scy0') olarak Dumper'a enjekte
//      edilir; DataDirectory[IMPORT] guncellenir.
//
//  ONEMLI NOT: FirstThunk (IAT) RVA'si orijinal yerinde birakilir. Boylece
//  loader, exe calistiginda ayni bellek bolgesine cozulmus pointer'lari yazar
//  ve dump edilmis kod bu pointer'lari (orijinal kod gibi) kullanmaya devam
//  eder.
// =============================================================================

// Bir cozulmus import girisi: (modul adı, fonksiyon adı veya ordinal)
struct ResolvedImport {
    std::string moduleName;       // ornek: "kernel32.dll"
    std::string functionName;     // ornek: "CreateFileW" — ordinal ise bos
    WORD        ordinal = 0;      // ordinal-only ise > 0
    bool        byOrdinal = false;
};

// Tek bir DLL'e ait ardisik import girisleri
struct ImportChunk {
    std::string                 moduleName;
    std::uintptr_t              firstThunkVA = 0;  // hedef bellegindeki adres
    std::vector<ResolvedImport> entries;
};

class IATRebuilder {
public:
    // Hedef surec referansi (modul taramasi icin), ImageBase (RVA hesabi icin)
    IATRebuilder(const ProcessManager& target, std::uintptr_t imageBase);

    // ADIM 1+2: Surecte yuklu modulleri ve export'larini topla.
    void EnumerateAndCacheExports();

    // ADIM 3+4: Belirtilen bolge icindeki IAT'yi cozumle, chunk'lara böl.
    //   iatStartVA: hedef adres uzayinda IAT'nin baslangic VA'si
    //   iatSize   : taranacak byte sayisi (4-byte/8-byte siralı)
    void ResolveIAT(std::uintptr_t iatStartVA, SIZE_T iatSize);

    // ADIM 5+6: Cozumlenmis chunk'lari kullanarak yeni import section'ini
    //          olustur ve Dumper'a enjekte et.
    void InjectInto(Dumper& dumper);

    // Tani
    [[nodiscard]] const std::vector<ImportChunk>& Chunks() const noexcept { return m_chunks; }
    [[nodiscard]] std::size_t ResolvedCount() const noexcept;

private:
    // Hedef surecten bir modulun export tablosunu oku ve haritaya isle.
    void CacheModuleExports(HMODULE hMod);

    // Bir VA verildiginde: hangi modulde ve hangi fonksiyon?
    // Bulamazsa byOrdinal=false, functionName="" ile false doner.
    bool LookupAddress(std::uintptr_t va, ResolvedImport& out) const;

    // Modul aralığını tanimlayan kayit
    struct ModuleInfo {
        std::string    name;        // küçük harfli dosya adi
        std::uintptr_t base = 0;
        SIZE_T         size = 0;
    };

    const ProcessManager& m_target;
    std::uintptr_t        m_imageBase;
    bool                  m_is64bit;     // hedef ile ayni mimari varsayilir

    std::vector<ModuleInfo>                        m_modules;
    // VA -> ResolvedImport (her exported fonksiyon icin bir kayit)
    std::unordered_map<std::uintptr_t, ResolvedImport> m_addressMap;

    std::vector<ImportChunk> m_chunks;
};
