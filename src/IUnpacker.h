#pragma once

#include <cstdint>
#include <filesystem>

// =============================================================================
//  IUnpacker — Soyut arayuz
//
//  Tasarim mantigi:
//    Bir "unpacker" surec başlatir, çalıstirmayi izler, OEP (Original Entry
//    Point) tespit ettikten sonra durur. Algoritma farkli olabilir
//    (debugger, emulator, sandbox) — bu yuzden arayuz farkli stratejilere
//    izin verir. (Strategy pattern + DIP)
// =============================================================================
class IUnpacker {
public:
    virtual ~IUnpacker() = default;

    // Hedef exe'yi yukler ve unpack islemini baslatir.
    // OEP bulunana, surec sonlanana veya hata olusana kadar bloklar.
    virtual void Run(const std::filesystem::path& targetExe) = 0;

    // Algoritma OEP'yi bulduysa true.
    [[nodiscard]] virtual bool IsOEPFound() const noexcept = 0;

    // OEP bulunduysa adresi; aksi halde 0.
    [[nodiscard]] virtual std::uintptr_t GetOEP() const noexcept = 0;
};
