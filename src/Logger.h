#pragma once

#include <iostream>
#include <string>
#include <string_view>
#include <format>
#include <functional>
#include <mutex>
#include <utility>

// =============================================================================
//  Logger — debug ciktilarini standartlastirmak icin basit bir yardimci.
//
//  Tasarim notlari:
//   - Header-only; mutex 'inline' static ile tek nokta paylasimi (C++17).
//   - Varsayilan olarak std::cout'a yazar (konsol uygulamasi).
//   - SetSink() ile GUI veya dosya gibi farkli bir cikti hedefine
//     yonlendirilebilir (DIP — bagimliligin tersine cevrilmesi).
//   - Thread-safe: birden cok iplikcik (debug loop + UI) ayni anda yazabilir.
// =============================================================================
class Logger {
public:
    enum class Level { Info, Event, Warn, Error };

    // (seviye, formatlı mesaj) → void
    using Sink = std::function<void(Level, const std::string&)>;

    template<typename... Args>
    static void Log(Level lvl, std::format_string<Args...> fmt, Args&&... args)
    {
        std::string msg = std::format(fmt, std::forward<Args>(args)...);
        std::scoped_lock lock(Mutex());
        auto& sink = GetSink();
        if (sink) {
            sink(lvl, msg);
        } else {
            std::cout << Prefix(lvl) << msg << "\n";
        }
    }

    // GUI baslarken bunu cagirip log'larini kendi penceresine yonlendirir.
    static void SetSink(Sink sink) {
        std::scoped_lock lock(Mutex());
        GetSink() = std::move(sink);
    }
    static void ClearSink() {
        std::scoped_lock lock(Mutex());
        GetSink() = {};
    }

    static constexpr std::string_view Prefix(Level lvl) {
        switch (lvl) {
        case Level::Info:  return "[INFO ] ";
        case Level::Event: return "[EVENT] ";
        case Level::Warn:  return "[WARN ] ";
        case Level::Error: return "[ERROR] ";
        }
        return "[?????] ";
    }

private:
    static std::mutex& Mutex() { static std::mutex m; return m; }
    static Sink&       GetSink() { static Sink s; return s; }
};

// Kullanim kisaltmalari
#define LOG_INFO(...)  Logger::Log(Logger::Level::Info,  __VA_ARGS__)
#define LOG_EVENT(...) Logger::Log(Logger::Level::Event, __VA_ARGS__)
#define LOG_WARN(...)  Logger::Log(Logger::Level::Warn,  __VA_ARGS__)
#define LOG_ERROR(...) Logger::Log(Logger::Level::Error, __VA_ARGS__)
