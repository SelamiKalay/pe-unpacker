cmake_minimum_required(VERSION 3.20)
project(ExecutableUnpacker LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (NOT WIN32)
    message(FATAL_ERROR "Bu proje yalnizca Windows hedefler.")
endif()

if (MSVC)
    add_compile_options(/W4 /permissive- /EHsc /utf-8 /Zc:__cplusplus)
    add_compile_definitions(_WIN32_WINNT=0x0A00 NOMINMAX WIN32_LEAN_AND_MEAN UNICODE _UNICODE)
endif()

# ── Ortak motor kaynak dosyalari (her iki hedef de paylasir) ────────────────
set(ENGINE_SOURCES
    PEParser.cpp
    ProcessManager.cpp
    DebuggerEngine.cpp
    Dumper.cpp
    IATRebuilder.cpp
)

# ── Konsol hedefi (orijinal CLI) ────────────────────────────────────────────
add_executable(unpacker
    main.cpp
    ${ENGINE_SOURCES}
)
target_link_libraries(unpacker PRIVATE psapi)

# ── GUI hedefi (Win32 native pencere) ───────────────────────────────────────
add_executable(unpacker_gui WIN32
    gui_main.cpp
    MainWindow.cpp
    ${ENGINE_SOURCES}
)
target_link_libraries(unpacker_gui PRIVATE
    psapi
    comctl32
    comdlg32
    shell32
)
