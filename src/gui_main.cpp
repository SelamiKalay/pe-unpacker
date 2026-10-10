// =============================================================================
//  GUI giris noktasi (WinMain)
//  Konsol acmadan dogrudan pencereyi gosterir.
// =============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "MainWindow.h"
#include "PEParser.h"
#include "Dumper.h"
#include "IATRebuilder.h"
#include "ProcessManager.h"

int APIENTRY wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int nCmdShow)
{
    try {
        MainWindow win;
        if (!win.Create(hInst, nCmdShow)) {
            ::MessageBoxW(nullptr, L"Pencere olusturulamadi.", L"Hata",
                          MB_OK | MB_ICONERROR);
            return 1;
        }
        return win.RunMessageLoop();
    }
    catch (const std::exception& e) {
        ::MessageBoxA(nullptr, e.what(), "Fatal", MB_OK | MB_ICONERROR);
        return 99;
    }
}
