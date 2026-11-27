// Safe counterparts of fixtures/vulnerable/cpp/win32.cpp.
#include <windows.h>
#include <shellapi.h>

void launch(LPWSTR arguments)
{
    STARTUPINFOW si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    CreateProcessW(L"C:\\Windows\\System32\\notepad.exe", arguments, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    ShellExecuteW(NULL, L"open", L"https://www.example.com/help", NULL, NULL, SW_SHOW);
    HMODULE helper = LoadLibraryExW(L"helper.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    (void)helper;
}
