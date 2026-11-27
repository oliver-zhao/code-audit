// Seeds for the Windows API rules.
#include <windows.h>
#include <shellapi.h>

void launch(LPSTR commandLine, LPCSTR document, const void *buffer)
{
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    CreateProcessA(NULL, commandLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi); // cpp-createprocess-unquoted
    WinExec(commandLine, SW_HIDE);                       // cpp-winexec-api
    ShellExecuteA(NULL, "open", document, NULL, NULL, SW_SHOW); // cpp-winexec-api
    HMODULE helper = LoadLibraryA("helper.dll");         // cpp-loadlibrary-relative
    if (IsBadReadPtr(buffer, 16)) {                      // cpp-isbadptr
        return;
    }
    (void)helper;
}
