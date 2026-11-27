// Seeds for the C++ rules.
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>

class Widget {};

void run(const std::string &host, const std::string &message)
{
    char name[32];
    std::cin >> name;                                    // cpp-cin-char-array
    std::system(("ping -c 1 " + host).c_str());          // cpp-system-concat
    std::printf(message.c_str());                        // cpp-format-string-cstr
    std::auto_ptr<Widget> widget(new Widget());          // cpp-auto-ptr
}
