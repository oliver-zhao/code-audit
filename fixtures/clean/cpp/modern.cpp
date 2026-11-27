// Safe counterparts of fixtures/vulnerable/cpp/modern.cpp.
#include <cstdio>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string>
#include <unistd.h>

class Widget {};

void run(const std::string &host, const std::string &message)
{
    char name[32];
    std::cin >> std::setw(sizeof name) >> name;
    std::string line;
    std::cin >> line;
    execlp("ping", "ping", "-c", "1", host.c_str(), static_cast<char *>(nullptr));
    std::printf("%s", message.c_str());
    std::unique_ptr<Widget> widget = std::make_unique<Widget>();
}
