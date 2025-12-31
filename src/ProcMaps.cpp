#include "ProcMaps.hpp"
#include <fstream>
#include <sstream>

ProcMaps::ProcMaps(pid_t pid, const std::string& exePath) {
    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
    std::string line;

    while (std::getline(maps, line)) {
        if (line.find(exePath) == std::string::npos)
            continue;
        if (line.find("r-xp") == std::string::npos)
            continue;

        std::stringstream ss(line);
        std::string addr;
        ss >> addr;

        auto dash = addr.find('-');
        textBase = std::stoull(addr.substr(0, dash), nullptr, 16);

        pie = (textBase != 0x400000);
        return;
    }
}
