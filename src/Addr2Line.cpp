#include "Addr2Line.hpp"

#include <sstream>
#include <cstdio>

std::string execAddr2Line(const std::string& exe, uintptr_t addr) {
    std::stringstream cmd;
    cmd << "addr2line -f -C -e " << exe
        << " 0x" << std::hex << addr;

    FILE* f = popen(cmd.str().c_str(), "r");
    if (!f) return "??";

    char buf[256];
    std::string out;
    while (fgets(buf, sizeof(buf), f))
        out += buf;

    pclose(f);

    if (!out.empty())
        out.erase(out.find_last_not_of("\n") + 1);

    return out.empty() ? "??" : out;
}
