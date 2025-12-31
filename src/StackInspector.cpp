#include "StackInspector.hpp"

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <cerrno>
#include <cstring>

StackInspector::ProcMaps::ProcMaps(pid_t pid, const std::string& exe) {
    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
    std::string line;
    while (std::getline(maps, line)) {
        if (line.find(exe) == std::string::npos) continue;
        if (line.find("r-xp") == std::string::npos) continue;
        auto dash = line.find('-');
        base_ = std::stoull(line.substr(0, dash), nullptr, 16);
        pie_ = (base_ != 0x400000);
        break;
    }
}

uintptr_t StackInspector::ProcMaps::normalize(uintptr_t rip) const { 
    return pie_ ? rip - base_ : rip; 
}

bool StackInspector::ProcMaps::pie() const { return pie_; }
uintptr_t StackInspector::ProcMaps::base() const { return base_; }

StackInspector::StackInspector(pid_t pid, const std::string& exe)
    : pid_(pid), exe_(exe), maps_(pid, exe) {}

uintptr_t StackInspector::peek(uintptr_t addr) {
    errno = 0;
    long val = ptrace(PTRACE_PEEKDATA, pid_, addr, nullptr);
    return errno ? 0 : static_cast<uintptr_t>(val);
}

std::string StackInspector::addr2line(uintptr_t addr) {
    std::stringstream cmd;
    cmd << "addr2line -f -C -e " << exe_ 
        << " 0x" << std::hex << maps_.normalize(addr);
    FILE* f = popen(cmd.str().c_str(), "r");
    if (!f) return "??";
    char buf[256]; std::string out;
    while (fgets(buf, sizeof(buf), f)) out += buf;
    pclose(f);
    while (!out.empty() && out.back() == '\n') out.pop_back();
    return out.empty() ? "??" : out;
}

void StackInspector::inspect(int maxFrames) {
    ptrace(PTRACE_ATTACH, pid_, nullptr, nullptr);
    waitpid(pid_, nullptr, 0);

    user_regs_struct regs{};
    ptrace(PTRACE_GETREGS, pid_, nullptr, &regs);

    uintptr_t rip = regs.rip;
    uintptr_t rbp = regs.rbp;

    std::cout << "\n=== Stack Trace (PID " << pid_ << ") ===\n";
    std::cout << "PIE: " << (maps_.pie() ? "YES" : "NO")
              << "  base=0x" << std::hex << maps_.base() << std::dec << "\n";

    for (int frame = 0; frame < maxFrames && rbp; ++frame) {
        std::cout << "\n[Frame " << frame << "]\n";
        std::cout << "  RIP: 0x" << std::hex << rip << std::dec << "\n";
        std::cout << "  Symbol:\n    " << addr2line(rip) << "\n";

        std::cout << "  Stack args:\n";
        for (int i = 0; i < 6; ++i) {
            uintptr_t arg = peek(rbp + 16 + i * 8);
            std::cout << "    arg" << i << " = 0x" 
                      << std::hex << arg << std::dec << "\n";
        }

        std::cout << "  Locals:\n";
        for (int i = 0; i < 6; ++i) {
            uintptr_t v = peek(rbp - (i + 1) * 8);
            std::cout << "    [rbp-" << (i + 1) * 8 
                      << "] = 0x" << std::hex << v << std::dec << "\n";
        }

        uintptr_t nextRip = peek(rbp + 8);
        uintptr_t nextRbp = peek(rbp);
        rip = nextRip;
        rbp = nextRbp;
    }

    ptrace(PTRACE_DETACH, pid_, nullptr, nullptr);
    std::cout << "\n[Detached]\n";
}
