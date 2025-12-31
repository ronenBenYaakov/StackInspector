#include "DWARFParser.hpp"

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>

#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <cstdint>
#include <fstream>

class StackInspector {
public:
    StackInspector(pid_t pid, const std::string& exe)
        : pid(pid), exe(exe), dwarf(exe) {}

    void inspect(int maxFrames = 10) {
        attach();
        user_regs_struct regs{};
        ptrace(PTRACE_GETREGS, pid, nullptr, &regs);

        uintptr_t rip = regs.rip;
        uintptr_t rbp = regs.rbp;

        std::cout << "\n=== Stack Trace (PID " << pid << ") ===\n";
        std::cout << "PIE: " << (isPIE() ? "YES" : "NO") 
                  << "  base=0x" << std::hex << exeBase() << std::dec << "\n";

        for (int frame = 0; frame < maxFrames && rbp; ++frame) {
            std::cout << "\n[Frame " << frame << "]\n";
            std::cout << "  RIP: 0x" << std::hex << rip << std::dec << "\n";

            auto fnInfo = dwarf.lookup(rip);
            std::cout << "  Function: " << fnInfo.name << " ("
                      << fnInfo.file << ":" << fnInfo.line << ")\n";

            // Print arguments
            std::cout << "  Arguments:\n";
            for (size_t i = 0; i < fnInfo.args.size(); ++i) {
                uintptr_t val = peek(rbp + 16 + i * 8);
                std::cout << "    " 
                            << fnInfo.args[i].type << " " 
                            << fnInfo.args[i].name 
                            << "\n"
                            << " = 0x" << std::hex << val << std::dec << "\n";
            }

            // Print locals (raw)
            std::cout << "  Locals:\n";
            for (int i = 0; i < 6; ++i) {
                uintptr_t loc = peek(rbp - (i + 1) * 8);
                std::cout << "    [rbp-" << (i + 1) * 8
                          << "] = 0x" << std::hex << loc << std::dec << "\n";
            }

            // next frame
            uintptr_t next_rip = peek(rbp + 8);
            uintptr_t next_rbp = peek(rbp);

            rip = next_rip;
            rbp = next_rbp;
        }

        detach();
        std::cout << "\n[Detached]\n";
    }

private:
    pid_t pid;
    std::string exe;
    DWARFParser dwarf;

    void attach() {
        ptrace(PTRACE_ATTACH, pid, nullptr, nullptr);
        waitpid(pid, nullptr, 0);
    }

    void detach() {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    }

    uintptr_t peek(uintptr_t addr) {
        errno = 0;
        long val = ptrace(PTRACE_PEEKDATA, pid, addr, nullptr);
        if (errno) return 0;
        return static_cast<uintptr_t>(val);
    }

    bool isPIE() {
        // quick check if executable is PIE
        return exeBase() != 0;
    }

    uintptr_t exeBase() {
        // read /proc/<pid>/maps first line
        std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
        if (!maps.is_open()) return 0;
        std::string line;
        if (std::getline(maps, line)) {
            std::istringstream iss(line);
            std::string addr;
            if (iss >> addr) {
                auto dash = addr.find('-');
                if (dash != std::string::npos) {
                    return std::stoull(addr.substr(0, dash), nullptr, 16);
                }
            }
        }
        return 0;
    }
};
