#pragma once

#include <string>
#include <cstdint>
#include <sys/types.h>

class StackInspector {
public:
    StackInspector(pid_t pid, const std::string& exe);

    void inspect(int maxFrames = 10);

private:
    pid_t pid_;
    std::string exe_;

    uintptr_t peek(uintptr_t addr);
    std::string addr2line(uintptr_t addr);

    class ProcMaps {
    public:
        ProcMaps(pid_t pid, const std::string& exe);
        uintptr_t normalize(uintptr_t rip) const;
        bool pie() const;
        uintptr_t base() const;
    private:
        bool pie_{false};
        uintptr_t base_{0};
    };
    ProcMaps maps_;
};
