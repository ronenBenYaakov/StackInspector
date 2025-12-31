#pragma once
#include <string>
#include <cstdint>
#include <unistd.h>

class ProcMaps {
public:
    ProcMaps(pid_t pid, const std::string& exePath);

    uintptr_t normalize(uintptr_t rip) const;
    bool isPIE() const { return pie; }
    uintptr_t base() const { return textBase; }

private:
    bool pie{false};
    uintptr_t textBase{0};
};
