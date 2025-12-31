#include "PtraceUtils.hpp"
#include <sys/wait.h>
#include <cerrno>

uintptr_t peek(pid_t pid, uintptr_t addr) {
    errno = 0;
    long val = ptrace(PTRACE_PEEKDATA, pid, addr, nullptr);
    if (errno) return 0;
    return static_cast<uintptr_t>(val);
}

void attachProcess(pid_t pid) {
    ptrace(PTRACE_ATTACH, pid, nullptr, nullptr);
    waitpid(pid, nullptr, 0);
}

void detachProcess(pid_t pid) {
    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
}
