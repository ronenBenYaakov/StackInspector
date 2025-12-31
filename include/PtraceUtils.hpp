#pragma once

#include <sys/ptrace.h>
#include <sys/user.h>
#include <unistd.h>
#include <cstdint>

uintptr_t peek(pid_t pid, uintptr_t addr);
void attachProcess(pid_t pid);
void detachProcess(pid_t pid);
