#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

struct ArgInfo {
    std::string type;  // optional, can leave empty if DWARF parser doesn't resolve type yet
    std::string name;
};

struct FunctionInfo {
    std::string name;
    std::string file;        // source file
    int line = 0;            // line number
    uintptr_t lowPC = 0;
    uintptr_t highPC = 0;
    std::vector<std::string> argNames;
    std::vector<ArgInfo> args;  // full argument info
};


class DWARFParser {
public:
    DWARFParser(const std::string& exePath);
    ~DWARFParser();

    // Load DWARF info from the executable
    bool load();

    // Lookup function and argument info for a given address
    FunctionInfo lookup(uintptr_t addr) const;

private:
    std::string exePath_;
    std::unordered_map<uintptr_t, FunctionInfo> functions_; // key: lowPC

    bool parseDwarf();
};
