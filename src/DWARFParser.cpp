#include "DWARFParser.hpp"
#include <libdwarf/libdwarf.h>
#include <libdwarf/dwarf.h>
#include <libelf.h>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <vector>
#include <cstring>
#include <cassert>

DWARFParser::DWARFParser(const std::string& exePath)
    : exePath_(exePath) {}

DWARFParser::~DWARFParser() {}

bool DWARFParser::load() {
    return parseDwarf();
}

FunctionInfo DWARFParser::lookup(uintptr_t addr) const {
    for (const auto& [lowPC, info] : functions_) {
        if (addr >= lowPC && addr < info.highPC) {
            return info;
        }
    }
    return FunctionInfo{}; // empty = unknown
}

bool DWARFParser::parseDwarf() {
    int fd = open(exePath_.c_str(), O_RDONLY);
    if (fd < 0) {
        perror("open");
        return false;
    }

    if (elf_version(EV_CURRENT) == EV_NONE) {
        std::cerr << "ELF library init failed\n";
        close(fd);
        return false;
    }

    Elf* e = elf_begin(fd, ELF_C_READ, nullptr);
    if (!e) {
        std::cerr << "elf_begin failed\n";
        close(fd);
        return false;
    }

    Dwarf_Debug dbg = nullptr;
    Dwarf_Error err = nullptr;

    if (dwarf_init(fd, DW_DLC_READ, nullptr, nullptr, &dbg, &err) != DW_DLV_OK) {
        std::cerr << "dwarf_init failed\n";
        elf_end(e);
        close(fd);
        return false;
    }

    while (true) {
        Dwarf_Unsigned cuHeaderLength = 0;
        Dwarf_Half version = 0;
        Dwarf_Off abbrevOffset = 0;
        Dwarf_Half addressSize = 0;
        Dwarf_Half offsetIntoSection = 0;
        Dwarf_Half nextCuHeaderOffset = 0;
        Dwarf_Sig8* typeSig = nullptr;
        Dwarf_Unsigned nextCuHeader = 0;
        Dwarf_Unsigned headerCuType = 0;
        Dwarf_Half headerAbbrevOffset = 0;

        int res = dwarf_next_cu_header_d(
            dbg,
            true,
            &cuHeaderLength,
            &version,
            &abbrevOffset,
            &addressSize,
            &offsetIntoSection,
            &nextCuHeaderOffset,
            typeSig,
            &nextCuHeader,
            &headerCuType,
            &headerAbbrevOffset,
            &err
        );

        if (res == DW_DLV_NO_ENTRY) break;
        if (res != DW_DLV_OK) {
            std::cerr << "Error reading CU header\n";
            break;
        }

        Dwarf_Die cuDie = nullptr;
        if (dwarf_siblingof(dbg, nullptr, &cuDie, &err) != DW_DLV_OK) continue;

        std::vector<Dwarf_Die> stack{cuDie};

        while (!stack.empty()) {
            Dwarf_Die die = stack.back();
            stack.pop_back();

            Dwarf_Half tag = 0;
            if (dwarf_tag(die, &tag, &err) != DW_DLV_OK) continue;

            char* dieName = nullptr;
            dwarf_diename(die, &dieName, &err);

            if (tag == DW_TAG_subprogram) {
                Dwarf_Addr lowpc = 0;
                Dwarf_Addr highpc = 0;
                dwarf_lowpc(die, &lowpc, &err);
                dwarf_highpc(die, &highpc, &err);

                FunctionInfo info;
                info.name = dieName ? dieName : "??";
                info.lowPC = static_cast<uintptr_t>(lowpc);
                info.highPC = static_cast<uintptr_t>(highpc);

                // Collect argument names
                Dwarf_Die child;
                if (dwarf_child(die, &child, &err) == DW_DLV_OK) {
                    Dwarf_Die c = child;
                    while (c) {
                        Dwarf_Half ctag;
                        if (dwarf_tag(c, &ctag, &err) == DW_DLV_OK) {
                            if (ctag == DW_TAG_formal_parameter) {
                                char* argName = nullptr;
                                if (dwarf_diename(c, &argName, &err) == DW_DLV_OK && argName) {
                                    info.argNames.push_back(argName);
                                }
                            }
                        }
                        Dwarf_Die sibling;
                        if (dwarf_siblingof(dbg, c, &sibling, &err) != DW_DLV_OK) break;
                        c = sibling;
                    }
                }

                functions_[info.lowPC] = info;
            }

            Dwarf_Die sibling;
            if (dwarf_siblingof(dbg, die, &sibling, &err) == DW_DLV_OK) {
                stack.push_back(sibling);
            }
        }

        dwarf_dealloc(dbg, cuDie, DW_DLA_DIE);
    }

    dwarf_finish(dbg, &err);
    elf_end(e);
    close(fd);
    return true;
}
