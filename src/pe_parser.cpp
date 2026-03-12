// SPDX-License-Identifier: MIT
// Copyright (c) 2025 UDEBUG Contributors

#include "udebug.h"
#include <fstream>
#include <cstring>
#include <iostream>

#pragma pack(push, 1)
struct IMAGE_DOS_HEADER {
    uint16_t e_magic;
    uint16_t e_cblp, e_cp, e_crlc, e_cparhdr;
    uint16_t e_minalloc, e_maxalloc;
    uint16_t e_ss, e_sp, e_csum, e_ip, e_cs;
    uint16_t e_lfarlc, e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid, e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;
};
struct IMAGE_FILE_HEADER {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};
struct IMAGE_OPTIONAL_HEADER_COMMON { uint16_t Magic; };
struct IMAGE_SECTION_HEADER {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};
#pragma pack(pop)

#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080
#define IMAGE_SCN_MEM_EXECUTE            0x20000000
#define IMAGE_SCN_MEM_WRITE              0x80000000

std::vector<Section> parse_pe(const std::string& path) {
    std::vector<Section> sections;
    std::ifstream f(path, std::ios::binary);
    if (!f) { std::cerr << "[PE] Cannot open: " << path << "\n"; return sections; }

    IMAGE_DOS_HEADER dos{};
    f.read(reinterpret_cast<char*>(&dos), sizeof(dos));
    if (dos.e_magic != 0x5A4D) { std::cerr << "[PE] Bad MZ magic\n"; return sections; }

    f.seekg(dos.e_lfanew);
    uint32_t sig = 0;
    f.read(reinterpret_cast<char*>(&sig), 4);
    if (sig != 0x00004550) { std::cerr << "[PE] Bad PE signature\n"; return sections; }

    IMAGE_FILE_HEADER fh{};
    f.read(reinterpret_cast<char*>(&fh), sizeof(fh));

    IMAGE_OPTIONAL_HEADER_COMMON oh{};
    f.read(reinterpret_cast<char*>(&oh), sizeof(oh));

    f.seekg(dos.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + fh.SizeOfOptionalHeader);

    for (uint16_t i = 0; i < fh.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sh{};
        f.read(reinterpret_cast<char*>(&sh), sizeof(sh));

        Section sec;
        char name_buf[9] = {};
        memcpy(name_buf, sh.Name, 8);
        sec.name     = name_buf;
        sec.vaddr    = static_cast<Addr>(sh.VirtualAddress);
        sec.size     = sh.VirtualSize ? sh.VirtualSize : sh.SizeOfRawData;
        sec.flags    = sh.Characteristics;
        sec.is_exec  = (sh.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        sec.is_write = (sh.Characteristics & IMAGE_SCN_MEM_WRITE)   != 0;
        sec.is_bss   = (sh.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0;
        if (sec.name == ".bss" || sec.name == ".bss$") sec.is_bss = true;
        sections.push_back(sec);
    }
    return sections;
}
