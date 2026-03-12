// SPDX-License-Identifier: MIT
// Copyright (c) 2025 PROCDBG Contributors

#include "procdbg.h"
#include <fstream>
#include <cstring>
#include <iostream>

static const uint8_t ELF_MAGIC[4] = {0x7f, 'E', 'L', 'F'};

using Elf32_Half  = uint16_t;
using Elf32_Word  = uint32_t;
using Elf32_Addr  = uint32_t;
using Elf32_Off   = uint32_t;
using Elf64_Half  = uint16_t;
using Elf64_Word  = uint32_t;
using Elf64_Xword = uint64_t;
using Elf64_Addr  = uint64_t;
using Elf64_Off   = uint64_t;

#define EI_CLASS    4
#define ELFCLASS32  1
#define ELFCLASS64  2
#define SHT_NULL    0
#define SHT_NOBITS  8
#define SHF_WRITE       0x1
#define SHF_ALLOC       0x2
#define SHF_EXECINSTR   0x4

#pragma pack(push, 1)
struct Elf32_Ehdr {
    uint8_t    e_ident[16];
    Elf32_Half e_type, e_machine;
    Elf32_Word e_version;
    Elf32_Addr e_entry;
    Elf32_Off  e_phoff, e_shoff;
    Elf32_Word e_flags;
    Elf32_Half e_ehsize, e_phentsize, e_phnum;
    Elf32_Half e_shentsize, e_shnum, e_shstrndx;
};
struct Elf64_Ehdr {
    uint8_t    e_ident[16];
    Elf64_Half e_type, e_machine;
    Elf64_Word e_version;
    Elf64_Addr e_entry;
    Elf64_Off  e_phoff, e_shoff;
    Elf64_Word e_flags;
    Elf64_Half e_ehsize, e_phentsize, e_phnum;
    Elf64_Half e_shentsize, e_shnum, e_shstrndx;
};
struct Elf32_Shdr {
    Elf32_Word sh_name, sh_type, sh_flags;
    Elf32_Addr sh_addr;
    Elf32_Off  sh_offset;
    Elf32_Word sh_size, sh_link, sh_info, sh_addralign, sh_entsize;
};
struct Elf64_Shdr {
    Elf32_Word  sh_name, sh_type;
    Elf64_Xword sh_flags;
    Elf64_Addr  sh_addr;
    Elf64_Off   sh_offset;
    Elf64_Xword sh_size, sh_link, sh_info, sh_addralign, sh_entsize;
};
#pragma pack(pop)

BinaryFormat detect_format(const Bytes& hdr) {
    if (hdr.size() >= 4 && memcmp(hdr.data(), ELF_MAGIC, 4) == 0)
        return BinaryFormat::ELF;
    if (hdr.size() >= 2 && hdr[0] == 'M' && hdr[1] == 'Z')
        return BinaryFormat::PE;
    if (hdr.size() >= 4) {
        uint32_t magic;
        memcpy(&magic, hdr.data(), 4);
        if (magic == 0xFEEDFACEu || magic == 0xFEEDFACFu ||
            magic == 0xCEFAEDFEu || magic == 0xCFFAEDFEu ||
            magic == 0xBEBAFECAu)
            return BinaryFormat::MACHO;
    }
    return BinaryFormat::UNKNOWN;
}

std::vector<Section> parse_elf(const std::string& path) {
    std::vector<Section> sections;
    std::ifstream f(path, std::ios::binary);
    if (!f) { std::cerr << "[ELF] Cannot open: " << path << "\n"; return sections; }

    uint8_t ident[16] = {};
    f.read(reinterpret_cast<char*>(ident), 16);
    if (memcmp(ident, ELF_MAGIC, 4) != 0) {
        std::cerr << "[ELF] Not an ELF file\n";
        return sections;
    }

    uint8_t elfclass = ident[EI_CLASS];
    f.seekg(0);

    auto read_sections = [&]<typename Ehdr, typename Shdr>() {
        Ehdr ehdr{};
        f.read(reinterpret_cast<char*>(&ehdr), sizeof(Ehdr));
        if (!ehdr.e_shoff || !ehdr.e_shnum) return;

        std::vector<Shdr> shdrs(ehdr.e_shnum);
        f.seekg(ehdr.e_shoff);
        f.read(reinterpret_cast<char*>(shdrs.data()), ehdr.e_shnum * sizeof(Shdr));

        std::string strtab;
        if (ehdr.e_shstrndx < ehdr.e_shnum) {
            auto& shstr = shdrs[ehdr.e_shstrndx];
            strtab.resize(shstr.sh_size);
            f.seekg(shstr.sh_offset);
            f.read(strtab.data(), shstr.sh_size);
        }

        for (auto& sh : shdrs) {
            if (sh.sh_type == SHT_NULL) continue;
            Section sec;
            sec.name     = (sh.sh_name < strtab.size()) ? strtab.c_str() + sh.sh_name : "<unnamed>";
            sec.vaddr    = static_cast<Addr>(sh.sh_addr);
            sec.size     = static_cast<uint64_t>(sh.sh_size);
            sec.flags    = static_cast<uint32_t>(sh.sh_flags);
            sec.is_bss   = (sh.sh_type == SHT_NOBITS) && (sh.sh_flags & SHF_ALLOC);
            sec.is_exec  = (sh.sh_flags & SHF_EXECINSTR) != 0;
            sec.is_write = (sh.sh_flags & SHF_WRITE)     != 0;
            if (sec.name == ".bss" || sec.name == ".tbss" ||
                sec.name == ".sbss" || sec.name == ".bss.rel.ro")
                sec.is_bss = true;
            sections.push_back(sec);
        }
    };

    if      (elfclass == ELFCLASS64) read_sections.operator()<Elf64_Ehdr, Elf64_Shdr>();
    else if (elfclass == ELFCLASS32) read_sections.operator()<Elf32_Ehdr, Elf32_Shdr>();
    else std::cerr << "[ELF] Unknown class: " << (int)elfclass << "\n";

    return sections;
}
