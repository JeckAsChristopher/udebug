// SPDX-License-Identifier: MIT
// Copyright (c) 2025 UDEBUG Contributors

#include "udebug.h"
#include <fstream>
#include <cstring>
#include <iostream>

#define MH_MAGIC    0xFEEDFACEu
#define MH_CIGAM    0xCEFAEDFEu
#define MH_MAGIC_64 0xFEEDFACFu
#define MH_CIGAM_64 0xCFFAEDFEu
#define FAT_MAGIC   0xCAFEBABEu
#define LC_SEGMENT    0x1
#define LC_SEGMENT_64 0x19
#define S_ZEROFILL    0x1

#pragma pack(push, 1)
struct mach_header    { uint32_t magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags; };
struct mach_header_64 { uint32_t magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved; };
struct load_command   { uint32_t cmd, cmdsize; };
struct segment_command    { uint32_t cmd, cmdsize; char segname[16]; uint32_t vmaddr, vmsize, fileoff, filesize; int32_t maxprot, initprot; uint32_t nsects, flags; };
struct segment_command_64 { uint32_t cmd, cmdsize; char segname[16]; uint64_t vmaddr, vmsize, fileoff, filesize; int32_t maxprot, initprot; uint32_t nsects, flags; };
struct section    { char sectname[16], segname[16]; uint32_t addr, size; uint32_t offset, align, reloff, nreloc, flags, reserved1, reserved2; };
struct section_64 { char sectname[16], segname[16]; uint64_t addr, size; uint32_t offset, align, reloff, nreloc, flags, reserved1, reserved2, reserved3; };
struct fat_header { uint32_t magic, nfat_arch; };
struct fat_arch   { int32_t cputype, cpusubtype; uint32_t offset, size, align; };
#pragma pack(pop)

static bool needs_swap(uint32_t magic) { return magic == MH_CIGAM || magic == MH_CIGAM_64; }
static uint32_t swap32(uint32_t v, bool sw) {
    if (!sw) return v;
    return ((v&0xFF)<<24)|(((v>>8)&0xFF)<<16)|(((v>>16)&0xFF)<<8)|((v>>24)&0xFF);
}

static void parse_macho_at(std::ifstream& f, uint32_t magic, std::vector<Section>& out) {
    bool sw   = needs_swap(magic);
    bool is64 = (magic == MH_MAGIC_64 || magic == MH_CIGAM_64);

    uint32_t ncmds = 0;
    if (is64) { mach_header_64 mh{}; f.read(reinterpret_cast<char*>(&mh)+4, sizeof(mh)-4); ncmds = swap32(mh.ncmds, sw); }
    else      { mach_header    mh{}; f.read(reinterpret_cast<char*>(&mh)+4, sizeof(mh)-4); ncmds = swap32(mh.ncmds, sw); }

    for (uint32_t i = 0; i < ncmds; i++) {
        std::streampos lc_start = f.tellg();
        load_command lc{};
        f.read(reinterpret_cast<char*>(&lc), sizeof(lc));
        uint32_t cmd     = swap32(lc.cmd, sw);
        uint32_t cmdsize = swap32(lc.cmdsize, sw);
        if (cmdsize < sizeof(lc)) break;

        if (cmd == LC_SEGMENT_64 && is64) {
            f.seekg(lc_start);
            segment_command_64 seg{};
            f.read(reinterpret_cast<char*>(&seg), sizeof(seg));
            uint32_t nsects = swap32(seg.nsects, sw);
            for (uint32_t s = 0; s < nsects; s++) {
                section_64 sc{};
                f.read(reinterpret_cast<char*>(&sc), sizeof(sc));
                Section sec;
                char sn[17]={}, segn[17]={};
                memcpy(sn, sc.sectname, 16); memcpy(segn, sc.segname, 16);
                sec.name    = std::string(segn) + "." + sn;
                sec.vaddr   = sc.addr; sec.size = sc.size; sec.flags = sc.flags;
                sec.is_bss  = (sc.flags & 0xFF) == S_ZEROFILL;
                sec.is_exec = (std::string(segn) == "__TEXT");
                sec.is_write= (std::string(segn) == "__DATA");
                out.push_back(sec);
            }
        } else if (cmd == LC_SEGMENT && !is64) {
            f.seekg(lc_start);
            segment_command seg{};
            f.read(reinterpret_cast<char*>(&seg), sizeof(seg));
            uint32_t nsects = swap32(seg.nsects, sw);
            for (uint32_t s = 0; s < nsects; s++) {
                section sc{};
                f.read(reinterpret_cast<char*>(&sc), sizeof(sc));
                Section sec;
                char sn[17]={}, segn[17]={};
                memcpy(sn, sc.sectname, 16); memcpy(segn, sc.segname, 16);
                sec.name    = std::string(segn) + "." + sn;
                sec.vaddr   = sc.addr; sec.size = sc.size; sec.flags = sc.flags;
                sec.is_bss  = (sc.flags & 0xFF) == S_ZEROFILL;
                sec.is_exec = (std::string(segn) == "__TEXT");
                sec.is_write= (std::string(segn) == "__DATA");
                out.push_back(sec);
            }
        }
        f.seekg(lc_start + (std::streampos)cmdsize);
    }
}

std::vector<Section> parse_macho(const std::string& path) {
    std::vector<Section> sections;
    std::ifstream f(path, std::ios::binary);
    if (!f) { std::cerr << "[Mach-O] Cannot open: " << path << "\n"; return sections; }

    uint32_t magic = 0;
    f.read(reinterpret_cast<char*>(&magic), 4);

    if (magic == FAT_MAGIC) {
        fat_header fh{};
        f.seekg(0);
        f.read(reinterpret_cast<char*>(&fh), sizeof(fh));
        uint32_t narch = __builtin_bswap32(fh.nfat_arch);
        for (uint32_t i = 0; i < narch; i++) {
            fat_arch fa{};
            f.read(reinterpret_cast<char*>(&fa), sizeof(fa));
            uint32_t off = __builtin_bswap32(fa.offset);
            std::streampos saved = f.tellg();
            f.seekg(off);
            uint32_t arch_magic = 0;
            f.read(reinterpret_cast<char*>(&arch_magic), 4);
            parse_macho_at(f, arch_magic, sections);
            f.seekg(saved);
            if (!sections.empty()) break;
        }
    } else if (magic == MH_MAGIC || magic == MH_CIGAM ||
               magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
        parse_macho_at(f, magic, sections);
    } else {
        std::cerr << "[Mach-O] Unrecognized magic: 0x" << std::hex << magic << "\n";
    }
    return sections;
}
