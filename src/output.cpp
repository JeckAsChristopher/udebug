// SPDX-License-Identifier: MIT
// Copyright (c) 2025 PROCDBG Contributors

#include "procdbg.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <cmath>
#include <algorithm>

#define ANSI_RESET   "\033[0m"
#define ANSI_BOLD    "\033[1m"
#define ANSI_RED     "\033[31m"
#define ANSI_GREEN   "\033[32m"
#define ANSI_YELLOW  "\033[33m"
#define ANSI_BLUE    "\033[34m"
#define ANSI_MAGENTA "\033[35m"
#define ANSI_CYAN    "\033[36m"
#define ANSI_WHITE   "\033[37m"
#define ANSI_GRAY    "\033[90m"

Output::Output(const Config& cfg) : cfg_(cfg) {}

bool Output::use_color() const { return cfg_.color_output; }
std::string Output::col(const char* code) const { return use_color() ? code : ""; }

void Output::section_header(const std::string& title) {
    int pad = std::max(0, 47 - (int)title.size());
    std::cout << col(ANSI_BOLD) << col(ANSI_GREEN)
              << "== " << title << " " << std::string(pad, '=')
              << "\n" << col(ANSI_RESET);
}

std::string Output::fmt_bytes(uint64_t b) const {
    char buf[32];
    if      (b >= 1024ULL*1024*1024) snprintf(buf, sizeof(buf), "%.2f GB", b / 1073741824.0);
    else if (b >= 1024*1024)         snprintf(buf, sizeof(buf), "%.2f MB", b / 1048576.0);
    else if (b >= 1024)              snprintf(buf, sizeof(buf), "%.1f KB", b / 1024.0);
    else                             snprintf(buf, sizeof(buf), "%llu B",  (unsigned long long)b);
    return buf;
}

std::string Output::fmt_ms(uint64_t ms) const {
    char buf[32];
    if      (ms >= 3600000) snprintf(buf, sizeof(buf), "%lluh %llum",
        (unsigned long long)ms/3600000, (unsigned long long)(ms%3600000)/60000);
    else if (ms >= 60000)   snprintf(buf, sizeof(buf), "%llum %llus",
        (unsigned long long)ms/60000, (unsigned long long)(ms%60000)/1000);
    else                    snprintf(buf, sizeof(buf), "%.3fs", ms / 1000.0);
    return buf;
}

void Output::print_banner() {
    std::cout << col(ANSI_CYAN) << col(ANSI_BOLD)
              << "\nPROCDBG v" PROCDBG_VERSION " - Ultimate Debugger"
              << "  [ELF / PE / Mach-O]\n"
              << col(ANSI_RESET) << "\n";
}

void Output::print_snapshot(const ProcessSnapshot& snap) {
    section_header("PROCESS INFO");

    auto field = [&](const std::string& k, const std::string& v) {
        std::cout << "  " << col(ANSI_YELLOW) << std::left << std::setw(18) << k
                  << col(ANSI_RESET) << v << "\n";
    };

    std::string fmt;
    switch (snap.format) {
        case BinaryFormat::ELF:   fmt = "ELF (Linux/Unix)"; break;
        case BinaryFormat::PE:    fmt = "PE/EXE (Windows)"; break;
        case BinaryFormat::MACHO: fmt = "Mach-O (macOS)";   break;
        default:                  fmt = "Unknown";           break;
    }

    field("PID:",        std::to_string(snap.pid));
    field("Name:",       snap.name);
    field("Executable:", snap.exe_path.empty() ? "(n/a)" : snap.exe_path);
    field("Format:",     fmt);
    field("Elevated:",   snap.elevated ? "YES - full access" : "NO - limited, try sudo");
    field("Attached:",   snap.attached ? "YES" : "NO");
    std::cout << "\n";
}

void Output::print_sections(const std::vector<Section>& secs) {
    if (secs.empty()) { std::cout << "  No sections parsed.\n"; return; }

    section_header("SECTIONS");
    std::cout << col(ANSI_GRAY)
              << "  " << std::left
              << std::setw(18) << "Name"
              << std::setw(18) << "VirtAddr"
              << std::setw(14) << "Size"
              << std::setw(10) << "Flags"
              << "\n" << col(ANSI_RESET);
    std::cout << "  " << std::string(58, '-') << "\n";

    for (auto& s : secs) {
        std::string flags;
        if (s.is_exec)  flags += "X";
        if (s.is_write) flags += "W";
        if (s.is_bss)   flags += " BSS";

        if      (s.is_bss)  std::cout << col(ANSI_YELLOW);
        else if (s.is_exec) std::cout << col(ANSI_RED);
        else                std::cout << col(ANSI_WHITE);

        std::cout << "  " << std::left << std::setw(18) << s.name
                  << "0x" << std::hex << std::setw(16) << s.vaddr
                  << std::dec << std::setw(14) << s.size
                  << std::setw(10) << flags
                  << col(ANSI_RESET) << "\n";
    }
    std::cout << "\n";
}

void Output::print_maps(const std::vector<MemoryRegion>& maps) {
    if (maps.empty()) {
        std::cout << "  Memory map not available. Try sudo.\n\n";
        return;
    }

    section_header("MEMORY MAP");
    std::cout << col(ANSI_GRAY)
              << "  " << std::left
              << std::setw(20) << "Start"
              << std::setw(20) << "End"
              << std::setw(8)  << "Perms"
              << std::setw(10) << "Size"
              << "Label\n" << col(ANSI_RESET);
    std::cout << "  " << std::string(72, '-') << "\n";

    for (auto& r : maps) {
        bool is_exec  = r.perms.find('x') != std::string::npos;
        bool is_write = r.perms.find('w') != std::string::npos;

        if      (is_exec)  std::cout << col(ANSI_RED);
        else if (is_write) std::cout << col(ANSI_CYAN);
        else               std::cout << col(ANSI_GRAY);

        std::ostringstream sz;
        uint64_t s = r.size();
        if      (s >= 1024*1024) sz << (s/(1024*1024)) << " MB";
        else if (s >= 1024)      sz << (s/1024)         << " KB";
        else                     sz << s                 << " B ";

        std::cout << "  "
                  << "0x" << std::hex << std::setw(18) << r.start
                  << "0x" << std::hex << std::setw(18) << r.end
                  << std::dec << std::setw(8) << r.perms
                  << std::setw(10) << sz.str()
                  << r.label
                  << col(ANSI_RESET) << "\n";
    }
    std::cout << "\n";
}

void Output::print_registers(const RegisterSet& regs) {
    if (regs.gpr.empty() && !regs.rip) {
        std::cout << "  Registers not available. Requires sudo or admin.\n\n";
        return;
    }

    section_header("REGISTERS");

    auto print_reg = [&](const std::string& name, uint64_t val) {
        std::cout << "  " << col(ANSI_YELLOW) << std::left << std::setw(8) << name
                  << col(ANSI_RESET)
                  << "0x" << std::hex << std::setw(16) << std::setfill('0') << val
                  << std::setfill(' ') << "  (" << std::dec << val << ")\n";
    };

    if (regs.rip) print_reg("RIP/PC:", regs.rip);
    if (regs.rsp) print_reg("RSP:",    regs.rsp);
    if (regs.rbp) print_reg("RBP:",    regs.rbp);
    for (auto& [name, val] : regs.gpr)
        print_reg(name + ":", val);

    std::cout << "\n";
}

void Output::print_hex(const Bytes& data, Addr base_addr) {
    if (data.empty()) { std::cout << "  (no data)\n"; return; }

    int w = cfg_.hex_width;
    for (size_t i = 0; i < data.size(); i += w) {
        std::cout << col(ANSI_GRAY)
                  << "  0x" << std::hex << std::setw(12) << std::setfill('0')
                  << (base_addr + i) << "  "
                  << col(ANSI_RESET) << std::setfill(' ');

        for (int j = 0; j < w; j++) {
            if (i + j < data.size())
                std::cout << col(ANSI_CYAN)
                          << std::hex << std::setw(2) << std::setfill('0')
                          << (int)data[i+j] << " "
                          << col(ANSI_RESET) << std::setfill(' ');
            else
                std::cout << "   ";
            if (j == w/2 - 1) std::cout << " ";
        }

        std::cout << " |" << col(ANSI_GREEN);
        for (int j = 0; j < w && i + j < data.size(); j++) {
            uint8_t c = data[i+j];
            std::cout << (char)(c >= 0x20 && c < 0x7f ? c : '.');
        }
        std::cout << col(ANSI_RESET) << "|\n";
    }
}

void Output::print_bss_summary(const std::vector<Section>& secs,
                                const std::function<Bytes(Addr, size_t)>& reader) {
    bool any = false;
    for (auto& s : secs) {
        if (!s.is_bss) continue;
        any = true;
        section_header("BSS SECTION: " + s.name);
        std::cout << "  vaddr = 0x" << std::hex << s.vaddr
                  << "  size = " << std::dec << s.size << " bytes\n\n";

        if (s.size == 0) { std::cout << "  Empty section.\n\n"; continue; }

        size_t dump_len = std::min<uint64_t>(s.size, 256);
        Bytes  data     = reader(s.vaddr, dump_len);

        if (data.empty()) {
            std::cout << col(ANSI_RED)
                      << "  Cannot read memory. Process may require elevated privileges.\n"
                      << col(ANSI_RESET);
        } else {
            bool all_zero = true;
            for (auto b : data) if (b) { all_zero = false; break; }
            if (all_zero)
                std::cout << col(ANSI_GRAY) << "  All zeros - uninitialized.\n" << col(ANSI_RESET);
            else
                std::cout << col(ANSI_GREEN) << "  Contains runtime data.\n" << col(ANSI_RESET);

            print_hex(data, s.vaddr);
            if (dump_len < s.size)
                std::cout << col(ANSI_GRAY)
                          << "  ... (" << (s.size - dump_len) << " more bytes not shown)\n"
                          << col(ANSI_RESET);
        }
        std::cout << "\n";
    }
    if (!any) std::cout << "  No BSS or uninitialized-data sections found.\n\n";
}

void Output::print_comprehensive(const ComprehensiveInfo& ci) {
    auto field = [&](const std::string& k, const std::string& v,
                     const char* vc = ANSI_WHITE) {
        std::cout << "  " << col(ANSI_YELLOW) << std::left << std::setw(22) << k
                  << col(vc) << v << col(ANSI_RESET) << "\n";
    };

    section_header("PROCESS IDENTITY AND RUNTIME");
    field("PID:",        std::to_string(ci.pid));
    field("PPID:",       std::to_string(ci.ppid));
    field("Name:",       ci.name);
    field("Exe:",        ci.exe_path.empty() ? "(n/a)" : ci.exe_path);
    field("CWD:",        ci.cwd.empty()      ? "(n/a)" : ci.cwd);
    field("State:",      ci.state);
    field("UID / GID:",  std::to_string(ci.uid) + " / " + std::to_string(ci.gid));
    field("User CPU:",   fmt_ms(ci.utime_ms));
    field("Kernel CPU:", fmt_ms(ci.stime_ms));
    field("Nice:",       std::to_string(ci.nice));
    field("Threads:",    std::to_string(ci.num_threads));

    if (!ci.cmdline.empty()) {
        std::cout << "  " << col(ANSI_YELLOW) << std::left << std::setw(22)
                  << "Cmdline:" << col(ANSI_RESET);
        for (size_t i = 0; i < ci.cmdline.size(); i++) {
            if (i) std::cout << " ";
            std::cout << col(ANSI_CYAN) << ci.cmdline[i] << col(ANSI_RESET);
        }
        std::cout << "\n";
    }
    std::cout << "\n";

    section_header("ENVIRONMENT VARIABLES (" + std::to_string(ci.environ_vars.size()) + ")");
    if (ci.environ_vars.empty()) {
        std::cout << "  Not accessible. Try sudo.\n";
    } else {
        for (auto& ev : ci.environ_vars) {
            auto eq = ev.find('=');
            if (eq != std::string::npos) {
                std::cout << "  " << col(ANSI_YELLOW)
                          << std::left << std::setw(30) << ev.substr(0, eq)
                          << col(ANSI_RESET) << ev.substr(eq + 1) << "\n";
            } else {
                std::cout << "  " << ev << "\n";
            }
        }
    }
    std::cout << "\n";

    section_header("THREADS (" + std::to_string(ci.threads.size()) + ")");
    if (ci.threads.empty()) {
        std::cout << "  Thread list unavailable.\n";
    } else {
        std::cout << col(ANSI_GRAY)
                  << "  " << std::left
                  << std::setw(10) << "TID"
                  << std::setw(10) << "State"
                  << std::setw(16) << "State Name"
                  << std::setw(14) << "CPU Time"
                  << "\n" << col(ANSI_RESET);
        std::cout << "  " << std::string(48, '-') << "\n";
        for (auto& t : ci.threads) {
            const char* sc = ANSI_WHITE;
            if      (t.state == "R") sc = ANSI_GREEN;
            else if (t.state == "D") sc = ANSI_RED;
            else if (t.state == "Z") sc = ANSI_MAGENTA;
            std::cout << col(sc)
                      << "  " << std::left
                      << std::setw(10) << t.tid
                      << std::setw(10) << t.state
                      << std::setw(16) << (t.state_name.empty() ? "-" : t.state_name)
                      << std::setw(14) << (t.cpu_time ? fmt_ms(t.cpu_time) : "-")
                      << col(ANSI_RESET) << "\n";
        }
    }
    std::cout << "\n";

    section_header("OPEN FILE DESCRIPTORS (" + std::to_string(ci.fds.size()) + ")");
    if (ci.fds.empty()) {
        std::cout << "  FD list unavailable. Try sudo.\n";
    } else {
        std::cout << col(ANSI_GRAY)
                  << "  " << std::setw(6) << "FD"
                  << std::setw(10) << "Type"
                  << "Path\n" << col(ANSI_RESET);
        std::cout << "  " << std::string(60, '-') << "\n";
        for (auto& fd : ci.fds) {
            const char* fc = ANSI_WHITE;
            if      (fd.type == "socket") fc = ANSI_CYAN;
            else if (fd.type == "pipe")   fc = ANSI_YELLOW;
            std::cout << col(fc)
                      << "  " << std::setw(6) << fd.fd
                      << std::setw(10) << fd.type
                      << fd.path
                      << col(ANSI_RESET) << "\n";
        }
    }
    std::cout << "\n";

    section_header("LOADED LIBRARIES (" + std::to_string(ci.libs.size()) + ")");
    if (ci.libs.empty()) {
        std::cout << "  Library list unavailable.\n";
    } else {
        std::cout << col(ANSI_GRAY)
                  << "  " << std::left
                  << std::setw(20) << "Base Addr"
                  << std::setw(12) << "Size"
                  << "Path\n" << col(ANSI_RESET);
        std::cout << "  " << std::string(64, '-') << "\n";
        for (auto& lib : ci.libs) {
            std::cout << "  " << col(ANSI_CYAN)
                      << "0x" << std::hex << std::setw(16) << std::setfill('0') << lib.base
                      << std::setfill(' ') << std::dec
                      << "  " << std::left << std::setw(10) << fmt_bytes(lib.size)
                      << col(ANSI_WHITE) << lib.path
                      << col(ANSI_RESET) << "\n";
        }
    }
    std::cout << "\n";

    section_header("MEMORY BREAKDOWN");
    auto mem_row = [&](const std::string& label, uint64_t bytes, const char* c = ANSI_WHITE) {
        if (!bytes) return;
        std::cout << "  " << col(ANSI_YELLOW) << std::left << std::setw(20) << label
                  << col(c) << fmt_bytes(bytes) << col(ANSI_RESET) << "\n";
    };
    mem_row("Virtual (VSZ):",  ci.mem.vsz_bytes);
    mem_row("Resident (RSS):", ci.mem.rss_bytes,    ANSI_GREEN);
    mem_row("Code (r-x):",     ci.mem.code_bytes,   ANSI_RED);
    mem_row("Data (rw-):",     ci.mem.data_bytes,   ANSI_CYAN);
    mem_row("Heap:",           ci.mem.heap_bytes,   ANSI_YELLOW);
    mem_row("Stack:",          ci.mem.stack_bytes,  ANSI_MAGENTA);
    mem_row("Shared/mapped:",  ci.mem.shared_bytes);
    mem_row("Anonymous:",      ci.mem.anon_bytes);
    std::cout << "\n";

    section_header("SIGNAL DISPOSITION");
    if (ci.signals.empty()) {
        std::cout << "  Signal info unavailable.\n";
    } else {
        size_t per_row = 3;
        for (size_t i = 0; i < ci.signals.size(); i++) {
            auto& s = ci.signals[i];
            const char* sc = ANSI_GRAY;
            if      (s.disposition == "CAUGHT")  sc = ANSI_GREEN;
            else if (s.disposition == "BLOCKED")  sc = ANSI_YELLOW;

            std::cout << "  " << col(ANSI_WHITE) << std::left << std::setw(10) << s.name
                      << col(sc) << std::setw(8) << s.disposition << col(ANSI_RESET);
            if ((i+1) % per_row == 0 || i+1 == ci.signals.size()) std::cout << "\n";
        }
    }
    std::cout << "\n";

    section_header("RESOURCE LIMITS");
    if (ci.limits.empty()) {
        std::cout << "  Limits unavailable.\n";
    } else {
        std::cout << col(ANSI_GRAY)
                  << "  " << std::left
                  << std::setw(30) << "Limit"
                  << std::setw(20) << "Soft"
                  << std::setw(20) << "Hard"
                  << "Unit\n" << col(ANSI_RESET);
        std::cout << "  " << std::string(74, '-') << "\n";
        for (auto& rl : ci.limits) {
            auto fmt_lim = [](uint64_t v) -> std::string {
                return (v == UINT64_MAX) ? "unlimited" : std::to_string(v);
            };
            std::cout << "  " << col(ANSI_WHITE) << std::left << std::setw(30) << rl.name
                      << col(ANSI_CYAN)  << std::setw(20) << fmt_lim(rl.soft)
                      << col(ANSI_GREEN) << std::setw(20) << fmt_lim(rl.hard)
                      << col(ANSI_GRAY)  << rl.unit
                      << col(ANSI_RESET) << "\n";
        }
    }
    std::cout << "\n";

    section_header("NETWORK CONNECTIONS (" + std::to_string(ci.net.size()) + ")");
    if (ci.net.empty()) {
        std::cout << "  None or unavailable.\n";
    } else {
        std::cout << col(ANSI_GRAY)
                  << "  " << std::left
                  << std::setw(8)  << "Proto"
                  << std::setw(26) << "Local"
                  << std::setw(26) << "Remote"
                  << "State\n" << col(ANSI_RESET);
        std::cout << "  " << std::string(72, '-') << "\n";
        for (auto& nc : ci.net) {
            const char* nc_col = (nc.state == "ESTABLISHED") ? ANSI_GREEN :
                                 (nc.state == "LISTEN")       ? ANSI_CYAN  : ANSI_WHITE;
            std::cout << col(nc_col)
                      << "  " << std::left
                      << std::setw(8)  << nc.proto
                      << std::setw(26) << nc.local_addr
                      << std::setw(26) << nc.remote_addr
                      << nc.state
                      << col(ANSI_RESET) << "\n";
        }
    }
    std::cout << "\n";

    section_header("SECTION ENTROPY ANALYSIS");
    if (ci.entropy.empty()) {
        std::cout << "  Entropy unavailable.\n";
    } else {
        std::cout << col(ANSI_GRAY)
                  << "  " << std::left
                  << std::setw(20) << "Section"
                  << std::setw(10) << "Entropy"
                  << "Assessment\n" << col(ANSI_RESET);
        std::cout << "  " << std::string(60, '-') << "\n";
        for (auto& se : ci.entropy) {
            const char* ec = ANSI_GREEN;
            if      (se.entropy > 7.2) ec = ANSI_RED;
            else if (se.entropy > 6.5) ec = ANSI_YELLOW;
            else if (se.entropy > 4.5) ec = ANSI_CYAN;

            std::cout << "  " << col(ANSI_WHITE)
                      << std::left << std::setw(20) << se.name
                      << col(ec) << std::fixed << std::setprecision(3)
                      << std::setw(10) << se.entropy
                      << col(ANSI_RESET) << se.assessment << "\n";
        }
    }
    std::cout << "\n";

    section_header("EXTRACTED STRINGS (" + std::to_string(ci.strings.size()) + ")");
    if (ci.strings.empty()) {
        std::cout << "  No strings found or memory unreadable. Try sudo for better results.\n";
    } else {
        std::cout << col(ANSI_GRAY)
                  << "  " << std::left
                  << std::setw(18) << "Address"
                  << std::setw(14) << "Section"
                  << "String\n" << col(ANSI_RESET);
        std::cout << "  " << std::string(70, '-') << "\n";
        for (auto& es : ci.strings) {
            std::cout << "  " << col(ANSI_GRAY)
                      << "0x" << std::hex << std::setw(14) << std::setfill('0') << es.addr
                      << std::setfill(' ') << std::dec
                      << col(ANSI_YELLOW) << std::left << std::setw(14) << es.section
                      << col(ANSI_WHITE) << es.value
                      << col(ANSI_RESET) << "\n";
        }
    }
    std::cout << "\n";
}
