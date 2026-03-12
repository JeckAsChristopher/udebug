// SPDX-License-Identifier: MIT
// Copyright (c) 2025 PROCDBG Contributors

#include "procdbg.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <cstring>
#include <csignal>

#ifdef PROCDBG_WINDOWS
  #include <windows.h>
  #include <tlhelp32.h>
#else
  #include <unistd.h>
  #include <sys/types.h>
  #include <dirent.h>
#endif

namespace fs = std::filesystem;

static bool g_color = true;
static std::string col_str(const char* c) { return g_color ? c : ""; }

static std::unique_ptr<IDebugger> g_dbg;

static void on_signal(int) {
    std::cout << "\n[PROCDBG] Caught signal, detaching...\n";
    if (g_dbg && g_dbg->is_attached()) g_dbg->detach();
    std::exit(0);
}

static void print_usage(const char* argv0) {
    std::cout <<
        "\nPROCDBG v" PROCDBG_VERSION " - Ultimate Debugger\n"
        "Supports ELF (Linux), PE/EXE (Windows), Mach-O (macOS).\n"
        "Works without root. Running with sudo or as Administrator gives full access.\n"
        "\nUSAGE:\n"
        "  " << argv0 << " --attach <pid|name>    Attach to a running process by PID or name\n"
        "  " << argv0 << " --pid    <pid>          Attach by numeric PID\n"
        "  " << argv0 << " --name   <name>         Attach by process name\n"
        "  " << argv0 << " --file   <binary>        Static parse only, no live attach\n"
        "  " << argv0 << " --config <path>          Load alternate config file\n"
        "  " << argv0 << " --c                      Comprehensive mode: threads, open files,\n"
        "                                environment, libraries, signals, limits,\n"
        "                                network connections, strings, entropy\n"
        "  " << argv0 << " --dump-stack             Dump stack memory at RSP\n"
        "  " << argv0 << " --dump-heap              Dump heap memory regions\n"
        "  " << argv0 << " --no-color               Disable color output\n"
        "  " << argv0 << " --verbose                Verbose internal messages\n"
        "  " << argv0 << " --help                   Show this help\n"
        "\nEXAMPLES:\n"
        "  procdbg --attach myapp\n"
        "  procdbg --attach 1234\n"
        "  procdbg --pid 5678 --dump-stack\n"
        "  procdbg --pid 5678 --c\n"
        "  procdbg --file ./program.elf\n"
        "  procdbg --name nginx --c\n"
        "  sudo procdbg --attach myapp --c\n"
        "\nNOTES:\n"
        "  Without sudo: reads memory maps and parses binary headers.\n"
        "  With sudo:    full memory read, register access, and string extraction.\n\n";
}

static bool is_number(const std::string& s) {
    return !s.empty() && s.find_first_not_of("0123456789") == std::string::npos;
}

static std::string default_config_path() {
    std::vector<std::string> candidates = {
        "procdbg.conf",
        (std::string(getenv("HOME") ? getenv("HOME") : "") + "/.config/procdbg/procdbg.conf"),
        "/etc/procdbg/procdbg.conf"
    };
    for (auto& p : candidates)
        if (fs::exists(p)) return p;
    return "procdbg.conf";
}

static void analyze_file(const std::string& path, const Config& cfg) {
    Output out(cfg);
    out.print_banner();

    if (!fs::exists(path)) {
        std::cerr << "[ERROR] File not found: " << path << "\n";
        return;
    }

    std::ifstream f(path, std::ios::binary);
    Bytes hdr(16, 0);
    f.read(reinterpret_cast<char*>(hdr.data()), 16);
    BinaryFormat fmt = detect_format(hdr);

    std::string fmt_name;
    std::vector<Section> sections;
    switch (fmt) {
        case BinaryFormat::ELF:   fmt_name = "ELF";     sections = parse_elf(path);   break;
        case BinaryFormat::PE:    fmt_name = "PE/EXE";  sections = parse_pe(path);    break;
        case BinaryFormat::MACHO: fmt_name = "Mach-O";  sections = parse_macho(path); break;
        default:
            fmt_name = "UNKNOWN";
            std::cerr << "[WARN] Cannot detect binary format for: " << path << "\n";
    }

    std::cout << "\n  File    : " << path << "\n";
    std::cout << "  Format  : " << fmt_name << "\n";
    std::cout << "  Sections: " << sections.size() << "\n\n";

    out.print_sections(sections);

    for (auto& s : sections) {
        if (s.is_bss) {
            std::cout << "\n  [.bss] \"" << s.name << "\""
                      << "  vaddr=0x" << std::hex << s.vaddr
                      << "  size=" << std::dec << s.size << " bytes\n";
            std::cout << "  Attach to a live process to read BSS contents.\n";
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) { print_usage(argv[0]); return 0; }

    std::string config_path   = default_config_path();
    std::string attach_arg;
    std::string file_arg;
    bool        by_pid        = false;
    bool        by_name       = false;
    bool        static_only   = false;
    bool        verbose_flag  = false;
    bool        no_color      = false;
    bool        dump_stack    = false;
    bool        dump_heap     = false;
    bool        comprehensive = false;

    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if      (a == "--help" || a == "-h")           { print_usage(argv[0]); return 0; }
        else if (a == "--verbose" || a == "-v")          verbose_flag  = true;
        else if (a == "--no-color")                      no_color      = true;
        else if (a == "--dump-stack")                    dump_stack    = true;
        else if (a == "--dump-heap")                     dump_heap     = true;
        else if (a == "--c" || a == "--comprehensive")   comprehensive = true;
        else if ((a == "--config" || a == "-c") && i+1 < argc) config_path = argv[++i];
        else if (a == "--file"   && i+1 < argc) { file_arg   = argv[++i]; static_only = true; }
        else if (a == "--pid"    && i+1 < argc) { attach_arg = argv[++i]; by_pid  = true; }
        else if (a == "--name"   && i+1 < argc) { attach_arg = argv[++i]; by_name = true; }
        else if (a == "--attach" && i+1 < argc) {
            attach_arg = argv[++i];
            by_pid  = is_number(attach_arg);
            by_name = !by_pid;
        } else {
            std::cerr << "[ERROR] Unknown argument: " << a << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    Config cfg   = load_config(config_path);
    if (verbose_flag)  cfg.verbose       = true;
    if (no_color)      cfg.color_output  = false;
    if (dump_stack)    cfg.dump_stack    = true;
    if (dump_heap)     cfg.dump_heap     = true;
    if (comprehensive) cfg.comprehensive = true;
    g_color = cfg.color_output;

    if (static_only) { analyze_file(file_arg, cfg); return 0; }

    if (attach_arg.empty()) {
        std::cerr << "[ERROR] No target specified. Use --attach, --pid, --name, or --file.\n";
        print_usage(argv[0]);
        return 1;
    }

    std::signal(SIGINT,  on_signal);
    std::signal(SIGTERM, on_signal);

    g_dbg = make_debugger();
    Output out(cfg);
    out.print_banner();

    bool ok = false;
    if (by_pid) {
        Pid pid = static_cast<Pid>(std::stoul(attach_arg));
        std::cout << "[PROCDBG] Attaching to PID " << pid << " ...\n";
        ok = g_dbg->attach(pid);
    } else {
        std::cout << "[PROCDBG] Attaching to process \"" << attach_arg << "\" ...\n";
        ok = g_dbg->attach_by_name(attach_arg);
    }

    if (!ok) {
        std::cerr << "[ERROR] Failed to attach.\n";
        std::cerr << "  Try running with sudo (Linux/macOS) or as Administrator (Windows).\n";
        std::cerr << "  Or use --file <binary> for static analysis without attaching.\n";
        return 2;
    }

    ProcessSnapshot snap = g_dbg->snapshot();
    out.print_snapshot(snap);

    if (cfg.dump_registers && snap.attached)
        out.print_registers(snap.regs);

    if (cfg.dump_maps)
        out.print_maps(snap.maps);

    out.print_sections(snap.sections);

    if (cfg.dump_bss && snap.attached) {
        auto reader = [&](Addr a, size_t n) { return g_dbg->read_memory(a, n); };
        out.print_bss_summary(snap.sections, reader);
    }

    if (cfg.dump_stack && snap.attached) {
        std::cout << "\nSTACK SNAPSHOT (" << cfg.stack_depth * cfg.hex_width << " bytes)\n";
        Addr sp = snap.regs.rsp;
        if (sp) {
            Bytes stk = g_dbg->read_memory(sp, cfg.stack_depth * cfg.hex_width);
            out.print_hex(stk, sp);
        } else {
            std::cout << "  Stack pointer not available without elevated privileges.\n";
        }
    }

    if (cfg.comprehensive) {
        std::cout << "\n" << col_str("\033[1m\033[35m")
                  << "COMPREHENSIVE ANALYSIS\n"
                  << std::string(50, '-') << "\n"
                  << col_str("\033[0m");
        ComprehensiveInfo ci = g_dbg->comprehensive_info(cfg, snap);
        out.print_comprehensive(ci);
    }

    std::cout << "\n[PROCDBG] Done. Detaching...\n";
    g_dbg->detach();
    return 0;
}
