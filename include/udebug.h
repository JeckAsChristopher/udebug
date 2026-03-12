// SPDX-License-Identifier: MIT
// Copyright (c) 2025 UDEBUG Contributors

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <optional>
#include <functional>
#include <memory>

#if !defined(UDEBUG_WINDOWS) && !defined(UDEBUG_MACOS) && !defined(UDEBUG_LINUX)
  #if defined(_WIN32) || defined(_WIN64)
    #define UDEBUG_WINDOWS
  #elif defined(__APPLE__)
    #define UDEBUG_MACOS
  #elif defined(__linux__)
    #define UDEBUG_LINUX
  #endif
#endif

using Pid   = uint32_t;
using Addr  = uint64_t;
using Bytes = std::vector<uint8_t>;

enum class BinaryFormat { UNKNOWN, ELF, PE, MACHO };

struct Section {
    std::string name;
    Addr        vaddr    = 0;
    uint64_t    size     = 0;
    uint32_t    flags    = 0;
    bool        is_bss   = false;
    bool        is_exec  = false;
    bool        is_write = false;
};

struct MemoryRegion {
    Addr        start = 0;
    Addr        end   = 0;
    std::string perms;
    std::string label;
    uint64_t    size() const { return end - start; }
};

struct RegisterSet {
    std::map<std::string, uint64_t> gpr;
    uint64_t rip = 0;
    uint64_t rsp = 0;
    uint64_t rbp = 0;
};

struct ProcessSnapshot {
    Pid                       pid      = 0;
    std::string               name;
    std::string               exe_path;
    BinaryFormat              format   = BinaryFormat::UNKNOWN;
    std::vector<Section>      sections;
    std::vector<MemoryRegion> maps;
    RegisterSet               regs;
    bool                      elevated = false;
    bool                      attached = false;
};

struct ThreadInfo {
    uint32_t    tid      = 0;
    std::string state;
    std::string state_name;
    uint64_t    cpu_time = 0;
    uint64_t    pc       = 0;
};

struct FdInfo {
    int         fd   = -1;
    std::string path;
    std::string type;
};

struct LibInfo {
    std::string path;
    Addr        base = 0;
    uint64_t    size = 0;
};

struct SigInfo {
    int         signo = 0;
    std::string name;
    std::string disposition;
};

struct RLimit {
    std::string name;
    uint64_t    soft = 0;
    uint64_t    hard = 0;
    std::string unit;
};

struct MemStats {
    uint64_t vsz_bytes    = 0;
    uint64_t rss_bytes    = 0;
    uint64_t heap_bytes   = 0;
    uint64_t stack_bytes  = 0;
    uint64_t code_bytes   = 0;
    uint64_t data_bytes   = 0;
    uint64_t shared_bytes = 0;
    uint64_t anon_bytes   = 0;
};

struct ExtractedString {
    Addr        addr = 0;
    std::string section;
    std::string value;
};

struct SectionEntropy {
    std::string name;
    double      entropy    = 0.0;
    std::string assessment;
};

struct NetConn {
    std::string proto;
    std::string local_addr;
    std::string remote_addr;
    std::string state;
    uint32_t    inode = 0;
};

struct ComprehensiveInfo {
    Pid         pid          = 0;
    Pid         ppid         = 0;
    std::string name;
    std::string exe_path;
    std::string cwd;
    std::vector<std::string> cmdline;
    std::vector<std::string> environ_vars;
    std::string state;
    uint32_t    uid          = 0;
    uint32_t    gid          = 0;
    uint64_t    utime_ms     = 0;
    uint64_t    stime_ms     = 0;
    uint64_t    start_time_s = 0;
    int         nice         = 0;
    uint32_t    num_threads  = 0;
    std::vector<ThreadInfo>      threads;
    std::vector<FdInfo>          fds;
    std::vector<LibInfo>         libs;
    std::vector<SigInfo>         signals;
    std::vector<RLimit>          limits;
    MemStats                     mem;
    std::vector<ExtractedString> strings;
    std::vector<SectionEntropy>  entropy;
    std::vector<NetConn>         net;
};

struct Config {
    bool  dump_bss       = true;
    bool  dump_registers = true;
    bool  dump_maps      = true;
    bool  dump_stack     = false;
    bool  dump_heap      = false;
    bool  comprehensive  = false;
    bool  color_output   = true;
    bool  verbose        = false;
    int   stack_depth    = 16;
    int   hex_width      = 16;
    int   max_strings    = 80;
    int   min_string_len = 5;
    std::string output_file;
};

Config load_config(const std::string& path);

class IDebugger {
public:
    virtual ~IDebugger() = default;
    virtual bool        attach(Pid pid)                         = 0;
    virtual bool        attach_by_name(const std::string& name) = 0;
    virtual void        detach()                                = 0;
    virtual bool        is_attached()  const                    = 0;
    virtual bool        is_elevated()  const                    = 0;
    virtual ProcessSnapshot           snapshot()                = 0;
    virtual Bytes                     read_memory(Addr addr, size_t len) = 0;
    virtual RegisterSet               read_registers()          = 0;
    virtual std::vector<MemoryRegion> memory_map()              = 0;
    virtual ComprehensiveInfo         comprehensive_info(const Config& cfg,
                                          const ProcessSnapshot& snap) = 0;
};

std::unique_ptr<IDebugger> make_debugger();

BinaryFormat         detect_format(const Bytes& header);
std::vector<Section> parse_elf    (const std::string& path);
std::vector<Section> parse_pe     (const std::string& path);
std::vector<Section> parse_macho  (const std::string& path);

class Output {
public:
    explicit Output(const Config& cfg);
    void print_banner();
    void print_snapshot(const ProcessSnapshot& snap);
    void print_sections(const std::vector<Section>& secs);
    void print_maps(const std::vector<MemoryRegion>& maps);
    void print_registers(const RegisterSet& regs);
    void print_hex(const Bytes& data, Addr base_addr);
    void print_bss_summary(const std::vector<Section>& secs,
                           const std::function<Bytes(Addr, size_t)>& reader);
    void print_comprehensive(const ComprehensiveInfo& info);
private:
    const Config& cfg_;
    bool        use_color()                   const;
    std::string col(const char* code)         const;
    void        section_header(const std::string& title);
    std::string fmt_bytes(uint64_t b)         const;
    std::string fmt_ms(uint64_t ms)           const;
};
