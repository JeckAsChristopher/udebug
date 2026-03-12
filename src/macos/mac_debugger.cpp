// SPDX-License-Identifier: MIT
// Copyright (c) 2025 PROCDBG Contributors
//  PROCDBG — src/macos/mac_debugger.cpp
//  macOS implementation using Mach kernel APIs:
//    - task_for_pid()        (needs sudo or com.apple.security.cs.debugger)
//    - mach_vm_read_overwrite() for memory
//    - mach_vm_region()       for memory map
//    - thread_get_state()     for registers

#ifdef PROCDBG_MACOS

#include "mac_debugger.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <cerrno>
#include <cmath>
#include <set>
#include <unistd.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/sysctl.h>
#include <mach/mach_vm.h>
#include <mach/vm_region.h>
#include <mach/thread_act.h>
#include <mach/thread_info.h>

#ifdef __x86_64__
#include <mach/x86/thread_status.h>
#elif defined(__aarch64__)
#include <mach/arm/thread_status.h>
#endif

MacDebugger::MacDebugger() {
    elevated_ = (geteuid() == 0);
}

MacDebugger::~MacDebugger() {
    if (task_ != TASK_NULL) mach_port_deallocate(mach_task_self(), task_);
}

bool MacDebugger::attach(Pid pid) {
    pid_ = pid;

    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task_);
    if (kr != KERN_SUCCESS) {
        std::cerr << "[macOS] task_for_pid failed: " << mach_error_string(kr) << "
";
        std::cerr << "  → Run with sudo for full access, or sign with get-task-allow entitlement
";
        std::cerr << "  → Falling back to limited static analysis...
";
        task_    = TASK_NULL;
        attached_ = false;
        // Still valid for static analysis
        return true;
    }

    attached_ = true;
    std::cout << "[macOS] Mach task acquired for PID " << pid << "
";
    return true;
}

bool MacDebugger::attach_by_name(const std::string& name) {
    // List all PIDs
    int n = proc_listallpids(nullptr, 0);
    if (n <= 0) { std::cerr << "[macOS] proc_listallpids failed
"; return false; }

    std::vector<pid_t> pids(n);
    n = proc_listallpids(pids.data(), n * sizeof(pid_t));

    for (int i = 0; i < n; i++) {
        char pathbuf[PROC_PIDPATHINFO_MAXSIZE] = {};
        proc_pidpath(pids[i], pathbuf, sizeof(pathbuf));
        std::string full = pathbuf;
        // basename
        auto slash = full.rfind('/');
        std::string base = (slash != std::string::npos) ? full.substr(slash + 1) : full;

        if (base == name || base.find(name) == 0) {
            std::cout << "[macOS] Found \"" << name << "\" → PID " << pids[i] << "
";
            return attach(static_cast<Pid>(pids[i]));
        }
    }
    std::cerr << "[macOS] Process \"" << name << "\" not found
";
    return false;
}

void MacDebugger::detach() {
    if (task_ != TASK_NULL) {
        mach_port_deallocate(mach_task_self(), task_);
        task_ = TASK_NULL;
    }
    attached_ = false;
    std::cout << "[macOS] Detached from PID " << pid_ << "
";
}

bool MacDebugger::is_attached()  const { return attached_; }
bool MacDebugger::is_elevated()  const { return elevated_; }

std::string MacDebugger::exe_path_for(Pid pid) const {
    char buf[PROC_PIDPATHINFO_MAXSIZE] = {};
    proc_pidpath(pid, buf, sizeof(buf));
    return buf;
}

Bytes MacDebugger::read_memory(Addr addr, size_t len) {
    if (task_ == TASK_NULL) return {};
    Bytes buf(len, 0);
    mach_vm_size_t out_size = len;
    kern_return_t kr = mach_vm_read_overwrite(
        task_,
        static_cast<mach_vm_address_t>(addr),
        static_cast<mach_vm_size_t>(len),
        reinterpret_cast<mach_vm_address_t>(buf.data()),
        &out_size
    );
    if (kr != KERN_SUCCESS) {
        std::cerr << "[macOS] mach_vm_read_overwrite: " << mach_error_string(kr) << "
";
        return {};
    }
    buf.resize(out_size);
    return buf;
}

std::vector<MemoryRegion> MacDebugger::memory_map() {
    std::vector<MemoryRegion> regions;
    if (task_ == TASK_NULL) return regions;

    mach_vm_address_t addr = 0;
    mach_vm_size_t    size = 0;
    uint32_t          depth = 1;

    while (true) {
        vm_region_submap_info_data_64_t info{};
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;

        kern_return_t kr = mach_vm_region_recurse(
            task_, &addr, &size, &depth,
            reinterpret_cast<vm_region_recurse_info_t>(&info), &count
        );
        if (kr != KERN_SUCCESS) break;

        if (info.is_submap) {
            depth++;
        } else {
            MemoryRegion r;
            r.start = addr;
            r.end   = addr + size;

            if (info.protection & VM_PROT_READ)    r.perms += "r";
            if (info.protection & VM_PROT_WRITE)   r.perms += "w";
            if (info.protection & VM_PROT_EXECUTE) r.perms += "x";
            if (r.perms.empty()) r.perms = "---";

            // Try to get filename
            char pathbuf[PATH_MAX] = {};
            proc_regionfilename(pid_, addr, pathbuf, sizeof(pathbuf));
            r.label = pathbuf[0] ? pathbuf : "[anon]";

            regions.push_back(r);
            addr += size;
            depth = 1;
        }
    }
    return regions;
}

RegisterSet MacDebugger::read_registers() {
    RegisterSet rs;
    if (task_ == TASK_NULL || !attached_) return rs;

    // Get thread list
    thread_act_array_t threads;
    mach_msg_type_number_t thread_count;
    if (task_threads(task_, &threads, &thread_count) != KERN_SUCCESS) return rs;
    if (thread_count == 0) return rs;

    thread_act_t thread = threads[0]; // First thread

#ifdef __x86_64__
    x86_thread_state64_t state{};
    mach_msg_type_number_t count = x86_THREAD_STATE64_COUNT;
    if (thread_get_state(thread, x86_THREAD_STATE64,
                         reinterpret_cast<thread_state_t>(&state), &count)
        == KERN_SUCCESS) {
        rs.rip = state.__rip;
        rs.rsp = state.__rsp;
        rs.rbp = state.__rbp;
        rs.gpr["rax"] = state.__rax;
        rs.gpr["rbx"] = state.__rbx;
        rs.gpr["rcx"] = state.__rcx;
        rs.gpr["rdx"] = state.__rdx;
        rs.gpr["rsi"] = state.__rsi;
        rs.gpr["rdi"] = state.__rdi;
        rs.gpr["r8"]  = state.__r8;
        rs.gpr["r9"]  = state.__r9;
        rs.gpr["r10"] = state.__r10;
        rs.gpr["r11"] = state.__r11;
        rs.gpr["r12"] = state.__r12;
        rs.gpr["r13"] = state.__r13;
        rs.gpr["r14"] = state.__r14;
        rs.gpr["r15"] = state.__r15;
    }
#elif defined(__aarch64__)
    arm_thread_state64_t state{};
    mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
    if (thread_get_state(thread, ARM_THREAD_STATE64,
                         reinterpret_cast<thread_state_t>(&state), &count)
        == KERN_SUCCESS) {
        rs.rip = arm_thread_state64_get_pc(state);
        rs.rsp = arm_thread_state64_get_sp(state);
        rs.rbp = arm_thread_state64_get_fp(state);
        for (int i = 0; i < 29; i++)
            rs.gpr["x" + std::to_string(i)] = state.__x[i];
    }
#endif

    // Release thread list
    vm_deallocate(mach_task_self(),
                  reinterpret_cast<vm_address_t>(threads),
                  thread_count * sizeof(thread_act_t));
    return rs;
}

ProcessSnapshot MacDebugger::snapshot() {
    ProcessSnapshot snap;
    snap.pid      = pid_;
    snap.elevated = elevated_;
    snap.attached = attached_;
    snap.exe_path = exe_path_for(pid_);

    // Process name: basename of exe_path
    auto slash = snap.exe_path.rfind('/');
    snap.name = (slash != std::string::npos)
                ? snap.exe_path.substr(slash + 1)
                : snap.exe_path;

    // Binary format
    if (!snap.exe_path.empty()) {
        std::ifstream ef(snap.exe_path, std::ios::binary);
        if (ef) {
            Bytes hdr(16, 0);
            ef.read(reinterpret_cast<char*>(hdr.data()), 16);
            snap.format = detect_format(hdr);
            switch (snap.format) {
                case BinaryFormat::ELF:   snap.sections = parse_elf  (snap.exe_path); break;
                case BinaryFormat::PE:    snap.sections = parse_pe   (snap.exe_path); break;
                case BinaryFormat::MACHO: snap.sections = parse_macho(snap.exe_path); break;
                default: break;
            }
        }
    }

    snap.maps = memory_map();
    if (attached_ && task_ != TASK_NULL)
        snap.regs = read_registers();
    return snap;
}

ComprehensiveInfo MacDebugger::comprehensive_info(
    const Config& cfg, const ProcessSnapshot& snap)
{
    ComprehensiveInfo ci;
    ci.pid      = pid_;
    ci.name     = snap.name;
    ci.exe_path = snap.exe_path;

    {
        // Use proc_pidpath already done; for cmdline use sysctl KERN_PROCARGS2
        int mib[3] = { CTL_KERN, KERN_PROCARGS2, (int)pid_ };
        size_t argmax = 0;
        sysctl(mib, 3, nullptr, &argmax, nullptr, 0);
        if (argmax) {
            std::vector<char> args(argmax, 0);
            if (sysctl(mib, 3, args.data(), &argmax, nullptr, 0) == 0) {
                int argc = 0;
                memcpy(&argc, args.data(), sizeof(argc));
                const char* p = args.data() + sizeof(argc);
                // skip exe path
                while (p < args.data()+argmax && *p) p++;
                while (p < args.data()+argmax && !*p) p++;
                for (int i = 0; i < argc && p < args.data()+argmax; i++) {
                    ci.cmdline.push_back(p);
                    while (p < args.data()+argmax && *p) p++;
                    p++;
                }
                // environment follows
                while (p < args.data()+argmax && *p) {
                    ci.environ_vars.push_back(p);
                    while (p < args.data()+argmax && *p) p++;
                    p++;
                }
            }
        }
    }

    {
        struct proc_vnodepathinfo vpi{};
        if (proc_pidinfo(pid_, PROC_PIDVNODEPATHINFO, 0, &vpi, sizeof(vpi)) > 0)
            ci.cwd = vpi.pvi_cdir.vip_path;
    }

    {
        std::set<std::string> seen;
        for (auto& r : snap.maps) {
            if (r.label.empty() || r.label[0] != '/') continue;
            if (seen.count(r.label)) continue;
            seen.insert(r.label);
            LibInfo li; li.path = r.label; li.base = r.start; li.size = r.size();
            ci.libs.push_back(li);
        }
    }

    for (auto& r : snap.maps) {
        bool ex = r.perms.find('x') != std::string::npos;
        bool wr = r.perms.find('w') != std::string::npos;
        if      (r.label=="[heap]")   ci.mem.heap_bytes  += r.size();
        else if (r.label=="[stack]")  ci.mem.stack_bytes += r.size();
        else if (ex)                  ci.mem.code_bytes  += r.size();
        else if (wr)                  ci.mem.data_bytes  += r.size();
        else                          ci.mem.shared_bytes+= r.size();
        ci.mem.vsz_bytes += r.size();
    }

    int found = 0, min_len = cfg.min_string_len;
    for (auto& sec : snap.sections) {
        if (found >= cfg.max_strings || sec.is_exec || sec.size == 0) continue;
        Bytes data = read_memory(sec.vaddr, std::min<uint64_t>(sec.size, 65536));
        if (data.empty()) continue;
        std::string run; Addr run_addr = sec.vaddr;
        for (size_t i = 0; i <= data.size(); i++) {
            uint8_t c = (i < data.size()) ? data[i] : 0;
            if (c >= 0x20 && c < 0x7f) { if(run.empty()) run_addr=sec.vaddr+i; run+=(char)c; }
            else {
                if ((int)run.size() >= min_len) {
                    ci.strings.push_back({run_addr, sec.name, run.substr(0,200)});
                    if (++found >= cfg.max_strings) break;
                }
                run.clear();
            }
        }
    }

    return ci;
}

std::unique_ptr<IDebugger> make_debugger() {
    return std::make_unique<MacDebugger>();
}

#endif // PROCDBG_MACOS
