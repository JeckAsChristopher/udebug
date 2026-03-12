// SPDX-License-Identifier: MIT
// Copyright (c) 2025 PROCDBG Contributors
//  PROCDBG — src/windows/win_debugger.cpp
//  Windows implementation:
//    - OpenProcess(PROCESS_ALL_ACCESS) — needs admin for other users
//    - DebugActiveProcess()             — attaches debug port
//    - ReadProcessMemory()              — read target memory
//    - VirtualQueryEx()                 — enumerate memory regions
//    - GetThreadContext()               — read CPU registers
//    - CreateToolhelp32Snapshot()       — find process by name

#ifdef PROCDBG_WINDOWS

#include "win_debugger.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <set>
#include <cmath>
#include <tlhelp32.h>
#include <psapi.h>
#include <string>

// Convert wide string to narrow
static std::string ws2s(const std::wstring& ws) {
    std::string s;
    s.reserve(ws.size());
    for (wchar_t c : ws) s += (c < 128) ? static_cast<char>(c) : '?';
    return s;
}

WinDebugger::WinDebugger() {
    elevated_ = check_elevated();
}

WinDebugger::~WinDebugger() {
    detach();
    if (hProc_) CloseHandle(hProc_);
}

bool WinDebugger::check_elevated() const {
    BOOL elevated = FALSE;
    HANDLE token;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION te{};
        DWORD size;
        GetTokenInformation(token, TokenElevation, &te, sizeof(te), &size);
        elevated = te.TokenIsElevated;
        CloseHandle(token);
    }
    return elevated == TRUE;
}

Pid WinDebugger::pid_from_name(const std::string& name) const {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);

    Pid found = 0;
    if (Process32First(snap, &pe)) {
        do {
            std::string exename = ws2s(pe.szExeFile);
            // Case-insensitive compare
            std::string lname = name, lexe = exename;
            std::transform(lname.begin(), lname.end(), lname.begin(), ::tolower);
            std::transform(lexe.begin(),  lexe.end(),  lexe.begin(),  ::tolower);
            if (lexe == lname || lexe == lname + ".exe") {
                found = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

bool WinDebugger::attach(Pid pid) {
    pid_ = pid;

    // Try with full access first
    DWORD access = PROCESS_ALL_ACCESS;
    hProc_ = OpenProcess(access, FALSE, pid);
    if (!hProc_) {
        // Fall back to read-only
        access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
        hProc_ = OpenProcess(access, FALSE, pid);
        if (!hProc_) {
            std::cerr << "[Windows] OpenProcess failed: " << GetLastError() << "
";
            std::cerr << "  → Run as Administrator for full access
";
            return false;
        }
        std::cout << "[Windows] Opened PID " << pid << " in read-only mode
";
        attached_ = false;
        return true;
    }

    // Attach debug port
    if (DebugActiveProcess(pid)) {
        // Don't kill on detach
        DebugSetProcessKillOnExit(FALSE);
        attached_ = true;
        std::cout << "[Windows] Debug-attached to PID " << pid << "
";
    } else {
        std::cerr << "[Windows] DebugActiveProcess failed: " << GetLastError()
                  << " — limited access (no register read)
";
        attached_ = false;
    }
    return true;
}

bool WinDebugger::attach_by_name(const std::string& name) {
    Pid pid = pid_from_name(name);
    if (!pid) {
        std::cerr << "[Windows] Process \"" << name << "\" not found
";
        return false;
    }
    std::cout << "[Windows] Found \"" << name << "\" → PID " << pid << "
";
    return attach(pid);
}

void WinDebugger::detach() {
    if (attached_ && pid_)
        DebugActiveProcessStop(pid_);
    attached_ = false;
    if (hProc_) {
        CloseHandle(hProc_);
        hProc_ = nullptr;
    }
}

bool WinDebugger::is_attached()  const { return attached_;  }
bool WinDebugger::is_elevated()  const { return elevated_;  }

std::string WinDebugger::exe_path_for(HANDLE hProc) const {
    wchar_t buf[MAX_PATH] = {};
    DWORD size = MAX_PATH;
    QueryFullProcessImageNameW(hProc, 0, buf, &size);
    return ws2s(buf);
}

Bytes WinDebugger::read_memory(Addr addr, size_t len) {
    if (!hProc_) return {};
    Bytes buf(len, 0);
    SIZE_T read = 0;
    BOOL ok = ReadProcessMemory(hProc_,
                                reinterpret_cast<LPCVOID>(addr),
                                buf.data(), len, &read);
    if (!ok || read == 0) {
        std::cerr << "[Windows] ReadProcessMemory failed: " << GetLastError() << "
";
        return {};
    }
    buf.resize(read);
    return buf;
}

std::vector<MemoryRegion> WinDebugger::memory_map() {
    std::vector<MemoryRegion> regions;
    if (!hProc_) return regions;

    MEMORY_BASIC_INFORMATION mbi{};
    Addr addr = 0;

    while (VirtualQueryEx(hProc_, reinterpret_cast<LPCVOID>(addr),
                           &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT) {
            MemoryRegion r;
            r.start = reinterpret_cast<Addr>(mbi.BaseAddress);
            r.end   = r.start + mbi.RegionSize;

            // Permissions
            DWORD prot = mbi.Protect & ~(PAGE_GUARD | PAGE_NOCACHE);
            if (prot == PAGE_READONLY          || prot == PAGE_EXECUTE_READ)         r.perms = "r--";
            else if (prot == PAGE_READWRITE    || prot == PAGE_EXECUTE_READWRITE)    r.perms = "rw-";
            else if (prot == PAGE_EXECUTE      || prot == PAGE_EXECUTE_READ)         r.perms = "r-x";
            else if (prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY) r.perms = "rwx";
            else r.perms = "---";

            // Type label
            if (mbi.Type == MEM_IMAGE) {
                wchar_t mod[MAX_PATH] = {};
                GetMappedFileNameW(hProc_, mbi.BaseAddress, mod, MAX_PATH);
                r.label = ws2s(mod);
                if (r.label.empty()) r.label = "[image]";
            } else if (mbi.Type == MEM_MAPPED) {
                r.label = "[mapped]";
            } else {
                r.label = "[private]";
            }

            regions.push_back(r);
        }
        addr = reinterpret_cast<Addr>(mbi.BaseAddress) + mbi.RegionSize;
        if (addr == 0) break; // wrap-around
    }
    return regions;
}

RegisterSet WinDebugger::read_registers() {
    RegisterSet rs;
    if (!attached_ || !hProc_) return rs;

    // Get first thread
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return rs;

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    DWORD first_tid = 0;

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid_) {
                first_tid = te.th32ThreadID;
                break;
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    if (!first_tid) return rs;

    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
                                FALSE, first_tid);
    if (!hThread) return rs;

    SuspendThread(hThread);
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_ALL;
    if (GetThreadContext(hThread, &ctx)) {
#ifdef _WIN64
        rs.rip = ctx.Rip;
        rs.rsp = ctx.Rsp;
        rs.rbp = ctx.Rbp;
        rs.gpr["rax"] = ctx.Rax;
        rs.gpr["rbx"] = ctx.Rbx;
        rs.gpr["rcx"] = ctx.Rcx;
        rs.gpr["rdx"] = ctx.Rdx;
        rs.gpr["rsi"] = ctx.Rsi;
        rs.gpr["rdi"] = ctx.Rdi;
        rs.gpr["r8"]  = ctx.R8;
        rs.gpr["r9"]  = ctx.R9;
        rs.gpr["r10"] = ctx.R10;
        rs.gpr["r11"] = ctx.R11;
        rs.gpr["r12"] = ctx.R12;
        rs.gpr["r13"] = ctx.R13;
        rs.gpr["r14"] = ctx.R14;
        rs.gpr["r15"] = ctx.R15;
        rs.gpr["eflags"] = ctx.EFlags;
#else
        rs.rip = ctx.Eip;
        rs.rsp = ctx.Esp;
        rs.rbp = ctx.Ebp;
        rs.gpr["eax"] = ctx.Eax;
        rs.gpr["ebx"] = ctx.Ebx;
        rs.gpr["ecx"] = ctx.Ecx;
        rs.gpr["edx"] = ctx.Edx;
        rs.gpr["esi"] = ctx.Esi;
        rs.gpr["edi"] = ctx.Edi;
        rs.gpr["eflags"] = ctx.EFlags;
#endif
    }
    ResumeThread(hThread);
    CloseHandle(hThread);
    return rs;
}

ProcessSnapshot WinDebugger::snapshot() {
    ProcessSnapshot snap;
    snap.pid      = pid_;
    snap.elevated = elevated_;
    snap.attached = attached_;

    if (hProc_) {
        snap.exe_path = exe_path_for(hProc_);
        auto slash = snap.exe_path.rfind('\');
        snap.name = (slash != std::string::npos)
                    ? snap.exe_path.substr(slash + 1)
                    : snap.exe_path;

        // Parse sections
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
    }

    snap.maps = memory_map();
    if (attached_) snap.regs = read_registers();
    return snap;
}

ComprehensiveInfo WinDebugger::comprehensive_info(
    const Config& cfg, const ProcessSnapshot& snap)
{
    ComprehensiveInfo ci;
    ci.pid      = pid_;
    ci.name     = snap.name;
    ci.exe_path = snap.exe_path;

    {
        PROCESS_MEMORY_COUNTERS_EX pmc{};
        pmc.cb = sizeof(pmc);
        if (GetProcessMemoryInfo(hProc_,
                reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))) {
            ci.mem.rss_bytes = pmc.WorkingSetSize;
            ci.mem.vsz_bytes = pmc.PrivateUsage;
        }

        FILETIME ct,et,kt,ut;
        if (GetProcessTimes(hProc_,&ct,&et,&kt,&ut)) {
            // 100-nanosecond units → ms
            ULARGE_INTEGER ui; ui.LowPart=ut.dwLowDateTime; ui.HighPart=ut.dwHighDateTime;
            ci.utime_ms = ui.QuadPart / 10000;
            ui.LowPart=kt.dwLowDateTime; ui.HighPart=kt.dwHighDateTime;
            ci.stime_ms = ui.QuadPart / 10000;
        }
    }

    {
        HANDLE snap_h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap_h != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te{}; te.dwSize = sizeof(te);
            if (Thread32First(snap_h, &te)) {
                do {
                    if (te.th32OwnerProcessID != pid_) continue;
                    ThreadInfo ti;
                    ti.tid = te.th32ThreadID;
                    HANDLE ht = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                    if (ht) {
                        ULONG_PTR cycles = 0;
                        QueryThreadCycleTime(ht, &cycles);
                        ti.cpu_time = cycles / 1000000; // rough ms
                        CloseHandle(ht);
                    }
                    ti.state = "?"; ti.state_name = "Unknown";
                    ci.threads.push_back(ti);
                } while (Thread32Next(snap_h, &te));
            }
            CloseHandle(snap_h);
        }
        ci.num_threads = (uint32_t)ci.threads.size();
    }

    {
        HANDLE msnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid_);
        if (msnap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W me{}; me.dwSize = sizeof(me);
            if (Module32FirstW(msnap, &me)) {
                do {
                    LibInfo li;
                    li.path = ws2s(me.szExePath);
                    li.base = reinterpret_cast<Addr>(me.modBaseAddr);
                    li.size = me.modBaseSize;
                    ci.libs.push_back(li);
                } while (Module32NextW(msnap, &me));
            }
            CloseHandle(msnap);
        }
    }

    for (auto& r : snap.maps) {
        bool ex = r.perms.find('x') != std::string::npos;
        bool wr = r.perms.find('w') != std::string::npos;
        if      (r.label=="[private]"&&wr) ci.mem.data_bytes  += r.size();
        else if (r.label=="[mapped]")      ci.mem.shared_bytes += r.size();
        else if (ex)                       ci.mem.code_bytes   += r.size();
        else                               ci.mem.anon_bytes   += r.size();
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
    return std::make_unique<WinDebugger>();
}

#endif // PROCDBG_WINDOWS
