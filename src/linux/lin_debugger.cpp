// SPDX-License-Identifier: MIT
// Copyright (c) 2025 UDEBUG Contributors

#ifdef UDEBUG_LINUX

#include "lin_debugger.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <dirent.h>
#include <unistd.h>
#include <cstring>
#include <cerrno>
#include <ctime>
#include <cmath>
#include <set>
#include <algorithm>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <memory>

LinuxDebugger::LinuxDebugger() { elevated_ = (geteuid() == 0); }
LinuxDebugger::~LinuxDebugger() { if (attached_) detach(); }

bool LinuxDebugger::attach(Pid pid) {
    pid_ = pid;
    long r = ptrace(PTRACE_ATTACH, pid, nullptr, nullptr);
    if (r == -1) {
        std::cerr << "[Linux] ptrace ATTACH failed: " << strerror(errno) << "\n";
        std::cerr << "  Falling back to read-only /proc access.\n";
        attached_ = false;
        return (access(("/proc/" + std::to_string(pid)).c_str(), F_OK) == 0);
    }
    int status;
    waitpid(pid, &status, 0);
    attached_ = true;
    std::cout << "[Linux] ptrace attached to PID " << pid << "\n";
    return true;
}

bool LinuxDebugger::attach_by_name(const std::string& name) {
    DIR* dir = opendir("/proc");
    if (!dir) { std::cerr << "[Linux] Cannot open /proc\n"; return false; }

    Pid found = 0;
    struct dirent* ent;
    while ((ent = readdir(dir)) != nullptr) {
        std::string dname = ent->d_name;
        if (dname.find_first_not_of("0123456789") != std::string::npos) continue;
        Pid candidate = static_cast<Pid>(std::stoul(dname));

        std::ifstream cf("/proc/" + dname + "/comm");
        if (!cf) continue;
        std::string comm;
        std::getline(cf, comm);
        if (!comm.empty() && comm.back() == '\n') comm.pop_back();

        bool matched = (comm == name || comm.find(name) == 0);
        if (!matched) {
            std::ifstream cmd("/proc/" + dname + "/cmdline");
            std::string cl; std::getline(cmd, cl);
            auto pos = cl.find('\0');
            if (pos != std::string::npos) cl = cl.substr(0, pos);
            auto slash = cl.rfind('/');
            if (slash != std::string::npos) cl = cl.substr(slash + 1);
            matched = (cl == name || cl.find(name) == 0);
        }
        if (matched) { found = candidate; break; }
    }
    closedir(dir);

    if (!found) { std::cerr << "[Linux] Process \"" << name << "\" not found\n"; return false; }
    std::cout << "[Linux] Found \"" << name << "\" -> PID " << found << "\n";
    return attach(found);
}

void LinuxDebugger::detach() {
    if (attached_ && pid_) {
        ptrace(PTRACE_DETACH, pid_, nullptr, nullptr);
        std::cout << "[Linux] Detached from PID " << pid_ << "\n";
    }
    attached_ = false;
}

bool LinuxDebugger::is_attached()  const { return attached_; }
bool LinuxDebugger::is_elevated()  const { return elevated_; }

std::string LinuxDebugger::exe_path() const {
    char buf[4096] = {};
    std::string link = "/proc/" + std::to_string(pid_) + "/exe";
    ssize_t n = readlink(link.c_str(), buf, sizeof(buf) - 1);
    return (n > 0) ? std::string(buf, n) : "";
}

std::string LinuxDebugger::proc_name() const {
    std::ifstream f("/proc/" + std::to_string(pid_) + "/comm");
    if (!f) return "unknown";
    std::string s; std::getline(f, s);
    return s;
}

RegisterSet LinuxDebugger::read_registers() {
    RegisterSet rs;
    if (!attached_) return rs;
#if defined(__x86_64__)
    struct user_regs_struct regs{};
    if (ptrace(PTRACE_GETREGS, pid_, nullptr, &regs) == 0) {
        rs.rip = regs.rip; rs.rsp = regs.rsp; rs.rbp = regs.rbp;
        rs.gpr["rax"] = regs.rax; rs.gpr["rbx"] = regs.rbx;
        rs.gpr["rcx"] = regs.rcx; rs.gpr["rdx"] = regs.rdx;
        rs.gpr["rsi"] = regs.rsi; rs.gpr["rdi"] = regs.rdi;
        rs.gpr["r8"]  = regs.r8;  rs.gpr["r9"]  = regs.r9;
        rs.gpr["r10"] = regs.r10; rs.gpr["r11"] = regs.r11;
        rs.gpr["r12"] = regs.r12; rs.gpr["r13"] = regs.r13;
        rs.gpr["r14"] = regs.r14; rs.gpr["r15"] = regs.r15;
        rs.gpr["eflags"] = regs.eflags; rs.gpr["cs"] = regs.cs; rs.gpr["ss"] = regs.ss;
    }
#elif defined(__aarch64__)
    struct iovec iov;
    struct user_pt_regs uregs{};
    iov.iov_base = &uregs; iov.iov_len = sizeof(uregs);
    if (ptrace(PTRACE_GETREGSET, pid_, (void*)1, &iov) == 0) {
        rs.rip = uregs.pc; rs.rsp = uregs.sp; rs.rbp = uregs.regs[29];
        for (int i = 0; i < 30; i++)
            rs.gpr["x" + std::to_string(i)] = uregs.regs[i];
    }
#endif
    return rs;
}

std::vector<MemoryRegion> LinuxDebugger::memory_map() {
    std::vector<MemoryRegion> regions;
    std::ifstream f("/proc/" + std::to_string(pid_) + "/maps");
    if (!f) { std::cerr << "[Linux] Cannot read maps\n"; return regions; }

    std::string line;
    while (std::getline(f, line)) {
        MemoryRegion r;
        char perms[8] = {};
        char label[512] = {};
        uint64_t start, end;
        if (sscanf(line.c_str(), "%lx-%lx %7s %*s %*s %*s %511[^\n]",
                   &start, &end, perms, label) >= 3) {
            r.start = start; r.end = end; r.perms = perms;
            r.label = label[0] ? label : "[anon]";
            while (!r.label.empty() && r.label[0] == ' ') r.label = r.label.substr(1);
            regions.push_back(r);
        }
    }
    return regions;
}

Bytes LinuxDebugger::read_memory(Addr addr, size_t len) {
    Bytes buf(len, 0);
    struct iovec local  = { buf.data(), len };
    struct iovec remote = { reinterpret_cast<void*>(addr), len };
    ssize_t n = process_vm_readv(pid_, &local, 1, &remote, 1, 0);
    if (n > 0) { buf.resize(n); return buf; }

    std::string mem_path = "/proc/" + std::to_string(pid_) + "/mem";
    int fd = open(mem_path.c_str(), O_RDONLY);
    if (fd < 0) {
        std::cerr << "[Linux] Cannot open " << mem_path << ": " << strerror(errno) << "\n";
        return {};
    }
    ssize_t r = pread(fd, buf.data(), len, static_cast<off_t>(addr));
    close(fd);
    if (r <= 0) return {};
    buf.resize(r);
    return buf;
}

ProcessSnapshot LinuxDebugger::snapshot() {
    ProcessSnapshot snap;
    snap.pid      = pid_;
    snap.name     = proc_name();
    snap.exe_path = exe_path();
    snap.elevated = elevated_;
    snap.attached = attached_;

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
    if (attached_) snap.regs = read_registers();
    return snap;
}

static std::string read_proc_file(const std::string& path) {
    std::ifstream f(path);
    if (!f) return {};
    std::ostringstream ss; ss << f.rdbuf(); return ss.str();
}

static std::vector<std::string> split_str(const std::string& s, char delim) {
    std::vector<std::string> out;
    std::istringstream ss(s);
    std::string tok;
    while (std::getline(ss, tok, delim)) if (!tok.empty()) out.push_back(tok);
    return out;
}

static double shannon_entropy(const uint8_t* data, size_t len) {
    if (!len) return 0.0;
    uint64_t freq[256] = {};
    for (size_t i = 0; i < len; i++) freq[data[i]]++;
    double h = 0.0;
    for (int i = 0; i < 256; i++) {
        if (!freq[i]) continue;
        double p = static_cast<double>(freq[i]) / len;
        h -= p * std::log2(p);
    }
    return h;
}

static std::string hex_to_ipport(const std::string& hex) {
    if (hex.size() < 13) return hex;
    unsigned ip_raw = 0, port = 0;
    sscanf(hex.c_str(), "%X:%X", &ip_raw, &port);
    uint8_t a=ip_raw&0xFF, b=(ip_raw>>8)&0xFF, c=(ip_raw>>16)&0xFF, d=(ip_raw>>24)&0xFF;
    char buf[32]; snprintf(buf, sizeof(buf), "%u.%u.%u.%u:%u", a, b, c, d, port);
    return buf;
}

static const char* tcp_state(int s) {
    switch(s) {
        case 1: return "ESTABLISHED"; case 2: return "SYN_SENT";
        case 3: return "SYN_RECV";    case 4: return "FIN_WAIT1";
        case 5: return "FIN_WAIT2";   case 6: return "TIME_WAIT";
        case 7: return "CLOSE";       case 8: return "CLOSE_WAIT";
        case 9: return "LAST_ACK";   case 10: return "LISTEN";
        case 11: return "CLOSING";   default: return "UNKNOWN";
    }
}

static const char* signame(int n) {
    switch(n) {
        case 1:return"SIGHUP";  case 2:return"SIGINT";  case 3:return"SIGQUIT";
        case 4:return"SIGILL";  case 5:return"SIGTRAP"; case 6:return"SIGABRT";
        case 7:return"SIGBUS";  case 8:return"SIGFPE";  case 9:return"SIGKILL";
        case 10:return"SIGUSR1";case 11:return"SIGSEGV";case 12:return"SIGUSR2";
        case 13:return"SIGPIPE";case 14:return"SIGALRM";case 15:return"SIGTERM";
        case 16:return"SIGSTKFLT";case 17:return"SIGCHLD";case 18:return"SIGCONT";
        case 19:return"SIGSTOP";case 20:return"SIGTSTP";case 21:return"SIGTTIN";
        case 22:return"SIGTTOU";case 23:return"SIGURG"; case 24:return"SIGXCPU";
        case 25:return"SIGXFSZ";case 26:return"SIGVTALRM";case 27:return"SIGPROF";
        case 28:return"SIGWINCH";case 29:return"SIGIO"; case 30:return"SIGPWR";
        case 31:return"SIGSYS"; default: return "SIG???";
    }
}

ComprehensiveInfo LinuxDebugger::comprehensive_info(
    const Config& cfg, const ProcessSnapshot& snap)
{
    ComprehensiveInfo ci;
    ci.pid      = pid_;
    ci.name     = snap.name;
    ci.exe_path = snap.exe_path;
    std::string base = "/proc/" + std::to_string(pid_);

    {
        std::ifstream f(base + "/status");
        std::string line;
        while (std::getline(f, line)) {
            auto col = line.find(':');
            if (col == std::string::npos) continue;
            std::string k = line.substr(0, col);
            std::string v = line.substr(col + 1);
            while (!v.empty() && (v[0]==' '||v[0]=='\t')) v = v.substr(1);
            if      (k == "PPid")    ci.ppid = std::stoul(v);
            else if (k == "State")   ci.state = v;
            else if (k == "Uid")     ci.uid  = std::stoul(split_str(v,'\t')[0]);
            else if (k == "Gid")     ci.gid  = std::stoul(split_str(v,'\t')[0]);
            else if (k == "Threads") ci.num_threads = std::stoul(v);
            else if (k == "VmRSS")  { std::istringstream ss(v); uint64_t kb; ss>>kb; ci.mem.rss_bytes = kb*1024; }
            else if (k == "VmSize") { std::istringstream ss(v); uint64_t kb; ss>>kb; ci.mem.vsz_bytes = kb*1024; }
        }
    }

    {
        std::string stat = read_proc_file(base + "/stat");
        if (!stat.empty()) {
            auto rp = stat.rfind(')');
            if (rp != std::string::npos) {
                std::istringstream ss(stat.substr(rp + 2));
                std::string state_char;
                long long ppid2,pgrp,session,tty,tpgid,flags,minflt,cminflt,majflt,cmajflt;
                long long utime, stime;
                ss >> state_char >> ppid2 >> pgrp >> session >> tty >> tpgid
                   >> flags >> minflt >> cminflt >> majflt >> cmajflt >> utime >> stime;
                long long cutime, cstime, priority, nice2;
                ss >> cutime >> cstime >> priority >> nice2;
                ci.nice     = (int)nice2;
                ci.utime_ms = (utime * 1000) / sysconf(_SC_CLK_TCK);
                ci.stime_ms = (stime * 1000) / sysconf(_SC_CLK_TCK);
                long long dummy;
                for (int i = 0; i < 5; i++) ss >> dummy;
                long long starttime; ss >> starttime;
                uint64_t uptime_s = 0;
                { std::ifstream up("/proc/uptime"); double u; up >> u; uptime_s = (uint64_t)u; }
                uint64_t clk = sysconf(_SC_CLK_TCK);
                ci.start_time_s = (uint64_t)time(nullptr) - uptime_s + starttime / clk;
            }
        }
    }

    {
        std::string raw = read_proc_file(base + "/cmdline");
        std::string tok;
        for (char c : raw) {
            if (c == '\0') { if (!tok.empty()) ci.cmdline.push_back(tok); tok.clear(); }
            else tok += c;
        }
        if (!tok.empty()) ci.cmdline.push_back(tok);
    }

    {
        std::string raw = read_proc_file(base + "/environ");
        std::string tok;
        for (char c : raw) {
            if (c == '\0') { if (!tok.empty()) ci.environ_vars.push_back(tok); tok.clear(); }
            else tok += c;
        }
        if (!tok.empty()) ci.environ_vars.push_back(tok);
    }

    {
        char buf[4096] = {};
        ssize_t n = readlink((base + "/cwd").c_str(), buf, sizeof(buf)-1);
        if (n > 0) ci.cwd = std::string(buf, n);
    }

    {
        DIR* tdir = opendir((base + "/task").c_str());
        if (tdir) {
            struct dirent* td;
            while ((td = readdir(tdir)) != nullptr) {
                std::string dname = td->d_name;
                if (dname.find_first_not_of("0123456789") != std::string::npos) continue;
                ThreadInfo ti;
                ti.tid = std::stoul(dname);
                std::string tbase = base + "/task/" + dname;
                std::ifstream tf(tbase + "/status");
                std::string tline;
                while (std::getline(tf, tline)) {
                    auto tc = tline.find(':');
                    if (tc == std::string::npos) continue;
                    std::string tk = tline.substr(0, tc);
                    std::string tv = tline.substr(tc+1);
                    while (!tv.empty()&&(tv[0]==' '||tv[0]=='\t')) tv=tv.substr(1);
                    if (tk == "State") {
                        ti.state = tv.empty() ? "?" : std::string(1, tv[0]);
                        switch(tv[0]) {
                            case 'R': ti.state_name="Running";   break;
                            case 'S': ti.state_name="Sleeping";  break;
                            case 'D': ti.state_name="Disk wait"; break;
                            case 'Z': ti.state_name="Zombie";    break;
                            case 'T': ti.state_name="Stopped";   break;
                            case 'I': ti.state_name="Idle";      break;
                            default:  ti.state_name="Unknown";   break;
                        }
                    }
                }
                std::string tstat = read_proc_file(tbase + "/stat");
                if (!tstat.empty()) {
                    auto rp = tstat.rfind(')');
                    if (rp != std::string::npos) {
                        std::istringstream ss(tstat.substr(rp+2));
                        std::string sc; long long pp,pg,se,tt,tp,fl,mf,cmf,mj,cmj,ut,st;
                        ss>>sc>>pp>>pg>>se>>tt>>tp>>fl>>mf>>cmf>>mj>>cmj>>ut>>st;
                        ti.cpu_time = (ut+st)*1000/sysconf(_SC_CLK_TCK);
                    }
                }
                ci.threads.push_back(ti);
            }
            closedir(tdir);
        }
    }

    {
        DIR* fdir = opendir((base + "/fd").c_str());
        if (fdir) {
            struct dirent* fd_ent;
            while ((fd_ent = readdir(fdir)) != nullptr) {
                std::string dn = fd_ent->d_name;
                if (dn.find_first_not_of("0123456789") != std::string::npos) continue;
                FdInfo fi;
                fi.fd = std::stoi(dn);
                char buf[4096] = {};
                ssize_t n = readlink((base + "/fd/" + dn).c_str(), buf, sizeof(buf)-1);
                if (n > 0) {
                    fi.path = std::string(buf, n);
                    if      (fi.path.substr(0,6) == "socket")   fi.type = "socket";
                    else if (fi.path.substr(0,4) == "pipe")     fi.type = "pipe";
                    else if (fi.path.substr(0,8) == "anon_ino") fi.type = "anon";
                    else fi.type = "file";
                } else { fi.path = "(unreadable)"; fi.type = "unknown"; }
                ci.fds.push_back(fi);
            }
            closedir(fdir);
            std::sort(ci.fds.begin(), ci.fds.end(),
                      [](const FdInfo& a, const FdInfo& b){ return a.fd < b.fd; });
        }
    }

    {
        std::set<std::string> seen;
        for (auto& reg : snap.maps) {
            if (reg.label.empty() || reg.label[0] != '/') continue;
            if (reg.label.find(".so") == std::string::npos && reg.label != snap.exe_path) continue;
            if (seen.count(reg.label)) continue;
            seen.insert(reg.label);
            uint64_t total = 0; Addr base_addr = ~0ULL;
            for (auto& r2 : snap.maps) if (r2.label == reg.label) {
                total += r2.size();
                if (r2.start < base_addr) base_addr = r2.start;
            }
            ci.libs.push_back({reg.label, base_addr, total});
        }
    }

    for (auto& r : snap.maps) {
        bool ex  = r.perms.find('x') != std::string::npos;
        bool wr  = r.perms.find('w') != std::string::npos;
        bool shr = r.perms.find('s') != std::string::npos;
        std::string lbl = r.label;
        if      (lbl == "[heap]")                      ci.mem.heap_bytes  += r.size();
        else if (lbl == "[stack]" || lbl.find("[stack:") == 0) ci.mem.stack_bytes += r.size();
        else if (ex)                                   ci.mem.code_bytes  += r.size();
        else if (shr || (!wr && !lbl.empty() && lbl[0]=='/')) ci.mem.shared_bytes += r.size();
        else if (wr && lbl == "[anon]")                ci.mem.anon_bytes  += r.size();
        else if (wr)                                   ci.mem.data_bytes  += r.size();
    }

    {
        std::string status = read_proc_file(base + "/status");
        uint64_t sig_caught = 0, sig_ignored = 0, sig_blocked = 0;
        std::istringstream ss(status);
        std::string line;
        while (std::getline(ss, line)) {
            auto col = line.find(':');
            if (col == std::string::npos) continue;
            std::string k = line.substr(0, col);
            std::string v = line.substr(col+1);
            while (!v.empty()&&(v[0]==' '||v[0]=='\t')) v=v.substr(1);
            if      (k=="SigBlk") sig_blocked = strtoull(v.c_str(),nullptr,16);
            else if (k=="SigIgn") sig_ignored = strtoull(v.c_str(),nullptr,16);
            else if (k=="SigCgt") sig_caught  = strtoull(v.c_str(),nullptr,16);
        }
        for (int s = 1; s <= 31; s++) {
            uint64_t bit = 1ULL << (s-1);
            std::string disp =
                (sig_blocked & bit) ? "BLOCKED" :
                (sig_ignored & bit) ? "IGN"     :
                (sig_caught  & bit) ? "CAUGHT"  : "DFL";
            ci.signals.push_back({s, signame(s), disp});
        }
    }

    {
        std::ifstream f(base + "/limits");
        std::string line;
        std::getline(f, line);
        while (std::getline(f, line)) {
            if (line.size() < 26) continue;
            std::string name_col = line.substr(0, 25);
            while (!name_col.empty() && name_col.back()==' ') name_col.pop_back();
            std::istringstream rs(line.substr(25));
            std::string sv, hv, unit;
            rs >> sv >> hv >> unit;
            RLimit rl;
            rl.name = name_col;
            rl.soft = (sv == "unlimited") ? UINT64_MAX : strtoull(sv.c_str(),nullptr,10);
            rl.hard = (hv == "unlimited") ? UINT64_MAX : strtoull(hv.c_str(),nullptr,10);
            rl.unit = unit;
            ci.limits.push_back(rl);
        }
    }

    {
        auto parse_net = [&](const std::string& proto, const std::string& file) {
            std::ifstream f(base + "/net/" + file);
            if (!f) f.open("/proc/net/" + file);
            std::string line;
            std::getline(f, line);
            while (std::getline(f, line)) {
                std::istringstream ss(line);
                std::string idx, local, remote, state_hex, dummy;
                ss >> idx >> local >> remote >> state_hex;
                for (int i = 0; i < 4; i++) ss >> dummy;
                uint32_t inode_num = 0; ss >> inode_num;
                int state_n = strtol(state_hex.c_str(), nullptr, 16);
                NetConn nc;
                nc.proto       = proto;
                nc.local_addr  = hex_to_ipport(local);
                nc.remote_addr = hex_to_ipport(remote);
                nc.state       = (proto=="tcp"||proto=="tcp6") ? tcp_state(state_n) : "UDP";
                nc.inode       = inode_num;
                ci.net.push_back(nc);
            }
        };
        parse_net("tcp", "tcp"); parse_net("udp", "udp");
        parse_net("tcp6", "tcp6"); parse_net("udp6", "udp6");

        std::set<uint32_t> our_inodes;
        for (auto& fd : ci.fds) if (fd.type == "socket") {
            auto lb = fd.path.find('['), rb = fd.path.find(']');
            if (lb!=std::string::npos && rb!=std::string::npos)
                our_inodes.insert(std::stoul(fd.path.substr(lb+1, rb-lb-1)));
        }
        if (!our_inodes.empty()) {
            std::vector<NetConn> filtered;
            for (auto& nc : ci.net) if (our_inodes.count(nc.inode)) filtered.push_back(nc);
            ci.net = filtered;
        }
    }

    if (cfg.max_strings > 0) {
        int min_len = cfg.min_string_len, found = 0;
        for (auto& sec : snap.sections) {
            if (found >= cfg.max_strings || sec.is_exec || sec.size == 0) continue;
            Bytes data = read_memory(sec.vaddr, std::min<uint64_t>(sec.size, 65536));
            if (data.empty()) continue;
            std::string run; Addr run_addr = sec.vaddr;
            for (size_t i = 0; i <= data.size(); i++) {
                uint8_t c = (i < data.size()) ? data[i] : 0;
                if (c >= 0x20 && c < 0x7f && c != '\\') {
                    if (run.empty()) run_addr = sec.vaddr + i;
                    run += (char)c;
                } else {
                    if ((int)run.size() >= min_len) {
                        ci.strings.push_back({run_addr, sec.name, run.substr(0, 200)});
                        if (++found >= cfg.max_strings) break;
                    }
                    run.clear();
                }
            }
        }
    }

    for (auto& sec : snap.sections) {
        if (sec.size == 0) continue;
        Bytes data = read_memory(sec.vaddr, std::min<uint64_t>(sec.size, 65536));
        SectionEntropy se;
        se.name = sec.name;
        if (data.empty()) {
            se.entropy = 0.0; se.assessment = "(no memory access)";
        } else {
            se.entropy = shannon_entropy(data.data(), data.size());
            if      (se.entropy < 1.0) se.assessment = "almost empty or zero-fill";
            else if (se.entropy < 4.5) se.assessment = "normal text or data";
            else if (se.entropy < 6.5) se.assessment = "dense binary data";
            else if (se.entropy < 7.2) se.assessment = "possibly compressed";
            else                       se.assessment = "likely encrypted or packed";
        }
        ci.entropy.push_back(se);
    }

    return ci;
}

std::unique_ptr<IDebugger> make_debugger() { return std::make_unique<LinuxDebugger>(); }

#endif
