// SPDX-License-Identifier: MIT
// Copyright (c) 2025 UDEBUG Contributors

#pragma once
#include "udebug.h"

#ifdef UDEBUG_WINDOWS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

class WinDebugger : public IDebugger {
public:
    WinDebugger();
    ~WinDebugger() override;

    bool  attach(Pid pid)                              override;
    bool  attach_by_name(const std::string& name)      override;
    void  detach()                                     override;
    bool  is_attached()        const                   override;
    bool  is_elevated()        const                   override;

    ProcessSnapshot           snapshot()               override;
    Bytes                     read_memory(Addr a, size_t n) override;
    RegisterSet               read_registers()         override;
    std::vector<MemoryRegion> memory_map()             override;
    ComprehensiveInfo         comprehensive_info(const Config& cfg,
                                  const ProcessSnapshot& snap) override;
private:
    Pid    pid_      = 0;
    HANDLE hProc_    = nullptr;
    bool   attached_ = false;
    bool   elevated_ = false;

    std::string exe_path_for(HANDLE hProc) const;
    bool        check_elevated()            const;
    Pid         pid_from_name(const std::string& name) const;
};
#endif
