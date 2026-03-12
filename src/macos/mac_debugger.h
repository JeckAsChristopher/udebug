// SPDX-License-Identifier: MIT
// Copyright (c) 2025 PROCDBG Contributors

#pragma once
#include "procdbg.h"

#ifdef PROCDBG_MACOS
#include <mach/mach.h>

class MacDebugger : public IDebugger {
public:
    MacDebugger();
    ~MacDebugger() override;

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
    task_t task_     = TASK_NULL;
    bool   attached_ = false;
    bool   elevated_ = false;

    std::string exe_path_for(Pid pid) const;
};
#endif
