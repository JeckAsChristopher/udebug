// SPDX-License-Identifier: MIT
// Copyright (c) 2025 UDEBUG Contributors

#pragma once
#include "udebug.h"
#include <sys/types.h>

class LinuxDebugger : public IDebugger {
public:
    LinuxDebugger();
    ~LinuxDebugger() override;

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
    Pid  pid_      = 0;
    bool attached_ = false;
    bool elevated_ = false;

    std::string exe_path()  const;
    std::string proc_name() const;
};
