// SPDX-License-Identifier: MIT
// Copyright (c) 2025 UDEBUG Contributors

#include "udebug.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <cctype>

static std::string trim(std::string s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(),
        [](unsigned char c){ return !std::isspace(c); }));
    s.erase(std::find_if(s.rbegin(), s.rend(),
        [](unsigned char c){ return !std::isspace(c); }).base(), s.end());
    return s;
}

static bool parse_bool(const std::string& v) {
    std::string lv = v;
    std::transform(lv.begin(), lv.end(), lv.begin(), ::tolower);
    return lv == "true" || lv == "yes" || lv == "1" || lv == "on";
}

Config load_config(const std::string& path) {
    Config cfg;
    std::ifstream f(path);
    if (!f.is_open()) return cfg;

    std::string line;
    int lineno = 0;
    while (std::getline(f, line)) {
        ++lineno;
        line = trim(line);
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;

        auto eq = line.find('=');
        if (eq == std::string::npos) continue;

        std::string key = trim(line.substr(0, eq));
        std::string val = trim(line.substr(eq + 1));

        auto hash = val.find('#');
        if (hash != std::string::npos) val = trim(val.substr(0, hash));

        if      (key == "dump_bss")       cfg.dump_bss       = parse_bool(val);
        else if (key == "dump_registers") cfg.dump_registers = parse_bool(val);
        else if (key == "dump_maps")      cfg.dump_maps      = parse_bool(val);
        else if (key == "dump_stack")     cfg.dump_stack     = parse_bool(val);
        else if (key == "dump_heap")      cfg.dump_heap      = parse_bool(val);
        else if (key == "comprehensive")  cfg.comprehensive  = parse_bool(val);
        else if (key == "color_output")   cfg.color_output   = parse_bool(val);
        else if (key == "verbose")        cfg.verbose        = parse_bool(val);
        else if (key == "stack_depth")    cfg.stack_depth    = std::stoi(val);
        else if (key == "hex_width")      cfg.hex_width      = std::stoi(val);
        else if (key == "max_strings")    cfg.max_strings    = std::stoi(val);
        else if (key == "min_string_len") cfg.min_string_len = std::stoi(val);
        else if (key == "output_file")    cfg.output_file    = val;
        else
            std::cerr << "[udebug.conf:" << lineno << "] Unknown key: " << key << "\n";
    }
    return cfg;
}
