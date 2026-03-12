# UDEBUG - Ultimate Debugger

Cross-platform process debugger supporting ELF (Linux), PE/EXE (Windows), and Mach-O (macOS).
Works without root or Administrator access with reduced capability. Running with elevated privileges enables full memory reading, register snapshots, and string extraction.

---

## Build

Requirements: CMake 3.16 or later, a C++17 compiler (GCC 9+, Clang 10+, MSVC 2019+).

**Linux and macOS**
```
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

**Windows**
```
cmake -B build
cmake --build build --config Release
```

---

## Usage

```
udebug --attach <pid|name>    Attach to a running process by PID or name
udebug --pid    <pid>         Attach by numeric PID
udebug --name   <name>        Attach by process name
udebug --file   <binary>      Static parse only, no live attach
udebug --config <path>        Load an alternate config file
udebug --c                    Comprehensive mode (see below)
udebug --dump-stack           Dump stack memory at RSP
udebug --dump-heap            Dump heap memory regions
udebug --no-color             Disable color output
udebug --verbose              Verbose internal messages
udebug --help                 Show help
```

**Examples**
```
udebug --attach myapp
udebug --attach 1234
udebug --pid 5678 --dump-stack
udebug --pid 5678 --c
udebug --file ./program.elf
udebug --name nginx --c
sudo udebug --attach myapp --c
```

---

## Comprehensive Mode (--c)

Passing `--c` runs a deep analysis of the process and prints eleven additional sections beyond the default output.

```
udebug --pid 1234 --c
sudo udebug --name nginx --c
```

What is collected:

- **Process identity and runtime** - PID, PPID, executable path, working directory, full command line, UID/GID, user and kernel CPU time, nice value, thread count
- **Environment variables** - full KEY=VALUE table read from the process environment
- **Threads** - all thread IDs with state (Running, Sleeping, Zombie, etc.) and CPU time
- **Open file descriptors** - fd number, type (file, socket, pipe, anonymous), and resolved path
- **Loaded libraries** - every shared library with its base address and total mapped size
- **Memory breakdown** - virtual size, resident size, code, data, heap, stack, shared, and anonymous regions in human-readable sizes
- **Signal disposition** - all 31 signals shown as DFL, IGN, CAUGHT, or BLOCKED
- **Resource limits** - soft and hard values for every limit (equivalent to ulimit -a)
- **Network connections** - TCP and UDP sockets filtered to this process, with local address, remote address, and state
- **Section entropy analysis** - Shannon entropy per binary section; sections above 7.2 bits are flagged as likely encrypted or packed
- **Extracted strings** - ASCII strings of configurable minimum length extracted from readable memory sections

---

## Expected Output

Default attach output:

```
UDEBUG v1.0.0 - Ultimate Debugger  [ELF / PE / Mach-O]

== PROCESS INFO ===========================================
  PID:              1234
  Name:             myapp
  Executable:       /usr/bin/myapp
  Format:           ELF (Linux/Unix)
  Elevated:         YES - full access
  Attached:         YES

== REGISTERS ==============================================
  RIP/PC:  0x00007f4a3b001234  (140275483652660)
  RSP:     0x00007ffee1234560  (140732900000096)
  RBP:     0x00007ffee1234580  (140732900000128)
  rax:     0x0000000000000000  (0)
  ...

== MEMORY MAP =============================================
  Start               End                 Perms   Size      Label
  -----------------------------------------------------------------------
  0x55f4077c1000      0x55f4077c5000      r--p    16 KB     /usr/bin/myapp
  0x55f4077c5000      0x55f4077da000      r-xp    84 KB     /usr/bin/myapp
  0x55f407805000      0x55f407826000      rw-p    132 KB    [heap]
  0x7eb63854d000      0x7eb638d4d000      rw-p    8 MB      [stack]
  ...

== SECTIONS ===============================================
  Name              VirtAddr          Size          Flags
  ----------------------------------------------------------
  .text             0x401000          65536         X
  .rodata           0x411000          4096
  .data             0x412000          2048          W
  .bss              0x413000          1024          W BSS

== BSS SECTION: .bss ======================================
  vaddr = 0x413000  size = 1024 bytes

  Contains runtime data.
  0x000000413000  00 00 00 00 12 34 56 78  de ad be ef 00 00 00 00  |.....4Vx........|
  ...
```

Comprehensive mode (`--c`) appends after the standard sections:

```
COMPREHENSIVE ANALYSIS
--------------------------------------------------
== PROCESS IDENTITY AND RUNTIME ===================
  PID:                  1234
  PPID:                 1
  Name:                 myapp
  CWD:                  /home/user/projects
  User CPU:             1.234s
  Kernel CPU:           0.056s
  Threads:              4
  Cmdline:              ./myapp --port 8080

== ENVIRONMENT VARIABLES (18) =====================
  HOME                          /home/user
  PATH                          /usr/local/bin:/usr/bin:/bin
  ...

== THREADS (4) ====================================
  TID       State     State Name      CPU Time
  ------------------------------------------------
  1234      S         Sleeping        1.290s
  1235      S         Sleeping        0.001s
  1236      R         Running         0.044s
  1237      S         Sleeping        0.000s

== OPEN FILE DESCRIPTORS (12) =====================
  FD    Type      Path
  ------------------------------------------------------------
  0     file      /dev/null
  1     pipe      pipe:[12345]
  4     socket    socket:[67890]
  5     file      /var/log/myapp.log
  ...

== NETWORK CONNECTIONS (2) ========================
  Proto   Local                     Remote                    State
  -----------------------------------------------------------------------
  tcp     0.0.0.0:8080              0.0.0.0:0                 LISTEN
  tcp     192.168.1.5:8080          10.0.0.22:54312           ESTABLISHED

== SECTION ENTROPY ANALYSIS =======================
  Section             Entropy   Assessment
  ------------------------------------------------------------
  .text               5.821     dense binary data
  .rodata             4.102     normal text or data
  .data               2.340     normal text or data
  .bss                0.000     almost empty or zero-fill

== EXTRACTED STRINGS (35) =========================
  Address         Section       String
  -----------------------------------------------------------------------
  0x411020        .rodata       /var/log/myapp.log
  0x411034        .rodata       listening on port %d
  0x411050        .rodata       connection accepted from %s
  ...
```

---

## Configuration

The config file `udebug.conf` is searched in order:

1. `./udebug.conf` alongside the binary
2. `~/.config/udebug/udebug.conf`
3. `/etc/udebug/udebug.conf`
4. Path given with `--config`

Available options:

```ini
dump_bss       = true    # Hex dump of BSS sections
dump_registers = true    # CPU register snapshot
dump_maps      = true    # Memory map table
dump_stack     = false   # Stack memory at RSP
dump_heap      = false   # Heap memory regions
comprehensive  = false   # Always run --c mode
color_output   = true    # ANSI color output
verbose        = false   # Internal debug messages
stack_depth    = 16      # Rows of stack to show
hex_width      = 16      # Bytes per hex row
max_strings    = 80      # Maximum extracted strings (0 to disable)
min_string_len = 5       # Minimum printable character run length
output_file    =         # Empty means stdout
```

---

## Privilege Summary

| Feature | Without sudo | With sudo |
|---------|-------------|-----------|
| Parse binary sections | Yes | Yes |
| Read memory maps | Yes (own processes) | Yes (any process) |
| Read BSS and data sections | Own processes only | Any process |
| CPU registers | No | Yes |
| Stack and heap dump | No | Yes |
| String extraction | Limited | Full |
| Attach to system processes | No | Yes |

---

## License

MIT - see LICENSE file.
