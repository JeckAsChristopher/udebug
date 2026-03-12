cmake_minimum_required(VERSION 3.16)
project(procdbg VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ─── Output binary to build/
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# ─── Common sources
set(COMMON_SOURCES
    src/main.cpp
    src/elf_parser.cpp
    src/pe_parser.cpp
    src/macho_parser.cpp
    src/session.cpp
    src/output.cpp
)

# ─── Platform detection
if(WIN32)
    message(STATUS "[PROCDBG] Platform: Windows")
    set(PLATFORM_SOURCES
        src/windows/win_debugger.cpp
        src/windows/win_process.cpp
        src/windows/win_memory.cpp
    )
    set(PLATFORM_DEFINES PROCDBG_WINDOWS)
    set(PLATFORM_LIBS psapi dbghelp)

elseif(APPLE)
    message(STATUS "[PROCDBG] Platform: macOS")
    set(PLATFORM_SOURCES
        src/macos/mac_debugger.cpp
        src/macos/mac_process.cpp
        src/macos/mac_memory.cpp
    )
    set(PLATFORM_DEFINES PROCDBG_MACOS)
    set(PLATFORM_LIBS)
    # macOS needs special entitlements for task_for_pid
    # Works fully with sudo; limited without
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -framework Foundation")

elseif(UNIX)
    message(STATUS "[PROCDBG] Platform: Linux")
    set(PLATFORM_SOURCES
        src/linux/lin_debugger.cpp
        src/linux/lin_process.cpp
        src/linux/lin_memory.cpp
    )
    set(PLATFORM_DEFINES PROCDBG_LINUX)
    set(PLATFORM_LIBS)
endif()

# ─── Build target
add_executable(procdbg
    ${COMMON_SOURCES}
    ${PLATFORM_SOURCES}
)

target_include_directories(procdbg PRIVATE
    include/
    src/
)

target_compile_definitions(procdbg PRIVATE
    ${PLATFORM_DEFINES}
    PROCDBG_VERSION="1.0.0"
)

target_compile_options(procdbg PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra -O2>
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /O2>
)

if(PLATFORM_LIBS)
    target_link_libraries(procdbg PRIVATE ${PLATFORM_LIBS})
endif()

# ─── Install
install(TARGETS procdbg DESTINATION bin)
install(FILES procdbg.conf DESTINATION etc/procdbg)

message(STATUS "[procdbg] Build configured. Run: cmake --build .")
