#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <chrono>
#include <memory>
#include <algorithm>
#include <functional>
#include <unordered_map>
#include <thread> // Add this for std::this_thread

// Architecture detection
#ifdef _WIN64
    #define ARCH_X64
#else
    #define ARCH_X86
#endif

// Error codes
enum class ErrorCode : uint32_t {
    SUCCESS = 0,
    PROCESS_NOT_FOUND = 1,
    PROCESS_ACCESS_DENIED = 2,
    MEMORY_ALLOCATION_FAILED = 3,
    MEMORY_WRITE_FAILED = 4,
    MEMORY_PROTECTION_FAILED = 5,
    THREAD_HIJACK_FAILED = 6,
    PE_PARSE_FAILED = 7,
    IMPORT_RESOLUTION_FAILED = 8,
    RELOCATION_FAILED = 9,
    EXECUTION_FAILED = 10,
    INVALID_ARCHITECTURE = 11,
    SYSCALL_FAILED = 12,
    SECTION_CREATION_FAILED = 13,
    INVALID_PARAMETER = 14,
    FILE_NOT_FOUND = 15,
    UNKNOWN_ERROR = 0xFFFFFFFF
};

// Structure to hold error information
struct ErrorInfo {
    ErrorCode code;
    std::string message;
    DWORD lastWinError;
};

// Forward declarations
class ProcessInterface;
class MemoryManager;
class SyscallManager;
class NameRandomizer;
class ErrorHandler;
class PEParser;
class ManualMapper;
class ImportResolver;
class ExecutionEngine;
class InjectorController;

// Typedefs for clarity
using ProcessId = DWORD;
using ThreadId = DWORD;
using ProcessHandle = HANDLE;
using ThreadHandle = HANDLE;
using MemoryAddress = PVOID;
using MemorySize = SIZE_T;
using SectionHandle = HANDLE;

// Constants
constexpr size_t MAX_PATH_LENGTH = 260;
constexpr size_t MIN_RANDOM_NAME_LENGTH = 8;
constexpr size_t MAX_RANDOM_NAME_LENGTH = 16;

// Utility functions
namespace Utils {
    // String conversion utilities
    std::wstring StringToWideString(const std::string& str);
    std::string WideStringToString(const std::wstring& wstr);
    
    // Random number generation
    uint32_t GetRandomNumber(uint32_t min, uint32_t max);
    
    // Timing utilities
    void RandomSleep(uint32_t minMs, uint32_t maxMs);
    
    // Architecture detection
    bool IsProcess64Bit(ProcessHandle hProcess);
    
    // Memory utilities
    void SecureZeroMemory(void* ptr, size_t size);
}
