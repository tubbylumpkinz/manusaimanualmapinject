#include "common.h"
#include <thread> // Add this for std::this_thread

// Implementation of utility functions
namespace Utils {
    // String conversion utilities
    std::wstring StringToWideString(const std::string& str) {
        if (str.empty()) {
            return std::wstring();
        }
        
        int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
        std::wstring wstr(size_needed, 0);
        MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstr[0], size_needed);
        return wstr;
    }
    
    std::string WideStringToString(const std::wstring& wstr) {
        if (wstr.empty()) {
            return std::string();
        }
        
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
        std::string str(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &str[0], size_needed, NULL, NULL);
        return str;
    }
    
    // Random number generation
    uint32_t GetRandomNumber(uint32_t min, uint32_t max) {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        std::uniform_int_distribution<uint32_t> dist(min, max);
        return dist(gen);
    }
    
    // Timing utilities
    void RandomSleep(uint32_t minMs, uint32_t maxMs) {
        uint32_t sleepTime = GetRandomNumber(minMs, maxMs);
        std::this_thread::sleep_for(std::chrono::milliseconds(sleepTime));
    }
    
    // Architecture detection
    bool IsProcess64Bit(ProcessHandle hProcess) {
        BOOL isWow64 = FALSE;
        
#ifdef ARCH_X64
        // On 64-bit Windows, check if the process is running under WOW64
        if (IsWow64Process(hProcess, &isWow64)) {
            // If it's not running under WOW64, it's a 64-bit process
            return !isWow64;
        }
#else
        // On 32-bit Windows, all processes are 32-bit
        return false;
#endif
        
        // Default to assuming same architecture as current process
#ifdef ARCH_X64
        return true;
#else
        return false;
#endif
    }
    
    // Memory utilities
    void SecureZeroMemory(void* ptr, size_t size) {
        volatile char* p = (volatile char*)ptr;
        while (size--) {
            *p++ = 0;
        }
    }
}
