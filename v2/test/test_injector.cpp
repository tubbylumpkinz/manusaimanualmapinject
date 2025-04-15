#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>

// Forward declarations
bool InjectDll(const std::string& dllPath, const std::string& processName);
std::string GetLastErrorMessage();

int main(int argc, char* argv[]) {
    std::cout << "DLL Injector Test Utility" << std::endl;
    std::cout << "=========================" << std::endl;
    
    // Check command line arguments
    if (argc < 3) {
        std::cout << "Usage: test_injector.exe <dll_path> <process_name>" << std::endl;
        std::cout << "Example: test_injector.exe test_dll.dll notepad.exe" << std::endl;
        return 1;
    }
    
    std::string dllPath = argv[1];
    std::string processName = argv[2];
    
    std::cout << "DLL Path: " << dllPath << std::endl;
    std::cout << "Target Process: " << processName << std::endl;
    
    // Inject the DLL
    std::cout << "Injecting DLL..." << std::endl;
    bool success = InjectDll(dllPath, processName);
    
    if (success) {
        std::cout << "DLL injection successful!" << std::endl;
    } else {
        std::cout << "DLL injection failed: " << GetLastErrorMessage() << std::endl;
        return 1;
    }
    
    // Test calling exported functions
    std::cout << "Testing exported functions..." << std::endl;
    
    // Get the module handle in the current process (for testing only)
    HMODULE hModule = LoadLibraryA(dllPath.c_str());
    if (hModule) {
        // Test HelloWorld function
        typedef void (*HelloWorld_t)();
        HelloWorld_t HelloWorld = (HelloWorld_t)GetProcAddress(hModule, "HelloWorld");
        if (HelloWorld) {
            std::cout << "Calling HelloWorld function..." << std::endl;
            HelloWorld();
        }
        
        // Test Add function
        typedef int (*Add_t)(int, int);
        Add_t Add = (Add_t)GetProcAddress(hModule, "Add");
        if (Add) {
            int result = Add(5, 7);
            std::cout << "Calling Add function: 5 + 7 = " << result << std::endl;
        }
        
        // Test MessageBoxTest function
        typedef void (*MessageBoxTest_t)();
        MessageBoxTest_t MessageBoxTest = (MessageBoxTest_t)GetProcAddress(hModule, "MessageBoxTest");
        if (MessageBoxTest) {
            std::cout << "Calling MessageBoxTest function..." << std::endl;
            MessageBoxTest();
        }
        
        // Free the library
        FreeLibrary(hModule);
    }
    
    std::cout << "Test completed." << std::endl;
    return 0;
}

// Mock implementation for testing
bool InjectDll(const std::string& dllPath, const std::string& processName) {
    // This would be replaced with the actual injector implementation
    // For testing purposes, we'll just load the DLL in the current process
    HMODULE hModule = LoadLibraryA(dllPath.c_str());
    return (hModule != NULL);
}

std::string GetLastErrorMessage() {
    // Get the error message from Windows
    DWORD error = GetLastError();
    if (error == 0) {
        return "No error";
    }
    
    LPSTR messageBuffer = nullptr;
    size_t size = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
    
    std::string message(messageBuffer, size);
    LocalFree(messageBuffer);
    
    return message;
}
