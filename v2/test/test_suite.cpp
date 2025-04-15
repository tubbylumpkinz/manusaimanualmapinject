#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>

// Main injector controller class forward declaration
class InjectorController;

// Function to create and initialize the injector
InjectorController* CreateInjector();

// Function to test the injector
bool TestInjector(InjectorController* injector, const std::string& dllPath, const std::string& processName);

// Function to validate the injection
bool ValidateInjection(const std::string& processName);

int main(int argc, char* argv[]) {
    std::cout << "DLL Injector Test Suite" << std::endl;
    std::cout << "======================" << std::endl;
    
    // Check command line arguments
    if (argc < 3) {
        std::cout << "Usage: test_suite.exe <dll_path> <process_name>" << std::endl;
        std::cout << "Example: test_suite.exe test_dll.dll target_process.exe" << std::endl;
        return 1;
    }
    
    std::string dllPath = argv[1];
    std::string processName = argv[2];
    
    std::cout << "DLL Path: " << dllPath << std::endl;
    std::cout << "Target Process: " << processName << std::endl;
    
    // Create and initialize the injector
    std::cout << "Creating injector..." << std::endl;
    InjectorController* injector = CreateInjector();
    if (!injector) {
        std::cout << "Failed to create injector!" << std::endl;
        return 1;
    }
    
    // Test the injector
    std::cout << "Testing injector..." << std::endl;
    bool success = TestInjector(injector, dllPath, processName);
    
    if (success) {
        std::cout << "Injection test successful!" << std::endl;
        
        // Validate the injection
        std::cout << "Validating injection..." << std::endl;
        if (ValidateInjection(processName)) {
            std::cout << "Injection validation successful!" << std::endl;
        } else {
            std::cout << "Injection validation failed!" << std::endl;
            success = false;
        }
    } else {
        std::cout << "Injection test failed!" << std::endl;
    }
    
    // Clean up
    delete injector;
    
    return success ? 0 : 1;
}

// Mock implementation for testing
InjectorController* CreateInjector() {
    // This would be replaced with the actual injector implementation
    return new InjectorController();
}

bool TestInjector(InjectorController* injector, const std::string& dllPath, const std::string& processName) {
    // This would be replaced with the actual injector implementation
    return injector->InjectDll(dllPath, processName);
}

bool ValidateInjection(const std::string& processName) {
    // Check for the log files created by the test DLL
    char szTempPath[MAX_PATH] = { 0 };
    GetTempPathA(MAX_PATH, szTempPath);
    
    std::string injectionLogPath = std::string(szTempPath) + "injection_log.txt";
    std::string helloWorldLogPath = std::string(szTempPath) + "hello_world_log.txt";
    std::string addLogPath = std::string(szTempPath) + "add_log.txt";
    std::string messageBoxLogPath = std::string(szTempPath) + "messagebox_log.txt";
    
    // Check if the injection log file exists
    std::ifstream injectionLog(injectionLogPath);
    if (!injectionLog.is_open()) {
        std::cout << "Injection log file not found!" << std::endl;
        return false;
    }
    injectionLog.close();
    
    // Check if the function call log files exist
    std::ifstream helloWorldLog(helloWorldLogPath);
    std::ifstream addLog(addLogPath);
    std::ifstream messageBoxLog(messageBoxLogPath);
    
    bool helloWorldCalled = helloWorldLog.is_open();
    bool addCalled = addLog.is_open();
    bool messageBoxCalled = messageBoxLog.is_open();
    
    helloWorldLog.close();
    addLog.close();
    messageBoxLog.close();
    
    std::cout << "HelloWorld function called: " << (helloWorldCalled ? "Yes" : "No") << std::endl;
    std::cout << "Add function called: " << (addCalled ? "Yes" : "No") << std::endl;
    std::cout << "MessageBox function called: " << (messageBoxCalled ? "Yes" : "No") << std::endl;
    
    // At least one function should have been called
    return helloWorldCalled || addCalled || messageBoxCalled;
}

// Mock InjectorController implementation for testing
class InjectorController {
public:
    InjectorController() {}
    ~InjectorController() {}
    
    bool InjectDll(const std::string& dllPath, const std::string& processName) {
        // This would be replaced with the actual injector implementation
        // For testing purposes, we'll just load the DLL in the current process
        HMODULE hModule = LoadLibraryA(dllPath.c_str());
        return (hModule != NULL);
    }
    
    std::string GetLastErrorMessage() const {
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
};
