#include <Windows.h>
#include <iostream>
#include <string>

// Include the fixed header files
#include "common.h"
#include "utility.h"
#include "process_memory.h"
#include "manual_mapping.h"

// Forward declaration of InjectorController
class InjectorController {
public:
    InjectorController();
    ~InjectorController();
    
    // Initialize the injector
    bool Initialize();
    
    // Inject a DLL into a process
    bool InjectDll(const std::string& dllPath, const std::string& processName);
    
    // Generate a random injector name
    std::string GenerateRandomInjectorName() const;
    
    // Get the last error message
    std::string GetLastErrorMessage() const;
    
private:
    ErrorHandler* m_errorHandler;
    NameRandomizer* m_nameRandomizer;
    ProcessInterface* m_processInterface;
    MemoryManager* m_memoryManager;
    SyscallManager* m_syscallManager;
    PEParser* m_peParser;
    ManualMapper* m_manualMapper;
    ExecutionEngine* m_executionEngine;
    
    // Internal helper methods
    bool ValidateParameters(const std::string& dllPath, const std::string& processName);
    bool CheckArchitectureCompatibility();
};

// Main entry point
int main(int argc, char* argv[]) {
    std::cout << "DLL Injector for Windows 11" << std::endl;
    std::cout << "=========================" << std::endl;
    
    // Check command line arguments
    if (argc < 3) {
        std::cout << "Usage: DLLInjector.exe <dll_path> <process_name>" << std::endl;
        std::cout << "Example: DLLInjector.exe C:\\path\\to\\your.dll notepad.exe" << std::endl;
        return 1;
    }
    
    std::string dllPath = argv[1];
    std::string processName = argv[2];
    
    std::cout << "DLL Path: " << dllPath << std::endl;
    std::cout << "Target Process: " << processName << std::endl;
    
    // Create and initialize the injector
    std::cout << "Creating injector..." << std::endl;
    InjectorController* injector = new InjectorController();
    if (!injector->Initialize()) {
        std::cout << "Failed to initialize injector: " << injector->GetLastErrorMessage() << std::endl;
        delete injector;
        return 1;
    }
    
    // Inject the DLL
    std::cout << "Injecting DLL..." << std::endl;
    bool success = injector->InjectDll(dllPath, processName);
    
    if (success) {
        std::cout << "DLL injection successful!" << std::endl;
    } else {
        std::cout << "DLL injection failed: " << injector->GetLastErrorMessage() << std::endl;
        delete injector;
        return 1;
    }
    
    // Clean up
    delete injector;
    
    return 0;
}
