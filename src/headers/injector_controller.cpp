#include "common.h"
#include "utility.h"
#include "process_memory.h"
#include "manual_mapping.h"
#include <random>
#include <chrono>
#include <sstream>
#include <iomanip>

// Main injector controller class
class InjectorController {
public:
    InjectorController();
    ~InjectorController();

    // Initialize the injector
    bool Initialize();
    
    // Inject a DLL into a process
    bool InjectDll(const std::string& dllPath, const std::string& processName);
    
    // Get the last error message
    std::string GetLastErrorMessage() const;
    
    // Generate a random injector name
    std::string GenerateRandomInjectorName() const;
    
    // Generate a random DLL name
    std::string GenerateRandomDllName(const std::string& originalDllPath) const;

private:
    ErrorHandler* m_errorHandler;
    NameRandomizer* m_nameRandomizer;
    ProcessInterface* m_processInterface;
    SyscallManager* m_syscallManager;
    MemoryManager* m_memoryManager;
    PEParser* m_peParser;
    ManualMapper* m_manualMapper;
    ExecutionEngine* m_executionEngine;
    
    // Internal helper methods
    bool CopyDllToRandomLocation(const std::string& dllPath, std::string& randomDllPath);
    void CleanupRandomDll(const std::string& randomDllPath);
    void ApplyAntiDetectionMeasures();
    void CleanupResources();
};

// Implementation
InjectorController::InjectorController()
    : m_errorHandler(nullptr),
      m_nameRandomizer(nullptr),
      m_processInterface(nullptr),
      m_syscallManager(nullptr),
      m_memoryManager(nullptr),
      m_peParser(nullptr),
      m_manualMapper(nullptr),
      m_executionEngine(nullptr) {
}

InjectorController::~InjectorController() {
    CleanupResources();
}

bool InjectorController::Initialize() {
    // Create components
    m_errorHandler = new ErrorHandler();
    m_nameRandomizer = new NameRandomizer();
    m_syscallManager = new SyscallManager(m_errorHandler);
    m_processInterface = new ProcessInterface(m_errorHandler, m_nameRandomizer, m_syscallManager);
    m_memoryManager = new MemoryManager(m_errorHandler, m_nameRandomizer, m_processInterface, m_syscallManager);
    m_peParser = new PEParser(m_errorHandler, m_nameRandomizer);
    m_manualMapper = new ManualMapper(m_errorHandler, m_nameRandomizer, m_processInterface, m_memoryManager);
    m_executionEngine = new ExecutionEngine(m_errorHandler, m_nameRandomizer, m_processInterface, m_memoryManager);
    
    // Initialize syscall manager
    if (!m_syscallManager->Initialize()) {
        return false;
    }
    
    // Apply anti-detection measures
    ApplyAntiDetectionMeasures();
    
    return true;
}

bool InjectorController::InjectDll(const std::string& dllPath, const std::string& processName) {
    if (dllPath.empty() || processName.empty()) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER, 
            "DLL path or process name is empty");
        return false;
    }
    
    // Apply random timing to avoid detection patterns
    m_nameRandomizer->ApplyRandomTiming(5, 20);
    
    // Copy the DLL to a random location
    std::string randomDllPath;
    if (!CopyDllToRandomLocation(dllPath, randomDllPath)) {
        return false;
    }
    
    // Find the target process
    ProcessId processId = m_processInterface->FindProcessByName(processName);
    if (processId == 0) {
        CleanupRandomDll(randomDllPath);
        return false;
    }
    
    // Open the process
    if (!m_processInterface->OpenProcess(processId)) {
        CleanupRandomDll(randomDllPath);
        return false;
    }
    
    // Load the DLL
    if (!m_peParser->LoadDll(randomDllPath)) {
        CleanupRandomDll(randomDllPath);
        return false;
    }
    
    // Map the DLL into the target process
    MemoryAddress baseAddress = m_manualMapper->MapDll(m_peParser);
    if (!baseAddress) {
        CleanupRandomDll(randomDllPath);
        return false;
    }
    
    // Execute the DLL's entry point
    DWORD entryPointRVA = m_peParser->GetEntryPointRVA();
    if (entryPointRVA != 0) {
        if (!m_executionEngine->ExecuteDllMain(baseAddress, entryPointRVA)) {
            CleanupRandomDll(randomDllPath);
            return false;
        }
    }
    
    // Clean up the random DLL
    CleanupRandomDll(randomDllPath);
    
    return true;
}

std::string InjectorController::GetLastErrorMessage() const {
    if (!m_errorHandler) {
        return "Error handler not initialized";
    }
    
    return m_errorHandler->FormatErrorMessage();
}

std::string InjectorController::GenerateRandomInjectorName() const {
    if (!m_nameRandomizer) {
        return "injector";
    }
    
    return m_nameRandomizer->GenerateRandomFileName("exe");
}

std::string InjectorController::GenerateRandomDllName(const std::string& originalDllPath) const {
    if (!m_nameRandomizer) {
        return originalDllPath;
    }
    
    // Extract the extension from the original path
    size_t dotPos = originalDllPath.find_last_of('.');
    std::string extension = (dotPos != std::string::npos) ? 
        originalDllPath.substr(dotPos + 1) : "dll";
    
    return m_nameRandomizer->GenerateRandomFileName(extension);
}

bool InjectorController::CopyDllToRandomLocation(const std::string& dllPath, std::string& randomDllPath) {
    // Generate a random DLL name
    std::string randomName = GenerateRandomDllName(dllPath);
    
    // Get the temp directory
    char tempPath[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tempPath) == 0) {
        m_errorHandler->SetError(ErrorCode::FILE_NOT_FOUND, 
            "Failed to get temp directory", GetLastError());
        return false;
    }
    
    // Create the random DLL path
    randomDllPath = std::string(tempPath) + randomName;
    
    // Copy the DLL
    if (!CopyFileA(dllPath.c_str(), randomDllPath.c_str(), FALSE)) {
        m_errorHandler->SetError(ErrorCode::FILE_NOT_FOUND, 
            "Failed to copy DLL to random location", GetLastError());
        return false;
    }
    
    return true;
}

void InjectorController::CleanupRandomDll(const std::string& randomDllPath) {
    if (!randomDllPath.empty()) {
        // Apply random timing to avoid detection patterns
        m_nameRandomizer->ApplyRandomTiming(5, 20);
        
        // Delete the random DLL
        DeleteFileA(randomDllPath.c_str());
    }
}

void InjectorController::ApplyAntiDetectionMeasures() {
    // Apply random timing to avoid detection patterns
    m_nameRandomizer->ApplyRandomTiming(10, 50);
    
    // Additional anti-detection measures could be implemented here
    // For example:
    // - Check for debugging
    // - Check for virtualization
    // - Check for monitoring tools
    // - Implement timing checks
    
    // For now, we'll just add some random timing variations
    for (int i = 0; i < 5; i++) {
        if (Utils::GetRandomNumber(0, 10) > 5) {
            m_nameRandomizer->ApplyRandomTiming(1, 10);
        }
    }
}

void InjectorController::CleanupResources() {
    // Clean up components in reverse order of creation
    if (m_executionEngine) {
        delete m_executionEngine;
        m_executionEngine = nullptr;
    }
    
    if (m_manualMapper) {
        delete m_manualMapper;
        m_manualMapper = nullptr;
    }
    
    if (m_peParser) {
        delete m_peParser;
        m_peParser = nullptr;
    }
    
    if (m_memoryManager) {
        delete m_memoryManager;
        m_memoryManager = nullptr;
    }
    
    if (m_processInterface) {
        delete m_processInterface;
        m_processInterface = nullptr;
    }
    
    if (m_syscallManager) {
        delete m_syscallManager;
        m_syscallManager = nullptr;
    }
    
    if (m_nameRandomizer) {
        delete m_nameRandomizer;
        m_nameRandomizer = nullptr;
    }
    
    if (m_errorHandler) {
        delete m_errorHandler;
        m_errorHandler = nullptr;
    }
}
