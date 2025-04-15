#include "syscall_manager.h"

SyscallManager::SyscallManager(ErrorHandler* errorHandler) : m_errorHandler(errorHandler) {
    // Initialize function pointers to NULL
    m_NtOpenProcess = nullptr;
    m_NtCreateSection = nullptr;
    m_NtMapViewOfSection = nullptr;
    m_NtUnmapViewOfSection = nullptr;
    m_NtClose = nullptr;
    m_NtGetContextThread = nullptr;
    m_NtSetContextThread = nullptr;
    m_NtResumeThread = nullptr;
    m_NtSuspendThread = nullptr;
}

SyscallManager::~SyscallManager() {
    // Nothing to clean up
}

bool SyscallManager::Initialize() {
    return LoadNtApiFunctions();
}

bool SyscallManager::LoadNtApiFunctions() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        m_errorHandler->SetError(ErrorCode::SYSCALL_FAILED, "Failed to get handle to ntdll.dll", GetLastError());
        return false;
    }
    
    m_NtOpenProcess = (NtOpenProcess_t)GetProcAddress(ntdll, "NtOpenProcess");
    m_NtCreateSection = (NtCreateSection_t)GetProcAddress(ntdll, "NtCreateSection");
    m_NtMapViewOfSection = (NtMapViewOfSection_t)GetProcAddress(ntdll, "NtMapViewOfSection");
    m_NtUnmapViewOfSection = (NtUnmapViewOfSection_t)GetProcAddress(ntdll, "NtUnmapViewOfSection");
    m_NtClose = (NtClose_t)GetProcAddress(ntdll, "NtClose");
    m_NtGetContextThread = (NtGetContextThread_t)GetProcAddress(ntdll, "NtGetContextThread");
    m_NtSetContextThread = (NtSetContextThread_t)GetProcAddress(ntdll, "NtSetContextThread");
    m_NtResumeThread = (NtResumeThread_t)GetProcAddress(ntdll, "NtResumeThread");
    m_NtSuspendThread = (NtSuspendThread_t)GetProcAddress(ntdll, "NtSuspendThread");
    
    if (!m_NtOpenProcess || !m_NtCreateSection || !m_NtMapViewOfSection || 
        !m_NtUnmapViewOfSection || !m_NtClose || !m_NtGetContextThread || 
        !m_NtSetContextThread || !m_NtResumeThread || !m_NtSuspendThread) {
        m_errorHandler->SetError(ErrorCode::SYSCALL_FAILED, "Failed to get NT API function addresses", GetLastError());
        return false;
    }
    
    return true;
}

NTSTATUS SyscallManager::NtOpenProcess(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PCLIENT_ID ClientId OPTIONAL) {
    if (!m_NtOpenProcess) {
        m_errorHandler->SetError(ErrorCode::SYSCALL_FAILED, "NtOpenProcess function not initialized");
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    
    return m_NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS SyscallManager::NtCreateSection(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN HANDLE FileHandle OPTIONAL) {
    if (!m_NtCreateSection) {
        m_errorHandler->SetError(ErrorCode::SYSCALL_FAILED, "NtCreateSection function not initialized");
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    
    return m_NtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, 
                            SectionPageProtection, AllocationAttributes, FileHandle);
}

NTSTATUS SyscallManager::NtMapViewOfSection(
    IN HANDLE SectionHandle,
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN SIZE_T CommitSize,
    IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
    IN OUT PSIZE_T ViewSize,
    IN SECTION_INHERIT InheritDisposition,
    IN ULONG AllocationType,
    IN ULONG Win32Protect) {
    if (!m_NtMapViewOfSection) {
        m_errorHandler->SetError(ErrorCode::SYSCALL_FAILED, "NtMapViewOfSection function not initialized");
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    
    return m_NtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, 
                               SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
}

NTSTATUS SyscallManager::NtUnmapViewOfSection(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress) {
    if (!m_NtUnmapViewOfSection) {
        m_errorHandler->SetError(ErrorCode::SYSCALL_FAILED, "NtUnmapViewOfSection function not initialized");
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    
    return m_NtUnmapViewOfSection(ProcessHandle, BaseAddress);
}

NTSTATUS SyscallManager::NtClose(
    IN HANDLE Handle) {
    if (!m_NtClose) {
        m_errorHandler->SetError(ErrorCode::SYSCALL_FAILED, "NtClose function not initialized");
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    
    return m_NtClose(Handle);
}

NTSTATUS SyscallManager::NtGetContextThread(
    IN HANDLE ThreadHandle,
    IN OUT PCONTEXT ThreadContext) {
    if (!m_NtGetContextThread) {
        m_errorHandler->SetError(ErrorCode::SYSCALL_FAILED, "NtGetContextThread function not initialized");
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    
    return m_NtGetContextThread(ThreadHandle, ThreadContext);
}

NTSTATUS SyscallManager::NtSetContextThread(
    IN HANDLE ThreadHandle,
    IN PCONTEXT ThreadContext) {
    if (!m_NtSetContextThread) {
        m_errorHandler->SetError(ErrorCode::SYSCALL_FAILED, "NtSetContextThread function not initialized");
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    
    return m_NtSetContextThread(ThreadHandle, ThreadContext);
}

NTSTATUS SyscallManager::NtResumeThread(
    IN HANDLE ThreadHandle,
    OUT PULONG PreviousSuspendCount OPTIONAL) {
    if (!m_NtResumeThread) {
        m_errorHandler->SetError(ErrorCode::SYSCALL_FAILED, "NtResumeThread function not initialized");
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    
    return m_NtResumeThread(ThreadHandle, PreviousSuspendCount);
}

NTSTATUS SyscallManager::NtSuspendThread(
    IN HANDLE ThreadHandle,
    OUT PULONG PreviousSuspendCount OPTIONAL) {
    if (!m_NtSuspendThread) {
        m_errorHandler->SetError(ErrorCode::SYSCALL_FAILED, "NtSuspendThread function not initialized");
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    
    return m_NtSuspendThread(ThreadHandle, PreviousSuspendCount);
}
