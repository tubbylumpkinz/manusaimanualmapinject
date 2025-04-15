#pragma once

#include "fixed_common.h"
#include "fixed_utility.h"
#include "fixed_process_memory.h"

// NT API function prototypes
typedef NTSTATUS (NTAPI *NtCreateThreadExFunc)(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits OPTIONAL,
    IN SIZE_T StackSize OPTIONAL,
    IN SIZE_T MaximumStackSize OPTIONAL,
    OUT PVOID AttributeList OPTIONAL
);

typedef NTSTATUS (NTAPI *NtAllocateVirtualMemoryFunc)(
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect
);

typedef NTSTATUS (NTAPI *NtProtectVirtualMemoryFunc)(
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect
);

typedef NTSTATUS (NTAPI *NtWriteVirtualMemoryFunc)(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PVOID Buffer,
    IN SIZE_T NumberOfBytesToWrite,
    OUT PSIZE_T NumberOfBytesWritten OPTIONAL
);

typedef NTSTATUS (NTAPI *NtReadVirtualMemoryFunc)(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    OUT PVOID Buffer,
    IN SIZE_T NumberOfBytesToRead,
    OUT PSIZE_T NumberOfBytesRead OPTIONAL
);

typedef NTSTATUS (NTAPI *NtCreateSectionFunc)(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN HANDLE FileHandle OPTIONAL
);

typedef NTSTATUS (NTAPI *NtMapViewOfSectionFunc)(
    IN HANDLE SectionHandle,
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN SIZE_T CommitSize,
    IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
    IN OUT PSIZE_T ViewSize,
    IN DWORD InheritDisposition,
    IN ULONG AllocationType,
    IN ULONG Win32Protect
);

typedef NTSTATUS (NTAPI *NtUnmapViewOfSectionFunc)(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress
);

typedef NTSTATUS (NTAPI *NtFlushInstructionCacheFunc)(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress OPTIONAL,
    IN SIZE_T Length
);

// Syscall Manager class for direct syscalls
class SyscallManager {
public:
    SyscallManager(ErrorHandler* errorHandler, NameRandomizer* nameRandomizer);
    ~SyscallManager();

    // Initialize the syscall manager
    bool Initialize();
    
    // Create a thread in the target process
    bool CreateRemoteThread(ProcessHandle processHandle, MemoryAddress startAddress, 
                           MemoryAddress parameter, ThreadHandle* threadHandle);
    
    // Allocate memory in the target process
    bool AllocateVirtualMemory(ProcessHandle processHandle, MemoryAddress* baseAddress, 
                              MemorySize size, DWORD allocationType, DWORD protection);
    
    // Protect memory in the target process
    bool ProtectVirtualMemory(ProcessHandle processHandle, MemoryAddress* baseAddress, 
                             MemorySize* size, DWORD newProtection, DWORD* oldProtection);
    
    // Write memory to the target process
    bool WriteVirtualMemory(ProcessHandle processHandle, MemoryAddress baseAddress, 
                           const void* buffer, MemorySize size, MemorySize* bytesWritten);
    
    // Read memory from the target process
    bool ReadVirtualMemory(ProcessHandle processHandle, MemoryAddress baseAddress, 
                          void* buffer, MemorySize size, MemorySize* bytesRead);
    
    // Create a section object
    bool CreateSection(SectionHandle* sectionHandle, DWORD desiredAccess, 
                      MemorySize maximumSize, DWORD pageProtection, DWORD allocationAttributes);
    
    // Map a view of a section
    bool MapViewOfSection(SectionHandle sectionHandle, ProcessHandle processHandle, 
                         MemoryAddress* baseAddress, MemorySize commitSize, 
                         MemorySize* viewSize, DWORD allocationType, DWORD protection);
    
    // Unmap a view of a section
    bool UnmapViewOfSection(ProcessHandle processHandle, MemoryAddress baseAddress);
    
    // Flush instruction cache
    bool FlushInstructionCache(ProcessHandle processHandle, MemoryAddress baseAddress, MemorySize size);
    
    // Get the last error message
    std::string GetLastErrorMessage() const;

private:
    ErrorHandler* m_errorHandler;
    NameRandomizer* m_nameRandomizer;
    
    HMODULE m_ntdllHandle;
    
    NtCreateThreadExFunc m_NtCreateThreadEx;
    NtAllocateVirtualMemoryFunc m_NtAllocateVirtualMemory;
    NtProtectVirtualMemoryFunc m_NtProtectVirtualMemory;
    NtWriteVirtualMemoryFunc m_NtWriteVirtualMemory;
    NtReadVirtualMemoryFunc m_NtReadVirtualMemory;
    NtCreateSectionFunc m_NtCreateSection;
    NtMapViewOfSectionFunc m_NtMapViewOfSection;
    NtUnmapViewOfSectionFunc m_NtUnmapViewOfSection;
    NtFlushInstructionCacheFunc m_NtFlushInstructionCache;
    
    // Internal helper methods
    void* GetProcAddressSafe(HMODULE module, const char* procName);
};
