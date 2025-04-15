#pragma once

#include "common.h"
#include "utility.h"

// Add necessary Windows NT definitions
#include <Windows.h>
#include <winternl.h>

// If POBJECT_ATTRIBUTES is not defined, define it
#ifndef _OBJECT_ATTRIBUTES_DEFINED
#define _OBJECT_ATTRIBUTES_DEFINED
typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
#endif

// Define any other missing NT structures
#ifndef _CLIENT_ID_DEFINED
#define _CLIENT_ID_DEFINED
typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;
#endif

// Define NT_SUCCESS macro if not defined
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Process Interface class for accessing target processes
class ProcessInterface {
public:
    ProcessInterface(ErrorHandler* errorHandler, NameRandomizer* nameRandomizer);
    ~ProcessInterface();

    // Open a process by name
    bool OpenProcessByName(const std::string& processName);
    
    // Open a process by ID
    bool OpenProcessById(ProcessId processId);
    
    // Close the process handle
    void CloseProcess();
    
    // Get the process handle
    ProcessHandle GetProcessHandle() const;
    
    // Get the process ID
    ProcessId GetProcessId() const;
    
    // Check if the process is 64-bit
    bool IsProcess64Bit() const;
    
    // Get a thread handle by ID
    ThreadHandle GetThreadHandle(ThreadId threadId) const;
    
    // Get the main thread ID
    ThreadId GetMainThreadId() const;
    
    // Suspend a thread
    bool SuspendThread(ThreadId threadId);
    
    // Resume a thread
    bool ResumeThread(ThreadId threadId);
    
    // Get the thread context
    bool GetThreadContext(ThreadId threadId, LPCONTEXT context);
    
    // Set the thread context
    bool SetThreadContext(ThreadId threadId, LPCONTEXT context);
    
    // Wait for a thread to complete
    bool WaitForThread(ThreadId threadId, DWORD timeoutMs);
    
    // Get the last error message
    std::string GetLastErrorMessage() const;

private:
    ErrorHandler* m_errorHandler;
    NameRandomizer* m_nameRandomizer;
    
    ProcessHandle m_processHandle;
    ProcessId m_processId;
    bool m_isProcess64Bit;
    
    // Internal helper methods
    bool OpenProcessNative(ProcessId processId);
    ProcessId GetProcessIdByName(const std::string& processName);
    ThreadId FindMainThreadId(ProcessId processId);
};

// Memory Manager class for memory operations
class MemoryManager {
public:
    MemoryManager(ErrorHandler* errorHandler, NameRandomizer* nameRandomizer, ProcessInterface* processInterface);
    ~MemoryManager();

    // Allocate memory in the target process
    MemoryAddress AllocateMemory(MemorySize size, DWORD protection);
    
    // Free memory in the target process
    bool FreeMemory(MemoryAddress address);
    
    // Write memory to the target process
    bool WriteMemory(MemoryAddress address, const void* buffer, MemorySize size);
    
    // Read memory from the target process
    bool ReadMemory(MemoryAddress address, void* buffer, MemorySize size);
    
    // Change memory protection
    bool ProtectMemory(MemoryAddress address, MemorySize size, DWORD protection, DWORD* oldProtection);
    
    // Create a section object
    SectionHandle CreateSection(MemorySize size, DWORD protection);
    
    // Map a section into the target process
    MemoryAddress MapSection(SectionHandle section, MemorySize size, DWORD protection);
    
    // Unmap a section from the target process
    bool UnmapSection(MemoryAddress address);
    
    // Map a view of a section into the local process
    MemoryAddress MapLocalSection(SectionHandle section, MemorySize size, DWORD protection);
    
    // Unmap a view of a section from the local process
    bool UnmapLocalSection(MemoryAddress address);
    
    // Flush instruction cache
    bool FlushInstructionCache(MemoryAddress address, MemorySize size);
    
    // Get the last error message
    std::string GetLastErrorMessage() const;

private:
    ErrorHandler* m_errorHandler;
    NameRandomizer* m_nameRandomizer;
    ProcessInterface* m_processInterface;
    
    // Internal helper methods
    bool InitializeObjectAttributes(POBJECT_ATTRIBUTES objectAttributes, PUNICODE_STRING objectName, ULONG attributes, HANDLE rootDirectory, PVOID securityDescriptor);
};
