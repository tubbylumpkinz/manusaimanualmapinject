#include "process_memory.h"
#include <Psapi.h>

// ProcessInterface implementation
ProcessInterface::ProcessInterface(ErrorHandler* errorHandler, NameRandomizer* nameRandomizer, SyscallManager* syscallManager)
    : m_errorHandler(errorHandler), 
      m_nameRandomizer(nameRandomizer),
      m_syscallManager(syscallManager),
      m_processHandle(NULL),
      m_threadHandle(NULL),
      m_processId(0),
      m_threadId(0),
      m_isTarget64Bit(false) {
}

ProcessInterface::~ProcessInterface() {
    CloseHandles();
}

ProcessId ProcessInterface::FindProcessByName(const std::string& processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        m_errorHandler->SetError(ErrorCode::PROCESS_NOT_FOUND, 
            "Failed to create process snapshot", GetLastError());
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Apply random timing to avoid detection patterns
    m_nameRandomizer->ApplyRandomTiming(1, 5);

    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        m_errorHandler->SetError(ErrorCode::PROCESS_NOT_FOUND, 
            "Failed to get first process", GetLastError());
        return 0;
    }

    std::wstring wideProcessName = Utils::StringToWideString(processName);
    ProcessId foundPid = 0;

    do {
        // Apply random timing between process checks
        if (Utils::GetRandomNumber(0, 10) > 8) {
            m_nameRandomizer->ApplyRandomTiming(1, 3);
        }

        if (_wcsicmp(pe32.szExeFile, wideProcessName.c_str()) == 0) {
            foundPid = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);

    if (foundPid == 0) {
        m_errorHandler->SetError(ErrorCode::PROCESS_NOT_FOUND, 
            "Process not found: " + processName);
    } else {
        m_processId = foundPid;
        m_errorHandler->ClearError();
    }

    return foundPid;
}

bool ProcessInterface::OpenProcess(ProcessId processId) {
    if (processId == 0) {
        processId = m_processId;
    }

    if (processId == 0) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER, 
            "Invalid process ID");
        return false;
    }

    // Close existing handle if any
    if (m_processHandle != NULL) {
        CloseHandle(m_processHandle);
        m_processHandle = NULL;
    }

    // Apply random timing
    m_nameRandomizer->ApplyRandomTiming(1, 5);

    // Use direct syscall for opening process to avoid API hooks
    OBJECT_ATTRIBUTES objAttr = { sizeof(OBJECT_ATTRIBUTES) };
    CLIENT_ID clientId = { 0 };
    clientId.UniqueProcess = (HANDLE)(DWORD_PTR)processId;

    NTSTATUS status = m_syscallManager->ExecuteNtOpenProcess(
        &m_processHandle,
        GetMinimalProcessAccess(),
        &objAttr,
        &clientId
    );

    if (!NT_SUCCESS(status) || m_processHandle == NULL) {
        m_errorHandler->SetError(ErrorCode::PROCESS_ACCESS_DENIED, 
            "Failed to open process", status);
        return false;
    }

    m_processId = processId;
    
    // Determine process architecture
    if (!GetProcessBitness()) {
        CloseHandle(m_processHandle);
        m_processHandle = NULL;
        return false;
    }

    m_errorHandler->ClearError();
    return true;
}

bool ProcessInterface::IsTarget64Bit() const {
    return m_isTarget64Bit;
}

ProcessHandle ProcessInterface::GetProcessHandle() const {
    return m_processHandle;
}

ThreadId ProcessInterface::FindThreadInProcess() {
    if (m_processId == 0) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER, 
            "Process ID not set");
        return 0;
    }

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        m_errorHandler->SetError(ErrorCode::THREAD_HIJACK_FAILED, 
            "Failed to create thread snapshot", GetLastError());
        return 0;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    // Apply random timing
    m_nameRandomizer->ApplyRandomTiming(1, 5);

    if (!Thread32First(hSnapshot, &te32)) {
        CloseHandle(hSnapshot);
        m_errorHandler->SetError(ErrorCode::THREAD_HIJACK_FAILED, 
            "Failed to get first thread", GetLastError());
        return 0;
    }

    ThreadId foundTid = 0;
    std::vector<ThreadId> candidateThreads;

    // First pass: collect all threads belonging to the target process
    do {
        if (te32.th32OwnerProcessID == m_processId) {
            candidateThreads.push_back(te32.th32ThreadID);
        }
    } while (Thread32Next(hSnapshot, &te32));

    CloseHandle(hSnapshot);

    if (candidateThreads.empty()) {
        m_errorHandler->SetError(ErrorCode::THREAD_HIJACK_FAILED, 
            "No threads found in target process");
        return 0;
    }

    // Apply random timing
    m_nameRandomizer->ApplyRandomTiming(1, 5);

    // Randomly select a thread from the candidates
    // This helps avoid detection patterns that might look for specific thread selection
    size_t randomIndex = Utils::GetRandomNumber(0, static_cast<uint32_t>(candidateThreads.size() - 1));
    foundTid = candidateThreads[randomIndex];

    if (foundTid != 0) {
        m_threadId = foundTid;
        m_errorHandler->ClearError();
    }

    return foundTid;
}

bool ProcessInterface::OpenThread(ThreadId threadId) {
    if (threadId == 0) {
        threadId = m_threadId;
    }

    if (threadId == 0) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER, 
            "Invalid thread ID");
        return false;
    }

    // Close existing handle if any
    if (m_threadHandle != NULL) {
        CloseHandle(m_threadHandle);
        m_threadHandle = NULL;
    }

    // Apply random timing
    m_nameRandomizer->ApplyRandomTiming(1, 5);

    // Open thread with minimal required access
    // Using standard API here as thread opening is less monitored than process opening
    m_threadHandle = ::OpenThread(
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
        FALSE,
        threadId
    );

    if (m_threadHandle == NULL) {
        m_errorHandler->SetError(ErrorCode::THREAD_HIJACK_FAILED, 
            "Failed to open thread", GetLastError());
        return false;
    }

    m_threadId = threadId;
    m_errorHandler->ClearError();
    return true;
}

ThreadHandle ProcessInterface::GetThreadHandle() const {
    return m_threadHandle;
}

void ProcessInterface::CloseHandles() {
    if (m_threadHandle != NULL) {
        CloseHandle(m_threadHandle);
        m_threadHandle = NULL;
    }

    if (m_processHandle != NULL) {
        CloseHandle(m_processHandle);
        m_processHandle = NULL;
    }

    m_processId = 0;
    m_threadId = 0;
}

bool ProcessInterface::GetProcessBitness() {
    if (m_processHandle == NULL) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER, 
            "Process handle not set");
        return false;
    }

    m_isTarget64Bit = Utils::IsProcess64Bit(m_processHandle);

    // Check architecture compatibility
    #ifdef ARCH_X86
    if (m_isTarget64Bit) {
        m_errorHandler->SetError(ErrorCode::INVALID_ARCHITECTURE, 
            "Cannot inject from 32-bit process to 64-bit process");
        return false;
    }
    #endif

    return true;
}

DWORD ProcessInterface::GetMinimalProcessAccess() const {
    // Use minimal required access to avoid triggering security alerts
    // that look for PROCESS_ALL_ACCESS handles
    return PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION;
}
