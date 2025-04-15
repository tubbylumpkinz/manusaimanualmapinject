#include "manual_mapping.h"
#include <Psapi.h>

// ImportResolver implementation
ImportResolver::ImportResolver(ErrorHandler* errorHandler, NameRandomizer* nameRandomizer, ProcessInterface* processInterface)
    : m_errorHandler(errorHandler),
      m_nameRandomizer(nameRandomizer),
      m_processInterface(processInterface) {
}

ImportResolver::~ImportResolver() {
    // Free loaded modules
    for (const auto& module : m_loadedModules) {
        if (module.second) {
            FreeLibrary(module.second);
        }
    }
    m_loadedModules.clear();
}

bool ImportResolver::ResolveImports(const PEParser* peParser, MemoryAddress baseAddress) {
    if (!peParser || !baseAddress) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER, 
            "Invalid parameters for import resolution");
        return false;
    }

    // Apply random timing to avoid detection patterns
    m_nameRandomizer->ApplyRandomTiming(1, 5);

    // Get the import directory
    PIMAGE_DATA_DIRECTORY importDirectory = peParser->GetDataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (!importDirectory || importDirectory->VirtualAddress == 0 || importDirectory->Size == 0) {
        // No imports to resolve
        return true;
    }

    // Get the import descriptors
    PIMAGE_IMPORT_DESCRIPTOR importDesc = static_cast<PIMAGE_IMPORT_DESCRIPTOR>(
        peParser->GetRvaPointer(importDirectory->VirtualAddress));
    if (!importDesc) {
        m_errorHandler->SetError(ErrorCode::IMPORT_RESOLUTION_FAILED, 
            "Failed to get import descriptors");
        return false;
    }

    // Process each imported DLL
    for (; importDesc->Name != 0; importDesc++) {
        // Get the name of the imported DLL
        const char* dllName = static_cast<const char*>(
            peParser->GetRvaPointer(importDesc->Name));
        if (!dllName) {
            m_errorHandler->SetError(ErrorCode::IMPORT_RESOLUTION_FAILED, 
                "Failed to get imported DLL name");
            return false;
        }

        // Apply random timing between DLL processing
        if (Utils::GetRandomNumber(0, 10) > 8) {
            m_nameRandomizer->ApplyRandomTiming(1, 3);
        }

        // Load the module in the local process
        HMODULE localModule = LoadModuleInLocalProcess(dllName);
        if (!localModule) {
            return false;
        }

        // Get the module handle in the remote process
        MemoryAddress remoteModule = GetRemoteModuleHandle(dllName);
        if (!remoteModule) {
            return false;
        }

        // Process the import address table (IAT)
        DWORD iatRva = importDesc->FirstThunk;
        DWORD originalFirstThunkRva = importDesc->OriginalFirstThunk;

        // If OriginalFirstThunk is 0, use FirstThunk instead
        if (originalFirstThunkRva == 0) {
            originalFirstThunkRva = iatRva;
        }

        // Get the thunk data
        if (peParser->Is64Bit()) {
            // 64-bit PE file
            PIMAGE_THUNK_DATA64 thunk = static_cast<PIMAGE_THUNK_DATA64>(
                peParser->GetRvaPointer(originalFirstThunkRva));
            PIMAGE_THUNK_DATA64 iat = static_cast<PIMAGE_THUNK_DATA64>(
                peParser->GetRvaPointer(iatRva));

            if (!thunk || !iat) {
                m_errorHandler->SetError(ErrorCode::IMPORT_RESOLUTION_FAILED, 
                    "Failed to get thunk data");
                return false;
            }

            // Process each function
            for (; thunk->u1.AddressOfData != 0; thunk++, iat++) {
                MemoryAddress functionAddress = 0;

                // Check if the import is by ordinal
                if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                    // Import by ordinal
                    WORD ordinal = static_cast<WORD>(thunk->u1.Ordinal & 0xFFFF);
                    functionAddress = GetRemoteProcAddressByOrdinal(localModule, remoteModule, ordinal);
                } else {
                    // Import by name
                    PIMAGE_IMPORT_BY_NAME importByName = static_cast<PIMAGE_IMPORT_BY_NAME>(
                        peParser->GetRvaPointer(static_cast<DWORD>(thunk->u1.AddressOfData)));
                    if (!importByName) {
                        m_errorHandler->SetError(ErrorCode::IMPORT_RESOLUTION_FAILED, 
                            "Failed to get import by name");
                        return false;
                    }

                    functionAddress = GetRemoteProcAddress(localModule, remoteModule, importByName->Name);
                }

                if (!functionAddress) {
                    return false;
                }

                // Write the function address to the IAT in the target process
                ULONGLONG* iatEntry = reinterpret_cast<ULONGLONG*>(
                    reinterpret_cast<BYTE*>(baseAddress) + iatRva + 
                    (reinterpret_cast<BYTE*>(iat) - reinterpret_cast<BYTE*>(
                        peParser->GetRvaPointer(iatRva))));
                *iatEntry = reinterpret_cast<ULONGLONG>(functionAddress);

                // Apply random timing between function resolution
                if (Utils::GetRandomNumber(0, 20) > 18) {
                    m_nameRandomizer->ApplyRandomTiming(1, 2);
                }
            }
        } else {
            // 32-bit PE file
            PIMAGE_THUNK_DATA32 thunk = static_cast<PIMAGE_THUNK_DATA32>(
                peParser->GetRvaPointer(originalFirstThunkRva));
            PIMAGE_THUNK_DATA32 iat = static_cast<PIMAGE_THUNK_DATA32>(
                peParser->GetRvaPointer(iatRva));

            if (!thunk || !iat) {
                m_errorHandler->SetError(ErrorCode::IMPORT_RESOLUTION_FAILED, 
                    "Failed to get thunk data");
                return false;
            }

            // Process each function
            for (; thunk->u1.AddressOfData != 0; thunk++, iat++) {
                MemoryAddress functionAddress = 0;

                // Check if the import is by ordinal
                if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
                    // Import by ordinal
                    WORD ordinal = static_cast<WORD>(thunk->u1.Ordinal & 0xFFFF);
                    functionAddress = GetRemoteProcAddressByOrdinal(localModule, remoteModule, ordinal);
                } else {
                    // Import by name
                    PIMAGE_IMPORT_BY_NAME importByName = static_cast<PIMAGE_IMPORT_BY_NAME>(
                        peParser->GetRvaPointer(thunk->u1.AddressOfData));
                    if (!importByName) {
                        m_errorHandler->SetError(ErrorCode::IMPORT_RESOLUTION_FAILED, 
                            "Failed to get import by name");
                        return false;
                    }

                    functionAddress = GetRemoteProcAddress(localModule, remoteModule, importByName->Name);
                }

                if (!functionAddress) {
                    return false;
                }

                // Write the function address to the IAT in the target process
                DWORD* iatEntry = reinterpret_cast<DWORD*>(
                    reinterpret_cast<BYTE*>(baseAddress) + iatRva + 
                    (reinterpret_cast<BYTE*>(iat) - reinterpret_cast<BYTE*>(
                        peParser->GetRvaPointer(iatRva))));
                *iatEntry = reinterpret_cast<DWORD>(functionAddress);

                // Apply random timing between function resolution
                if (Utils::GetRandomNumber(0, 20) > 18) {
                    m_nameRandomizer->ApplyRandomTiming(1, 2);
                }
            }
        }
    }

    m_errorHandler->ClearError();
    return true;
}

MemoryAddress ImportResolver::GetProcAddressByName(const std::string& moduleName, const std::string& functionName) {
    // Load the module in the local process
    HMODULE localModule = LoadModuleInLocalProcess(moduleName);
    if (!localModule) {
        return NULL;
    }

    // Get the module handle in the remote process
    MemoryAddress remoteModule = GetRemoteModuleHandle(moduleName);
    if (!remoteModule) {
        return NULL;
    }

    // Get the function address
    return GetRemoteProcAddress(localModule, remoteModule, functionName.c_str());
}

MemoryAddress ImportResolver::GetProcAddressByOrdinal(const std::string& moduleName, WORD ordinal) {
    // Load the module in the local process
    HMODULE localModule = LoadModuleInLocalProcess(moduleName);
    if (!localModule) {
        return NULL;
    }

    // Get the module handle in the remote process
    MemoryAddress remoteModule = GetRemoteModuleHandle(moduleName);
    if (!remoteModule) {
        return NULL;
    }

    // Get the function address
    return GetRemoteProcAddressByOrdinal(localModule, remoteModule, ordinal);
}

DWORD ImportResolver::CalculateFunctionHash(const char* functionName) const {
    if (!functionName) {
        return 0;
    }

    // Simple hash algorithm (djb2)
    DWORD hash = 5381;
    int c;

    while ((c = *functionName++)) {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }

    return hash;
}

HMODULE ImportResolver::LoadModuleInLocalProcess(const std::string& moduleName) {
    // Check if the module is already loaded
    auto it = m_loadedModules.find(moduleName);
    if (it != m_loadedModules.end()) {
        return it->second;
    }

    // Apply random timing to avoid detection patterns
    m_nameRandomizer->ApplyRandomTiming(1, 5);

    // Load the module
    HMODULE hModule = LoadLibraryA(moduleName.c_str());
    if (!hModule) {
        m_errorHandler->SetError(ErrorCode::IMPORT_RESOLUTION_FAILED, 
            "Failed to load module: " + moduleName, GetLastError());
        return NULL;
    }

    // Store the module handle
    m_loadedModules[moduleName] = hModule;

    return hModule;
}

MemoryAddress ImportResolver::GetRemoteModuleHandle(const std::string& moduleName) {
    if (!m_processInterface->GetProcessHandle()) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER, 
            "Process handle not set");
        return NULL;
    }

    // Apply random timing to avoid detection patterns
    m_nameRandomizer->ApplyRandomTiming(1, 5);

    // Get the list of modules in the remote process
    HMODULE hModules[1024];
    DWORD cbNeeded;

    if (!EnumProcessModules(m_processInterface->GetProcessHandle(), hModules, sizeof(hModules), &cbNeeded)) {
        m_errorHandler->SetError(ErrorCode::IMPORT_RESOLUTION_FAILED, 
            "Failed to enumerate process modules", GetLastError());
        return NULL;
    }

    // Calculate the number of modules
    DWORD numModules = cbNeeded / sizeof(HMODULE);

    // Convert module name to lowercase for case-insensitive comparison
    std::string lowerModuleName = moduleName;
    std::transform(lowerModuleName.begin(), lowerModuleName.end(), lowerModuleName.begin(), ::tolower);

    // Check if the module name ends with .dll
    if (lowerModuleName.size() < 4 || lowerModuleName.substr(lowerModuleName.size() - 4) != ".dll") {
        lowerModuleName += ".dll";
    }

    // Find the module
    for (DWORD i = 0; i < numModules; i++) {
        char szModName[MAX_PATH];
        if (GetModuleFileNameExA(m_processInterface->GetProcessHandle(), hModules[i], szModName, sizeof(szModName))) {
            // Extract the module name from the path
            std::string fullPath = szModName;
            size_t pos = fullPath.find_last_of('\\');
            std::string name = (pos != std::string::npos) ? fullPath.substr(pos + 1) : fullPath;

            // Convert to lowercase for case-insensitive comparison
            std::transform(name.begin(), name.end(), name.begin(), ::tolower);

            // Compare module names
            if (name == lowerModuleName) {
                return hModules[i];
            }
        }

        // Apply random timing between module checks
        if (Utils::GetRandomNumber(0, 20) > 18) {
            m_nameRandomizer->ApplyRandomTiming(1, 2);
        }
    }

    m_errorHandler->SetError(ErrorCode::IMPORT_RESOLUTION_FAILED, 
        "Module not found in target process: " + moduleName);
    return NULL;
}

MemoryAddress ImportResolver::GetRemoteProcAddress(HMODULE localModule, MemoryAddress remoteModule, const char* functionName) {
    if (!localModule || !remoteModule || !functionName) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER, 
            "Invalid parameters for GetRemoteProcAddress");
        return NULL;
    }

    // Apply random timing to avoid detection patterns
    if (Utils::GetRandomNumber(0, 10) > 8) {
        m_nameRandomizer->ApplyRandomTiming(1, 3);
    }

    // Get the function address in the local process
    FARPROC localFuncAddr = GetProcAddress(localModule, functionName);
    if (!localFuncAddr) {
        m_errorHandler->SetError(ErrorCode::IMPORT_RESOLUTION_FAILED, 
            std::string("Function not found: ") + functionName, GetLastError());
        return NULL;
    }

    // Calculate the offset from the module base
    DWORD_PTR offset = reinterpret_cast<DWORD_PTR>(localFuncAddr) - reinterpret_cast<DWORD_PTR>(localModule);

    // Calculate the function address in the remote process
    MemoryAddress remoteFuncAddr = reinterpret_cast<MemoryAddress>(
        reinterpret_cast<DWORD_PTR>(remoteModule) + offset);

    return remoteFuncAddr;
}

MemoryAddress ImportResolver::GetRemoteProcAddressByOrdinal(HMODULE localModule, MemoryAddress remoteModule, WORD ordinal) {
    if (!localModule || !remoteModule) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER, 
            "Invalid parameters for GetRemoteProcAddressByOrdinal");
        return NULL;
    }

    // Apply random timing to avoid detection patterns
    if (Utils::GetRandomNumber(0, 10) > 8) {
        m_nameRandomizer->ApplyRandomTiming(1, 3);
    }

    // Get the function address in the local process
    FARPROC localFuncAddr = GetProcAddress(localModule, reinterpret_cast<LPCSTR>(ordinal));
    if (!localFuncAddr) {
        m_errorHandler->SetError(ErrorCode::IMPORT_RESOLUTION_FAILED, 
            "Function not found by ordinal: " + std::to_string(ordinal), GetLastError());
        return NULL;
    }

    // Calculate the offset from the module base
    DWORD_PTR offset = reinterpret_cast<DWORD_PTR>(localFuncAddr) - reinterpret_cast<DWORD_PTR>(localModule);

    // Calculate the function address in the remote process
    MemoryAddress remoteFuncAddr = reinterpret_cast<MemoryAddress>(
        reinterpret_cast<DWORD_PTR>(remoteModule) + offset);

    return remoteFuncAddr;
}
