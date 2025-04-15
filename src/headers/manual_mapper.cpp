#include "manual_mapping.h"

// ManualMapper implementation
ManualMapper::ManualMapper(ErrorHandler* errorHandler, NameRandomizer* nameRandomizer, 
                         ProcessInterface* processInterface, MemoryManager* memoryManager)
    : m_errorHandler(errorHandler),
      m_nameRandomizer(nameRandomizer),
      m_processInterface(processInterface),
      m_memoryManager(memoryManager),
      m_importResolver(nullptr) {
    
    // Create the import resolver
    m_importResolver = new ImportResolver(errorHandler, nameRandomizer, processInterface);
}

ManualMapper::~ManualMapper() {
    // Clean up the import resolver
    if (m_importResolver) {
        delete m_importResolver;
        m_importResolver = nullptr;
    }
}

MemoryAddress ManualMapper::MapDll(const PEParser* peParser) {
    if (!peParser) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER, 
            "Invalid PE parser");
        return NULL;
    }

    // Apply random timing to avoid detection patterns
    m_nameRandomizer->ApplyRandomTiming(1, 5);

    // Check architecture compatibility
    bool is64BitProcess = m_processInterface->IsTarget64Bit();
    bool is64BitDll = peParser->Is64Bit();
    
    if (is64BitProcess != is64BitDll) {
        m_errorHandler->SetError(ErrorCode::INVALID_ARCHITECTURE, 
            "Architecture mismatch between process and DLL");
        return NULL;
    }

    // Get the size of the image
    DWORD imageSize = peParser->GetSizeOfImage();
    if (imageSize == 0) {
        m_errorHandler->SetError(ErrorCode::PE_PARSE_FAILED, 
            "Invalid image size");
        return NULL;
    }

    // Allocate memory for the DLL in the target process
    MemoryAddress baseAddress = m_memoryManager->AllocateMemory(imageSize, PAGE_EXECUTE_READWRITE);
    if (!baseAddress) {
        return NULL;
    }

    // Map the sections
    if (!MapSections(peParser, baseAddress)) {
        m_memoryManager->FreeMemory(baseAddress);
        return NULL;
    }

    // Process relocations
    ULONGLONG imageBase = peParser->GetImageBase();
    ULONGLONG deltaBase = reinterpret_cast<ULONGLONG>(baseAddress) - imageBase;
    
    if (deltaBase != 0) {
        if (!ProcessRelocations(peParser, baseAddress, deltaBase)) {
            m_memoryManager->FreeMemory(baseAddress);
            return NULL;
        }
    }

    // Resolve imports
    if (!m_importResolver->ResolveImports(peParser, baseAddress)) {
        m_memoryManager->FreeMemory(baseAddress);
        return NULL;
    }

    // Process TLS callbacks
    if (!ProcessTlsCallbacks(peParser, baseAddress)) {
        m_memoryManager->FreeMemory(baseAddress);
        return NULL;
    }

    // Initialize security cookie
    if (!InitializeSecurityCookie(peParser, baseAddress)) {
        m_memoryManager->FreeMemory(baseAddress);
        return NULL;
    }

    // Clean up PE headers
    if (!CleanupHeaders(baseAddress)) {
        m_memoryManager->FreeMemory(baseAddress);
        return NULL;
    }

    m_errorHandler->ClearError();
    return baseAddress;
}

bool ManualMapper::ProcessRelocations(const PEParser* peParser, MemoryAddress baseAddress, ULONGLONG deltaBase) {
    if (!peParser || !baseAddress || deltaBase == 0) {
        return true; // No relocations needed
    }

    // Apply random timing to avoid detection patterns
    m_nameRandomizer->ApplyRandomTiming(1, 5);

    // Get the relocation directory
    PIMAGE_DATA_DIRECTORY relocDir = peParser->GetDataDirectory(IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (!relocDir || relocDir->VirtualAddress == 0 || relocDir->Size == 0) {
        // No relocations
        return true;
    }

    // Get the first relocation block
    PIMAGE_BASE_RELOCATION relocationBlock = static_cast<PIMAGE_BASE_RELOCATION>(
        peParser->GetRvaPointer(relocDir->VirtualAddress));
    if (!relocationBlock) {
        m_errorHandler->SetError(ErrorCode::RELOCATION_FAILED, 
            "Failed to get relocation block");
        return false;
    }

    // Process each relocation block
    DWORD relocDirSize = relocDir->Size;
    DWORD processedSize = 0;

    while (processedSize < relocDirSize && relocationBlock->SizeOfBlock > 0) {
        // Apply the relocations in this block
        if (!ApplyRelocations(relocationBlock, baseAddress, deltaBase, relocationBlock->SizeOfBlock)) {
            return false;
        }

        // Move to the next block
        processedSize += relocationBlock->SizeOfBlock;
        relocationBlock = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
            reinterpret_cast<BYTE*>(relocationBlock) + relocationBlock->SizeOfBlock);

        // Apply random timing between relocation blocks
        if (Utils::GetRandomNumber(0, 10) > 8) {
            m_nameRandomizer->ApplyRandomTiming(1, 3);
        }
    }

    m_errorHandler->ClearError();
    return true;
}

bool ManualMapper::ProcessTlsCallbacks(const PEParser* peParser, MemoryAddress baseAddress) {
    if (!peParser || !baseAddress) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER, 
            "Invalid parameters for TLS processing");
        return false;
    }

    // Apply random timing to avoid detection patterns
    m_nameRandomizer->ApplyRandomTiming(1, 5);

    // Get the TLS directory
    PIMAGE_DATA_DIRECTORY tlsDir = peParser->GetDataDirectory(IMAGE_DIRECTORY_ENTRY_TLS);
    if (!tlsDir || tlsDir->VirtualAddress == 0 || tlsDir->Size == 0) {
        // No TLS callbacks
        return true;
    }

    // TLS processing is architecture-specific
    if (peParser->Is64Bit()) {
        // 64-bit TLS processing
        PIMAGE_TLS_DIRECTORY64 tlsDirectory = static_cast<PIMAGE_TLS_DIRECTORY64>(
            peParser->GetRvaPointer(tlsDir->VirtualAddress));
        if (!tlsDirectory) {
            m_errorHandler->SetError(ErrorCode::PE_PARSE_FAILED, 
                "Failed to get TLS directory");
            return false;
        }

        // Check if there are callbacks
        if (tlsDirectory->AddressOfCallBacks == 0) {
            return true;
        }

        // Get the callbacks array
        ULONGLONG* callbacks = reinterpret_cast<ULONGLONG*>(
            reinterpret_cast<BYTE*>(baseAddress) + 
            (tlsDirectory->AddressOfCallBacks - peParser->GetImageBase()));

        // Process each callback
        for (DWORD i = 0; callbacks[i] != 0; i++) {
            // Calculate the callback address in the target process
            ULONGLONG callbackRva = callbacks[i] - peParser->GetImageBase();
            ULONGLONG callbackAddr = reinterpret_cast<ULONGLONG>(baseAddress) + callbackRva;

            // Update the callback address
            callbacks[i] = callbackAddr;
        }
    } else {
        // 32-bit TLS processing
        PIMAGE_TLS_DIRECTORY32 tlsDirectory = static_cast<PIMAGE_TLS_DIRECTORY32>(
            peParser->GetRvaPointer(tlsDir->VirtualAddress));
        if (!tlsDirectory) {
            m_errorHandler->SetError(ErrorCode::PE_PARSE_FAILED, 
                "Failed to get TLS directory");
            return false;
        }

        // Check if there are callbacks
        if (tlsDirectory->AddressOfCallBacks == 0) {
            return true;
        }

        // Get the callbacks array
        DWORD* callbacks = reinterpret_cast<DWORD*>(
            reinterpret_cast<BYTE*>(baseAddress) + 
            (tlsDirectory->AddressOfCallBacks - peParser->GetImageBase()));

        // Process each callback
        for (DWORD i = 0; callbacks[i] != 0; i++) {
            // Calculate the callback address in the target process
            DWORD callbackRva = callbacks[i] - static_cast<DWORD>(peParser->GetImageBase());
            DWORD callbackAddr = reinterpret_cast<DWORD>(baseAddress) + callbackRva;

            // Update the callback address
            callbacks[i] = callbackAddr;
        }
    }

    m_errorHandler->ClearError();
    return true;
}

bool ManualMapper::InitializeSecurityCookie(const PEParser* peParser, MemoryAddress baseAddress) {
    if (!peParser || !baseAddress) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER, 
            "Invalid parameters for security cookie initialization");
        return false;
    }

    // Apply random timing to avoid detection patterns
    m_nameRandomizer->ApplyRandomTiming(1, 5);

    // Get the load config directory
    PIMAGE_DATA_DIRECTORY loadConfigDir = peParser->GetDataDirectory(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
    if (!loadConfigDir || loadConfigDir->VirtualAddress == 0 || loadConfigDir->Size == 0) {
        // No load config directory
        return true;
    }

    // Generate a random security cookie
    ULONGLONG cookie = 0;
    if (peParser->Is64Bit()) {
        // 64-bit cookie
        DWORD high = Utils::GetRandomNumber(0, 0xFFFFFFFF);
        DWORD low = Utils::GetRandomNumber(0, 0xFFFFFFFF);
        cookie = (static_cast<ULONGLONG>(high) << 32) | low;
    } else {
        // 32-bit cookie
        cookie = Utils::GetRandomNumber(0, 0xFFFFFFFF);
    }

    // Ensure the cookie is not a common value
    if (cookie == 0 || cookie == 0xBB40E64E || cookie == 0xBB40E64EFDCDFFFF) {
        cookie = 0xABCDEF0123456789;
    }

    // Write the cookie to the security cookie address
    if (peParser->Is64Bit()) {
        // 64-bit load config
        // Note: We're not using the full structure to avoid dependencies
        // Just accessing the SecurityCookie field directly
        BYTE* loadConfigData = static_cast<BYTE*>(peParser->GetRvaPointer(loadConfigDir->VirtualAddress));
        if (!loadConfigData) {
            m_errorHandler->SetError(ErrorCode::PE_PARSE_FAILED, 
                "Failed to get load config directory");
            return false;
        }

        // The SecurityCookie field is at offset 0x40 in the 64-bit load config
        ULONGLONG* securityCookieAddr = reinterpret_cast<ULONGLONG*>(loadConfigData + 0x40);
        if (*securityCookieAddr != 0) {
            // Calculate the security cookie address in the target process
            ULONGLONG cookieRva = *securityCookieAddr - peParser->GetImageBase();
            ULONGLONG* remoteCookieAddr = reinterpret_cast<ULONGLONG*>(
                reinterpret_cast<BYTE*>(baseAddress) + cookieRva);

            // Write the cookie
            *remoteCookieAddr = cookie;
        }
    } else {
        // 32-bit load config
        BYTE* loadConfigData = static_cast<BYTE*>(peParser->GetRvaPointer(loadConfigDir->VirtualAddress));
        if (!loadConfigData) {
            m_errorHandler->SetError(ErrorCode::PE_PARSE_FAILED, 
                "Failed to get load config directory");
            return false;
        }

        // The SecurityCookie field is at offset 0x1C in the 32-bit load config
        DWORD* securityCookieAddr = reinterpret_cast<DWORD*>(loadConfigData + 0x1C);
        if (*securityCookieAddr != 0) {
            // Calculate the security cookie address in the target process
            DWORD cookieRva = *securityCookieAddr - static_cast<DWORD>(peParser->GetImageBase());
            DWORD* remoteCookieAddr = reinterpret_cast<DWORD*>(
                reinterpret_cast<BYTE*>(baseAddress) + cookieRva);

            // Write the cookie
            *remoteCookieAddr = static_cast<DWORD>(cookie);
        }
    }

    m_errorHandler->ClearError();
    return true;
}

bool ManualMapper::CleanupHeaders(MemoryAddress baseAddress) {
    if (!baseAddress) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER, 
            "Invalid base address for header cleanup");
        return false;
    }

    // Apply random timing to avoid detection patterns
    m_nameRandomizer->ApplyRandomTiming(1, 5);

    // Get the DOS header
    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(baseAddress);
    
    // Calculate the size of the headers
    DWORD headerSize = 0;
    
    // Check if it's a 64-bit PE
    DWORD ntSignature = *reinterpret_cast<DWORD*>(
        reinterpret_cast<BYTE*>(baseAddress) + dosHeader->e_lfanew);
    
    if (ntSignature != 0x00004550) { // 'PE\0\0'
        m_errorHandler->SetError(ErrorCode::PE_PARSE_FAILED, 
            "Invalid NT signature");
        return false;
    }
    
    PIMAGE_FILE_HEADER fileHeader = reinterpret_cast<PIMAGE_FILE_HEADER>(
        reinterpret_cast<BYTE*>(baseAddress) + dosHeader->e_lfanew + sizeof(DWORD));
    
    if (fileHeader->Machine == 0x8664) { // IMAGE_FILE_MACHINE_AMD64
        // 64-bit PE
        PIMAGE_NT_HEADERS64 ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(
            reinterpret_cast<BYTE*>(baseAddress) + dosHeader->e_lfanew);
        headerSize = ntHeaders->OptionalHeader.SizeOfHeaders;
    } else {
        // 32-bit PE
        PIMAGE_NT_HEADERS32 ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS32>(
            reinterpret_cast<BYTE*>(baseAddress) + dosHeader->e_lfanew);
        headerSize = ntHeaders->OptionalHeader.SizeOfHeaders;
    }
    
    // Zero out the headers
    memset(baseAddress, 0, headerSize);
    
    m_errorHandler->ClearError();
    return true;
}

DWORD ManualMapper::GetSectionProtection(DWORD characteristics) const {
    DWORD protection = 0;
    
    // Determine the protection flags based on section characteristics
    if (characteristics & IMAGE_SCN_MEM_EXECUTE) {
        if (characteristics & IMAGE_SCN_MEM_WRITE) {
            protection = PAGE_EXECUTE_READWRITE;
        } else if (characteristics & IMAGE_SCN_MEM_READ) {
            protection = PAGE_EXECUTE_READ;
        } else {
            protection = PAGE_EXECUTE;
        }
    } else if (characteristics & IMAGE_SCN_MEM_WRITE) {
        protection = PAGE_READWRITE;
    } else if (characteristics & IMAGE_SCN_MEM_READ) {
        protection = PAGE_READONLY;
    } else {
        protection = PAGE_NOACCESS;
    }
    
    return protection;
}

bool ManualMapper::MapSections(const PEParser* peParser, MemoryAddress baseAddress) {
    if (!peParser || !baseAddress) {
        m_errorHandler->SetError(ErrorCode::INVALID_PARAMETER, 
            "Invalid parameters for section mapping");
        return false;
    }
    
    // Apply random timing to avoid detection patterns
    m_nameRandomizer->ApplyRandomTiming(1, 5);
    
    // Get the section headers
    PIMAGE_SECTION_HEADER sectionHeaders = peParser->GetSectionHeaders();
    WORD numberOfSections = peParser->GetNumberOfSections();
    
    if (!sectionHeaders || numberOfSections == 0) {
        m_errorHandler->SetError(ErrorCode::PE_PARSE_FAILED, 
            "Failed to get section headers");
        return false;
    }
    
    // Copy the headers
    DWORD headerSize = 0;
    
    if (peParser->Is64Bit()) {
        PIMAGE_NT_HEADERS64 ntHeaders = static_cast<PIMAGE_NT_HEADERS64>(peParser->GetNtHeaders());
        headerSize = ntHeaders->OptionalHeader.SizeOfHeaders;
    } else {
        PIMAGE_NT_HEADERS32 ntHeaders = static_cast<PIMAGE_NT_HEADERS32>(peParser->GetNtHeaders());
        headerSize = ntHeaders->OptionalHeader.SizeOfHeaders;
    }
    
    // Copy the headers to the target process
    if (!m_memoryManager->WriteMemory(baseAddress, peParser->GetDllData(), headerSize)) {
        return false;
    }
    
    // Map each section
    for (WORD i = 0; i < numberOfSections; i++) {
        // Get the section data
        DWORD virtualAddress = sectionHeaders[i].VirtualAddress;
        DWORD virtualSize = sectionHeaders[i].Misc.VirtualSize;
        DWORD rawDataSize = sectionHeaders[i].SizeOfRawData;
        DWORD rawDataOffset = sectionHeaders[i].PointerToRawData;
        
        // Calculate the section address in the target process
        MemoryAddress sectionAddress = reinterpret_cast<MemoryAddress>(
            reinterpret_cast<BYTE*>(baseAddress) + virtualAddress);
        
        // Copy the section data
        if (rawDataSize > 0) {
            const BYTE* sectionData = peParser->GetDllData() + rawDataOffset;
            
            // Write the section data to the target process
            if (!m_memoryManager->WriteMemory(sectionAddress, sectionData, rawDataSize)) {
                return false;
            }
        }
        
        // Apply random timing between section mapping
        if (Utils::GetRandomNumber(0, 10) > 8) {
            m_nameRandomizer->ApplyRandomTiming(1, 3);
        }
    }
    
    m_errorHandler->ClearError();
    return true;
}

bool ManualMapper::ApplyRelocations(PIMAGE_BASE_RELOCATION relocationBlock, MemoryAddress baseAddress, 
                                  ULONGLONG deltaBase, DWORD blockSize) {
    if (!relocationBlock || !baseAddress || deltaBase == 0 || blockSize < sizeof(IMAGE_BASE_RELOCATION)) {
        return true; // No relocations to apply
    }
    
    // Calculate the number of entries in this block
    DWORD entriesCount = (blockSize - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
    if (entriesCount == 0) {
        return true;
    }
    
    // Get the first entry
    WORD* entries = reinterpret_cast<WORD*>(relocationBlock + 1);
    
    // Get the page RVA (where the relocations should be applied)
    DWORD pageRva = relocationBlock->VirtualAddress;
    
    // Apply each relocation
    for (DWORD i = 0; i < entriesCount; i++) {
        // Get the relocation info
        WORD relocInfo = entries[i];
        WORD relocType = relocInfo >> 12;
        WORD offset = relocInfo & 0xFFF;
        
        // Calculate the relocation address
        BYTE* relocAddr = reinterpret_cast<BYTE*>(baseAddress) + pageRva + offset;
        
        // Apply the relocation based on type
        switch (relocType) {
            case IMAGE_REL_BASED_ABSOLUTE:
                // Do nothing
                break;
                
            case IMAGE_REL_BASED_HIGH:
                // Apply the high 16-bits of the delta
                *reinterpret_cast<WORD*>(relocAddr) += HIWORD(deltaBase);
                break;
                
            case IMAGE_REL_BASED_LOW:
                // Apply the low 16-bits of the delta
                *reinterpret_cast<WORD*>(relocAddr) += LOWORD(deltaBase);
                break;
                
            case IMAGE_REL_BASED_HIGHLOW:
                // Apply the 32-bit delta
                *reinterpret_cast<DWORD*>(relocAddr) += static_cast<DWORD>(deltaBase);
                break;
                
            case IMAGE_REL_BASED_DIR64:
                // Apply the 64-bit delta
                *reinterpret_cast<ULONGLONG*>(relocAddr) += deltaBase;
                break;
                
            default:
                // Unsupported relocation type
                m_errorHandler->SetError(ErrorCode::RELOCATION_FAILED, 
                    "Unsupported relocation type: " + std::to_string(relocType));
                return false;
        }
    }
    
    return true;
}
