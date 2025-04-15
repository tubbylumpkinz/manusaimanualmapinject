#include "manual_mapping.h"
#include <fstream>

// PEParser implementation
PEParser::PEParser(ErrorHandler* errorHandler, NameRandomizer* nameRandomizer)
    : m_errorHandler(errorHandler),
      m_nameRandomizer(nameRandomizer),
      m_is64Bit(false) {
}

PEParser::~PEParser() {
    // Clear DLL data for security
    if (!m_dllData.empty()) {
        Utils::SecureZeroMemory(m_dllData.data(), m_dllData.size());
        m_dllData.clear();
    }
}

bool PEParser::LoadDll(const std::string& dllPath) {
    // Apply random timing to avoid detection patterns
    m_nameRandomizer->ApplyRandomTiming(1, 5);

    // Get file size
    DWORD fileSize = GetFileSize(dllPath);
    if (fileSize == 0) {
        return false;
    }

    // Resize buffer to hold the DLL
    m_dllData.resize(fileSize);

    // Open the file
    std::ifstream file(dllPath, std::ios::binary);
    if (!file.is_open()) {
        m_errorHandler->SetError(ErrorCode::FILE_NOT_FOUND, 
            "Failed to open DLL file: " + dllPath);
        return false;
    }

    // Read the file
    file.read(reinterpret_cast<char*>(m_dllData.data()), fileSize);
    if (file.gcount() != fileSize) {
        m_errorHandler->SetError(ErrorCode::PE_PARSE_FAILED, 
            "Failed to read DLL file: " + dllPath);
        return false;
    }

    file.close();

    // Parse PE headers
    if (!ParsePEHeaders()) {
        m_dllData.clear();
        return false;
    }

    m_errorHandler->ClearError();
    return true;
}

const BYTE* PEParser::GetDllData() const {
    return m_dllData.data();
}

MemorySize PEParser::GetDllSize() const {
    return m_dllData.size();
}

PIMAGE_DOS_HEADER PEParser::GetDosHeader() const {
    if (m_dllData.empty()) {
        return nullptr;
    }
    return reinterpret_cast<PIMAGE_DOS_HEADER>(const_cast<BYTE*>(m_dllData.data()));
}

void* PEParser::GetNtHeaders() const {
    PIMAGE_DOS_HEADER dosHeader = GetDosHeader();
    if (!dosHeader) {
        return nullptr;
    }
    
    return reinterpret_cast<void*>(const_cast<BYTE*>(m_dllData.data()) + dosHeader->e_lfanew);
}

PIMAGE_FILE_HEADER PEParser::GetFileHeader() const {
    if (m_is64Bit) {
        PIMAGE_NT_HEADERS64 ntHeaders = static_cast<PIMAGE_NT_HEADERS64>(GetNtHeaders());
        if (!ntHeaders) {
            return nullptr;
        }
        return &ntHeaders->FileHeader;
    } else {
        PIMAGE_NT_HEADERS32 ntHeaders = static_cast<PIMAGE_NT_HEADERS32>(GetNtHeaders());
        if (!ntHeaders) {
            return nullptr;
        }
        return &ntHeaders->FileHeader;
    }
}

void* PEParser::GetOptionalHeader() const {
    if (m_is64Bit) {
        PIMAGE_NT_HEADERS64 ntHeaders = static_cast<PIMAGE_NT_HEADERS64>(GetNtHeaders());
        if (!ntHeaders) {
            return nullptr;
        }
        return &ntHeaders->OptionalHeader;
    } else {
        PIMAGE_NT_HEADERS32 ntHeaders = static_cast<PIMAGE_NT_HEADERS32>(GetNtHeaders());
        if (!ntHeaders) {
            return nullptr;
        }
        return &ntHeaders->OptionalHeader;
    }
}

PIMAGE_SECTION_HEADER PEParser::GetSectionHeaders() const {
    PIMAGE_FILE_HEADER fileHeader = GetFileHeader();
    if (!fileHeader) {
        return nullptr;
    }
    
    // Section headers follow the optional header
    if (m_is64Bit) {
        PIMAGE_NT_HEADERS64 ntHeaders = static_cast<PIMAGE_NT_HEADERS64>(GetNtHeaders());
        return reinterpret_cast<PIMAGE_SECTION_HEADER>(
            reinterpret_cast<BYTE*>(ntHeaders) + 
            sizeof(DWORD) + 
            sizeof(IMAGE_FILE_HEADER) + 
            fileHeader->SizeOfOptionalHeader
        );
    } else {
        PIMAGE_NT_HEADERS32 ntHeaders = static_cast<PIMAGE_NT_HEADERS32>(GetNtHeaders());
        return reinterpret_cast<PIMAGE_SECTION_HEADER>(
            reinterpret_cast<BYTE*>(ntHeaders) + 
            sizeof(DWORD) + 
            sizeof(IMAGE_FILE_HEADER) + 
            fileHeader->SizeOfOptionalHeader
        );
    }
}

WORD PEParser::GetNumberOfSections() const {
    PIMAGE_FILE_HEADER fileHeader = GetFileHeader();
    if (!fileHeader) {
        return 0;
    }
    
    return fileHeader->NumberOfSections;
}

DWORD PEParser::GetSizeOfImage() const {
    if (m_is64Bit) {
        PIMAGE_OPTIONAL_HEADER64 optionalHeader = static_cast<PIMAGE_OPTIONAL_HEADER64>(GetOptionalHeader());
        if (!optionalHeader) {
            return 0;
        }
        return optionalHeader->SizeOfImage;
    } else {
        PIMAGE_OPTIONAL_HEADER32 optionalHeader = static_cast<PIMAGE_OPTIONAL_HEADER32>(GetOptionalHeader());
        if (!optionalHeader) {
            return 0;
        }
        return optionalHeader->SizeOfImage;
    }
}

DWORD PEParser::GetEntryPointRVA() const {
    if (m_is64Bit) {
        PIMAGE_OPTIONAL_HEADER64 optionalHeader = static_cast<PIMAGE_OPTIONAL_HEADER64>(GetOptionalHeader());
        if (!optionalHeader) {
            return 0;
        }
        return optionalHeader->AddressOfEntryPoint;
    } else {
        PIMAGE_OPTIONAL_HEADER32 optionalHeader = static_cast<PIMAGE_OPTIONAL_HEADER32>(GetOptionalHeader());
        if (!optionalHeader) {
            return 0;
        }
        return optionalHeader->AddressOfEntryPoint;
    }
}

ULONGLONG PEParser::GetImageBase() const {
    if (m_is64Bit) {
        PIMAGE_OPTIONAL_HEADER64 optionalHeader = static_cast<PIMAGE_OPTIONAL_HEADER64>(GetOptionalHeader());
        if (!optionalHeader) {
            return 0;
        }
        return optionalHeader->ImageBase;
    } else {
        PIMAGE_OPTIONAL_HEADER32 optionalHeader = static_cast<PIMAGE_OPTIONAL_HEADER32>(GetOptionalHeader());
        if (!optionalHeader) {
            return 0;
        }
        return optionalHeader->ImageBase;
    }
}

bool PEParser::Is64Bit() const {
    return m_is64Bit;
}

PIMAGE_DATA_DIRECTORY PEParser::GetDataDirectory(DWORD directoryEntry) const {
    if (directoryEntry >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) {
        return nullptr;
    }
    
    if (m_is64Bit) {
        PIMAGE_OPTIONAL_HEADER64 optionalHeader = static_cast<PIMAGE_OPTIONAL_HEADER64>(GetOptionalHeader());
        if (!optionalHeader) {
            return nullptr;
        }
        return &optionalHeader->DataDirectory[directoryEntry];
    } else {
        PIMAGE_OPTIONAL_HEADER32 optionalHeader = static_cast<PIMAGE_OPTIONAL_HEADER32>(GetOptionalHeader());
        if (!optionalHeader) {
            return nullptr;
        }
        return &optionalHeader->DataDirectory[directoryEntry];
    }
}

DWORD PEParser::RvaToFileOffset(DWORD rva) const {
    PIMAGE_SECTION_HEADER sectionHeaders = GetSectionHeaders();
    WORD numberOfSections = GetNumberOfSections();
    
    if (!sectionHeaders || numberOfSections == 0) {
        return 0;
    }
    
    // Find the section containing the RVA
    for (WORD i = 0; i < numberOfSections; i++) {
        DWORD sectionRva = sectionHeaders[i].VirtualAddress;
        DWORD sectionSize = sectionHeaders[i].Misc.VirtualSize;
        
        if (rva >= sectionRva && rva < sectionRva + sectionSize) {
            DWORD delta = rva - sectionRva;
            return sectionHeaders[i].PointerToRawData + delta;
        }
    }
    
    return 0;
}

void* PEParser::GetRvaPointer(DWORD rva) const {
    if (m_dllData.empty()) {
        return nullptr;
    }
    
    DWORD fileOffset = RvaToFileOffset(rva);
    if (fileOffset == 0 || fileOffset >= m_dllData.size()) {
        return nullptr;
    }
    
    return const_cast<BYTE*>(m_dllData.data()) + fileOffset;
}

bool PEParser::ParsePEHeaders() {
    // Check if the buffer is large enough to contain a DOS header
    if (m_dllData.size() < sizeof(IMAGE_DOS_HEADER)) {
        m_errorHandler->SetError(ErrorCode::PE_PARSE_FAILED, 
            "Invalid PE file: too small for DOS header");
        return false;
    }
    
    // Get the DOS header
    PIMAGE_DOS_HEADER dosHeader = GetDosHeader();
    
    // Check the DOS signature
    if (dosHeader->e_magic != 0x5A4D) { // 'MZ'
        m_errorHandler->SetError(ErrorCode::PE_PARSE_FAILED, 
            "Invalid PE file: DOS signature not found");
        return false;
    }
    
    // Check if the buffer is large enough to contain the NT headers
    if (m_dllData.size() < static_cast<size_t>(dosHeader->e_lfanew + sizeof(DWORD))) {
        m_errorHandler->SetError(ErrorCode::PE_PARSE_FAILED, 
            "Invalid PE file: too small for NT headers");
        return false;
    }
    
    // Get the NT headers signature
    DWORD* ntSignature = reinterpret_cast<DWORD*>(m_dllData.data() + dosHeader->e_lfanew);
    
    // Check the NT signature
    if (*ntSignature != 0x00004550) { // 'PE\0\0'
        m_errorHandler->SetError(ErrorCode::PE_PARSE_FAILED, 
            "Invalid PE file: NT signature not found");
        return false;
    }
    
    // Get the file header
    PIMAGE_FILE_HEADER fileHeader = reinterpret_cast<PIMAGE_FILE_HEADER>(ntSignature + 1);
    
    // Check the machine type to determine if it's 64-bit
    m_is64Bit = (fileHeader->Machine == 0x8664); // IMAGE_FILE_MACHINE_AMD64
    
    // Check if the buffer is large enough to contain the optional header
    size_t optionalHeaderOffset = dosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    size_t optionalHeaderSize = m_is64Bit ? sizeof(IMAGE_OPTIONAL_HEADER64) : sizeof(IMAGE_OPTIONAL_HEADER32);
    
    if (m_dllData.size() < optionalHeaderOffset + optionalHeaderSize) {
        m_errorHandler->SetError(ErrorCode::PE_PARSE_FAILED, 
            "Invalid PE file: too small for optional header");
        return false;
    }
    
    // Check if the buffer is large enough to contain the section headers
    size_t sectionHeadersOffset = optionalHeaderOffset + fileHeader->SizeOfOptionalHeader;
    size_t sectionHeadersSize = fileHeader->NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    
    if (m_dllData.size() < sectionHeadersOffset + sectionHeadersSize) {
        m_errorHandler->SetError(ErrorCode::PE_PARSE_FAILED, 
            "Invalid PE file: too small for section headers");
        return false;
    }
    
    // Verify the optional header magic
    WORD* optionalHeaderMagic = reinterpret_cast<WORD*>(m_dllData.data() + optionalHeaderOffset);
    WORD expectedMagic = m_is64Bit ? 0x020B : 0x010B; // IMAGE_NT_OPTIONAL_HDR64_MAGIC or IMAGE_NT_OPTIONAL_HDR32_MAGIC
    
    if (*optionalHeaderMagic != expectedMagic) {
        m_errorHandler->SetError(ErrorCode::PE_PARSE_FAILED, 
            "Invalid PE file: incorrect optional header magic");
        return false;
    }
    
    return true;
}

DWORD PEParser::GetFileSize(const std::string& filePath) const {
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        m_errorHandler->SetError(ErrorCode::FILE_NOT_FOUND, 
            "Failed to open file: " + filePath);
        return 0;
    }
    
    DWORD size = static_cast<DWORD>(file.tellg());
    file.close();
    
    return size;
}
