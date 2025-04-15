#pragma once

#include "common.h"
#include "utility.h"
#include "process_memory.h"

// Instead of redefining Windows structures, use the ones from Windows headers
// Only define constants or structures that aren't in standard Windows headers
#ifndef IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14
#endif

// PE Parser class for parsing PE files
class PEParser {
public:
    PEParser(ErrorHandler* errorHandler, NameRandomizer* nameRandomizer);
    ~PEParser();

    // Load a DLL file into memory
    bool LoadDll(const std::string& dllPath);
    
    // Get the loaded DLL data
    const BYTE* GetDllData() const;
    
    // Get the size of the loaded DLL
    MemorySize GetDllSize() const;
    
    // Get the DOS header
    PIMAGE_DOS_HEADER GetDosHeader() const;
    
    // Get the NT headers (32-bit or 64-bit)
    void* GetNtHeaders() const;
    
    // Get the file header
    PIMAGE_FILE_HEADER GetFileHeader() const;
    
    // Get the optional header (32-bit or 64-bit)
    void* GetOptionalHeader() const;
    
    // Get the section headers
    PIMAGE_SECTION_HEADER GetSectionHeaders() const;
    
    // Get the number of sections
    WORD GetNumberOfSections() const;
    
    // Get the size of the image
    DWORD GetSizeOfImage() const;
    
    // Get the entry point RVA
    DWORD GetEntryPointRVA() const;
    
    // Get the image base
    ULONGLONG GetImageBase() const;
    
    // Check if the DLL is 64-bit
    bool Is64Bit() const;
    
    // Get a data directory
    PIMAGE_DATA_DIRECTORY GetDataDirectory(DWORD directoryEntry) const;
    
    // Convert a relative virtual address (RVA) to a file offset
    DWORD RvaToFileOffset(DWORD rva) const;
    
    // Get a pointer to data at a specific RVA
    void* GetRvaPointer(DWORD rva) const;

private:
    ErrorHandler* m_errorHandler;
    NameRandomizer* m_nameRandomizer;
    
    std::vector<BYTE> m_dllData;
    bool m_is64Bit;
    
    // Internal helper methods
    bool ParsePEHeaders();
    DWORD GetFileSize(const std::string& filePath) const;
};

// Import Resolver class for resolving DLL imports
class ImportResolver {
public:
    ImportResolver(ErrorHandler* errorHandler, NameRandomizer* nameRandomizer, ProcessInterface* processInterface);
    ~ImportResolver();

    // Resolve imports for a manually mapped DLL
    bool ResolveImports(const PEParser* peParser, MemoryAddress baseAddress);
    
    // Get a function address by name
    MemoryAddress GetProcAddressByName(const std::string& moduleName, const std::string& functionName);
    
    // Get a function address by ordinal
    MemoryAddress GetProcAddressByOrdinal(const std::string& moduleName, WORD ordinal);
    
    // Calculate hash for a function name (for stealth)
    DWORD CalculateFunctionHash(const char* functionName) const;

private:
    ErrorHandler* m_errorHandler;
    NameRandomizer* m_nameRandomizer;
    ProcessInterface* m_processInterface;
    
    std::unordered_map<std::string, HMODULE> m_loadedModules;
    
    // Internal helper methods
    HMODULE LoadModuleInLocalProcess(const std::string& moduleName);
    MemoryAddress GetRemoteModuleHandle(const std::string& moduleName);
    MemoryAddress GetRemoteProcAddress(HMODULE localModule, MemoryAddress remoteModule, const char* functionName);
    MemoryAddress GetRemoteProcAddressByOrdinal(HMODULE localModule, MemoryAddress remoteModule, WORD ordinal);
};

// Manual Mapper class for mapping DLLs into target processes
class ManualMapper {
public:
    ManualMapper(ErrorHandler* errorHandler, NameRandomizer* nameRandomizer, 
                ProcessInterface* processInterface, MemoryManager* memoryManager);
    ~ManualMapper();

    // Map a DLL into the target process
    MemoryAddress MapDll(const PEParser* peParser);
    
    // Process relocations for the mapped DLL
    bool ProcessRelocations(const PEParser* peParser, MemoryAddress baseAddress, ULONGLONG deltaBase);
    
    // Process TLS callbacks
    bool ProcessTlsCallbacks(const PEParser* peParser, MemoryAddress baseAddress);
    
    // Initialize security cookie
    bool InitializeSecurityCookie(const PEParser* peParser, MemoryAddress baseAddress);
    
    // Clean up PE headers after mapping
    bool CleanupHeaders(MemoryAddress baseAddress);

private:
    ErrorHandler* m_errorHandler;
    NameRandomizer* m_nameRandomizer;
    ProcessInterface* m_processInterface;
    MemoryManager* m_memoryManager;
    ImportResolver* m_importResolver;
    
    // Internal helper methods
    DWORD GetSectionProtection(DWORD characteristics) const;
    bool MapSections(const PEParser* peParser, MemoryAddress baseAddress);
    bool ApplyRelocations(PIMAGE_BASE_RELOCATION relocationBlock, MemoryAddress baseAddress, ULONGLONG deltaBase, DWORD blockSize);
};
