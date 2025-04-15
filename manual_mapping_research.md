# Manual Mapping Techniques Research

## Overview of Manual Mapping

Manual mapping is an advanced DLL injection technique that loads a DLL into a target process without using the standard Windows loader functions like LoadLibrary. This approach gives greater control over the loading process and can bypass many detection mechanisms that monitor standard API calls.

## PE File Format Understanding

To implement manual mapping, we need a deep understanding of the PE (Portable Executable) file format:

### PE Header Structure
- DOS Header: Contains the MZ signature and offset to PE header
- PE Header: Contains the PE signature and file characteristics
- Optional Header: Contains important data directories
- Section Headers: Define the layout of sections in the file

### Important Data Directories
- Export Directory: Contains exported functions
- Import Directory: Lists imported functions from other DLLs
- Relocation Directory: Contains base relocation information
- TLS Directory: Thread Local Storage callbacks
- Exception Directory: Exception handling information
- Load Config Directory: Load configuration

## Manual Mapping Process

The manual mapping process involves several key steps:

1. **Reading the DLL file**: Load the DLL file into the injector's memory
2. **Allocating memory in target process**: Allocate memory for the DLL in the target process
3. **Mapping sections**: Copy each section to the appropriate location in the allocated memory
4. **Performing relocations**: Adjust addresses based on the actual load address
5. **Resolving imports**: Find and link imported functions
6. **Handling TLS callbacks**: Execute Thread Local Storage callbacks if present
7. **Executing DllMain**: Call the DLL's entry point with DLL_PROCESS_ATTACH

## Advanced Evasion Techniques

### 1. Alternative Memory Allocation

Instead of using VirtualAllocEx, consider:
- Memory mapped files
- Shared memory sections
- Reusing existing memory regions
- Using NtMapViewOfSection instead of direct allocation

### 2. Stealthy Memory Writing

Instead of WriteProcessMemory:
- Use asynchronous I/O operations
- Implement custom memory writing using alternative APIs
- Use NtWriteVirtualMemory with obfuscated parameters
- Consider using shared memory sections to avoid explicit writes

### 3. Thread Execution Alternatives

Instead of CreateRemoteThread:
- Thread hijacking: Suspend an existing thread, modify its context, resume it
- APC (Asynchronous Procedure Call) injection
- Scheduler-based execution using SetWindowsHookEx
- Exception-based execution
- UI thread message queue injection

### 4. Import Resolution Techniques

- Implement custom GetProcAddress functionality
- Use hash-based function resolution
- Resolve imports at runtime rather than all at once
- Implement delayed resolution for less suspicious timing patterns

### 5. Syscall Implementation

- Direct syscall implementation to bypass user-mode hooks
- Dynamic syscall number resolution
- Syscall obfuscation techniques
- Syscall stack spoofing

### 6. Anti-Detection Measures

- Code obfuscation to avoid signature detection
- Timing variations to avoid behavioral detection
- Memory protection pattern variations
- Cleanup of PE headers after mapping
- String encryption for all paths and function names

## Novel Approach: Section Mapping Technique

A unique approach to manual mapping involves:

1. Creating a shared section object
2. Mapping the section into both the injector and target process
3. Writing the DLL into the shared section from the injector
4. Performing relocations and import resolution in the shared section
5. Executing the DLL using one of the thread execution alternatives

This approach minimizes suspicious API calls and memory patterns by:
- Reducing the number of memory allocations
- Eliminating the need for WriteProcessMemory
- Creating a more legitimate memory footprint
- Allowing for more natural memory protection transitions

## Architecture-Specific Considerations

### x86 (32-bit) Considerations
- Different structure alignments and sizes
- Different calling conventions
- Limited address space

### x64 (64-bit) Considerations
- Different relocation types
- Different exception handling
- Extended address space
- Additional security features

## Implementation Strategy

Based on the research, our implementation will:

1. Use a combination of section mapping and thread hijacking
2. Implement custom import resolution with hash-based function finding
3. Use direct syscalls for critical operations
4. Implement comprehensive PE parsing for both x86 and x64
5. Include robust error handling and cleanup
6. Incorporate randomization at multiple levels
7. Implement anti-forensic measures to remove evidence after injection
