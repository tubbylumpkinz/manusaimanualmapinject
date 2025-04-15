# DLL Injector Requirements Analysis

## Core Requirements
1. Create a DLL injector for Windows 11
2. Support injection into running processes
3. Implement manual mapping instead of using LoadLibrary
4. Support both x32 and x64 architectures
5. Include comprehensive error handling
6. Randomize DLL and injector names

## Detection Methods to Avoid

### 1. API Hooking/Monitoring
Security tools monitor key Windows APIs:
- CreateRemoteThread / NtCreateThreadEx
- VirtualAllocEx + WriteProcessMemory
- LoadLibrary and related functions

### 2. Behavioral Analysis
EDRs profile normal process behavior:
- Unusual process activity patterns
- Memory protection changes (e.g., PAGE_READWRITE to PAGE_EXECUTE_READ)
- Suspicious imported functions (LoadLibraryA, direct syscalls)

### 3. Memory Scanning
Security tools scan process memory:
- Known DLL paths as strings
- Shellcode signatures
- Unbacked executable memory regions

### 4. Thread Execution Flags
Windows 10/11 tracks thread origins:
- MEMORY_REMOTE_THREAD flags in kernel
- Thread creation monitoring

### 5. Handle Privilege Analysis
Tools audit process handles:
- PROCESS_ALL_ACCESS handles
- Unusual handle duplication

### 6. User-Mode Hooking (UMH)
EDRs inject agents into processes:
- Inline hooking of key functions
- Exception handler monitoring

### 7. Kernel-Mode Callbacks
EDRs use kernel drivers:
- Process creation notifications
- Image load notifications
- Thread creation notifications

### 8. Static Analysis
Disk-based detection:
- Signature detection
- Packer detection

### 9. Anomaly Detection (Machine Learning)
ML-based detection:
- Temporal patterns of API calls
- Rare combinations of operations

### 10. Syscall Stack Analysis
Direct syscall detection:
- Syscall origin verification
- Unbacked return addresses

## Evasion Strategy Requirements

1. **Process Access**
   - Avoid using high-privilege handles when possible
   - Minimize handle lifetime
   - Consider alternative process access methods

2. **Memory Operations**
   - Implement staggered memory operations
   - Use legitimate memory protection patterns
   - Avoid common shellcode signatures

3. **Thread Creation**
   - Explore alternatives to CreateRemoteThread
   - Consider hijacking existing threads
   - Implement asynchronous execution methods

4. **Import Resolution**
   - Implement custom GetProcAddress functionality
   - Avoid direct imports of suspicious functions
   - Use dynamic function resolution

5. **Code Execution**
   - Implement alternative execution techniques
   - Avoid suspicious execution patterns
   - Consider legitimate code paths for execution

6. **Randomization**
   - Randomize memory allocation sizes and locations
   - Implement timing variations
   - Randomize all string constants and signatures

7. **Error Handling**
   - Implement clean error recovery
   - Avoid leaving detectable artifacts on failure
   - Ensure proper cleanup of resources

## Implementation Constraints

1. Must work on Windows 11 (latest builds)
2. Must support both x32 and x64 architectures
3. Must handle various DLL types and dependencies
4. Must provide detailed error information without exposing operation
5. Must implement randomization of names and signatures
6. Must clean up all traces after successful or failed injection
