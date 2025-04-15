#include <Windows.h>
#include <iostream>

// Export functions
extern "C" {
    __declspec(dllexport) void HelloWorld();
    __declspec(dllexport) int Add(int a, int b);
    __declspec(dllexport) void MessageBoxTest();
}

// Global variables to demonstrate successful injection
HINSTANCE g_hInstance = NULL;
DWORD g_dwProcessId = 0;
char g_szModulePath[MAX_PATH] = { 0 };

// DLL entry point
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        // Save the instance handle
        g_hInstance = hinstDLL;
        
        // Get the process ID
        g_dwProcessId = GetCurrentProcessId();
        
        // Get the module path
        GetModuleFileNameA(hinstDLL, g_szModulePath, MAX_PATH);
        
        // Create a log file to verify injection
        char szLogPath[MAX_PATH] = { 0 };
        GetTempPathA(MAX_PATH, szLogPath);
        strcat_s(szLogPath, "injection_log.txt");
        
        FILE* pFile = NULL;
        fopen_s(&pFile, szLogPath, "w");
        if (pFile) {
            fprintf(pFile, "DLL injected successfully!\n");
            fprintf(pFile, "Process ID: %lu\n", g_dwProcessId);
            fprintf(pFile, "Module Path: %s\n", g_szModulePath);
            fclose(pFile);
        }
        
        break;
        
    case DLL_THREAD_ATTACH:
        break;
        
    case DLL_THREAD_DETACH:
        break;
        
    case DLL_PROCESS_DETACH:
        break;
    }
    
    return TRUE;
}

// Exported function implementations
void HelloWorld() {
    // Create a log file to verify function call
    char szLogPath[MAX_PATH] = { 0 };
    GetTempPathA(MAX_PATH, szLogPath);
    strcat_s(szLogPath, "hello_world_log.txt");
    
    FILE* pFile = NULL;
    fopen_s(&pFile, szLogPath, "w");
    if (pFile) {
        fprintf(pFile, "HelloWorld function called!\n");
        fprintf(pFile, "Process ID: %lu\n", g_dwProcessId);
        fclose(pFile);
    }
}

int Add(int a, int b) {
    // Create a log file to verify function call
    char szLogPath[MAX_PATH] = { 0 };
    GetTempPathA(MAX_PATH, szLogPath);
    strcat_s(szLogPath, "add_log.txt");
    
    FILE* pFile = NULL;
    fopen_s(&pFile, szLogPath, "w");
    if (pFile) {
        fprintf(pFile, "Add function called!\n");
        fprintf(pFile, "Parameters: %d, %d\n", a, b);
        fprintf(pFile, "Result: %d\n", a + b);
        fclose(pFile);
    }
    
    return a + b;
}

void MessageBoxTest() {
    // Show a message box to verify function call
    MessageBoxA(NULL, "DLL injection successful!", "Test DLL", MB_OK | MB_ICONINFORMATION);
    
    // Create a log file to verify function call
    char szLogPath[MAX_PATH] = { 0 };
    GetTempPathA(MAX_PATH, szLogPath);
    strcat_s(szLogPath, "messagebox_log.txt");
    
    FILE* pFile = NULL;
    fopen_s(&pFile, szLogPath, "w");
    if (pFile) {
        fprintf(pFile, "MessageBoxTest function called!\n");
        fprintf(pFile, "Process ID: %lu\n", g_dwProcessId);
        fclose(pFile);
    }
}
