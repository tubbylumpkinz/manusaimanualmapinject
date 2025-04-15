#include <Windows.h>
#include <iostream>
#include <string>

// Simple target process for testing DLL injection
int main(int argc, char* argv[]) {
    std::cout << "Target process started. Process ID: " << GetCurrentProcessId() << std::endl;
    std::cout << "Waiting for DLL injection..." << std::endl;
    
    // Create a log file to verify process execution
    char szLogPath[MAX_PATH] = { 0 };
    GetTempPathA(MAX_PATH, szLogPath);
    strcat_s(szLogPath, "target_process_log.txt");
    
    FILE* pFile = NULL;
    fopen_s(&pFile, szLogPath, "w");
    if (pFile) {
        fprintf(pFile, "Target process started!\n");
        fprintf(pFile, "Process ID: %lu\n", GetCurrentProcessId());
        fclose(pFile);
    }
    
    // Wait indefinitely for DLL injection
    while (true) {
        Sleep(1000);
        std::cout << "." << std::flush;
    }
    
    return 0;
}
