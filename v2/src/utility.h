#pragma once

#include "common.h"

// Error Handler class for managing errors
class ErrorHandler {
public:
    ErrorHandler();
    ~ErrorHandler();

    // Set an error
    void SetError(ErrorCode code, const std::string& message);
    
    // Set an error with Windows error code
    void SetLastWinError(ErrorCode code, const std::string& message);
    
    // Get the last error
    ErrorInfo GetLastError() const;
    
    // Get the last error message
    std::string GetLastErrorMessage() const;
    
    // Check if there is an error
    bool HasError() const;
    
    // Clear the last error
    void ClearError();

private:
    ErrorInfo m_lastError;
    bool m_hasError;
};

// Name Randomizer class for generating random names
class NameRandomizer {
public:
    NameRandomizer();
    ~NameRandomizer();

    // Generate a random name
    std::string GenerateRandomName(size_t minLength = MIN_RANDOM_NAME_LENGTH, 
                                  size_t maxLength = MAX_RANDOM_NAME_LENGTH) const;
    
    // Generate a random file name with extension
    std::string GenerateRandomFileName(const std::string& extension) const;
    
    // Generate a random path in the temp directory
    std::string GenerateRandomTempPath(const std::string& extension) const;
    
    // Generate a random memory offset
    uint32_t GenerateRandomOffset(uint32_t min, uint32_t max) const;
    
    // Generate a random delay
    uint32_t GenerateRandomDelay(uint32_t minMs, uint32_t maxMs) const;
    
    // Apply a random delay
    void ApplyRandomDelay(uint32_t minMs, uint32_t maxMs) const;

private:
    // Internal helper methods
    char GetRandomChar() const;
    std::string GetTempDirectory() const;
};
