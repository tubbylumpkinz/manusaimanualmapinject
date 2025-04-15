#include "fixed_utility.h"

// Implementation of ErrorHandler class
ErrorHandler::ErrorHandler() : m_hasError(false) {
    m_lastError.code = ErrorCode::SUCCESS;
    m_lastError.message = "No error";
    m_lastError.lastWinError = 0;
}

ErrorHandler::~ErrorHandler() {
}

void ErrorHandler::SetError(ErrorCode code, const std::string& message) {
    m_lastError.code = code;
    m_lastError.message = message;
    m_lastError.lastWinError = 0;
    m_hasError = true;
}

void ErrorHandler::SetLastWinError(ErrorCode code, const std::string& message) {
    m_lastError.code = code;
    m_lastError.message = message;
    m_lastError.lastWinError = GetLastError();
    m_hasError = true;
}

ErrorInfo ErrorHandler::GetLastError() const {
    return m_lastError;
}

std::string ErrorHandler::GetLastErrorMessage() const {
    std::string errorMsg = m_lastError.message;
    
    if (m_lastError.lastWinError != 0) {
        char winErrorMsg[256] = {0};
        FormatMessageA(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            m_lastError.lastWinError,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            winErrorMsg,
            sizeof(winErrorMsg),
            NULL
        );
        
        errorMsg += " (Windows Error: " + std::string(winErrorMsg) + ")";
    }
    
    return errorMsg;
}

bool ErrorHandler::HasError() const {
    return m_hasError;
}

void ErrorHandler::ClearError() {
    m_lastError.code = ErrorCode::SUCCESS;
    m_lastError.message = "No error";
    m_lastError.lastWinError = 0;
    m_hasError = false;
}

// Implementation of NameRandomizer class
NameRandomizer::NameRandomizer() {
    // Seed the random number generator
    srand(static_cast<unsigned int>(time(NULL)));
}

NameRandomizer::~NameRandomizer() {
}

std::string NameRandomizer::GenerateRandomName(size_t minLength, size_t maxLength) const {
    size_t length = Utils::GetRandomNumber(minLength, maxLength);
    std::string name;
    name.reserve(length);
    
    for (size_t i = 0; i < length; ++i) {
        name += GetRandomChar();
    }
    
    return name;
}

std::string NameRandomizer::GenerateRandomFileName(const std::string& extension) const {
    std::string fileName = GenerateRandomName();
    
    if (!extension.empty()) {
        if (extension[0] != '.') {
            fileName += '.';
        }
        fileName += extension;
    }
    
    return fileName;
}

std::string NameRandomizer::GenerateRandomTempPath(const std::string& extension) const {
    std::string tempDir = GetTempDirectory();
    std::string fileName = GenerateRandomFileName(extension);
    
    return tempDir + "\\" + fileName;
}

uint32_t NameRandomizer::GenerateRandomOffset(uint32_t min, uint32_t max) const {
    return Utils::GetRandomNumber(min, max);
}

uint32_t NameRandomizer::GenerateRandomDelay(uint32_t minMs, uint32_t maxMs) const {
    return Utils::GetRandomNumber(minMs, maxMs);
}

void NameRandomizer::ApplyRandomDelay(uint32_t minMs, uint32_t maxMs) const {
    Utils::RandomSleep(minMs, maxMs);
}

char NameRandomizer::GetRandomChar() const {
    // Generate a random alphanumeric character
    static const char charset[] = 
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    
    return charset[Utils::GetRandomNumber(0, sizeof(charset) - 2)];
}

std::string NameRandomizer::GetTempDirectory() const {
    char tempPath[MAX_PATH] = {0};
    GetTempPathA(MAX_PATH, tempPath);
    return std::string(tempPath);
}
