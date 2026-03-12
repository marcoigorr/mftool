/**
 * @file hex.cpp
 * @brief Implementazione delle funzioni di conversione esadecimale della classe Hex.
 */
#include "hex.h"
#include <stdexcept>
#include <cctype>


MifareKey Hex::stringToBytes(const std::string& hex)
{
    // Rimuovi spazi e converti a uppercase
    std::string cleaned;
    for (char c : hex)
    {
        if (!std::isspace(c))
            cleaned += static_cast<char>(std::toupper(c));
    }
    
    // Verifica lunghezza (deve essere 12 caratteri hex = 6 byte)
    if (cleaned.length() != 12)
    {
        throw std::invalid_argument(
            "Invalid key length: expected 12 hex chars (6 bytes), got " + 
            std::to_string(cleaned.length())
        );
    }
    
    // Verifica caratteri validi
    for (char c : cleaned)
    {
        if (!std::isxdigit(c))
        {
            throw std::invalid_argument(
                std::string("Invalid hex character: '") + c + "'"
            );
        }
    }
    
    // Conversione
    MifareKey result{};
    for (size_t i = 0; i < 6; ++i)
    {
        std::string byteStr = cleaned.substr(i * 2, 2);
        result[i] = static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16));
    }
    
    return result;
}

std::string Hex::bytesToString(const MifareKey& bytes, bool withSpaces)
{
    std::ostringstream ss;
    ss << std::uppercase << std::hex << std::setfill('0');
    
    for (size_t i = 0; i < bytes.size(); ++i)
    {
        if (i > 0 && withSpaces)
            ss << " ";
        ss << std::setw(2) << static_cast<int>(bytes[i]);
    }
    
    return ss.str();
}

std::string Hex::bytesToString(const std::vector<uint8_t>& bytes, bool withSpaces)
{
    std::ostringstream ss;
    ss << std::uppercase << std::hex << std::setfill('0');
    
    for (size_t i = 0; i < bytes.size(); ++i)
    {
        if (i > 0 && withSpaces)
            ss << " ";
        ss << std::setw(2) << static_cast<int>(bytes[i]);
    }
    
    return ss.str();
}