/**
 * @file hex.cpp
 * @brief Implementazione delle funzioni di conversione esadecimale della classe Hex.
 *
 * Copyright (C) 2026 Marco Petronio
 *
 * This file is part of mftool.
 *
 * mftool is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mftool is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with mftool. If not, see <https://www.gnu.org/licenses/>.
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