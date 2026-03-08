#pragma once
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <cctype>

class Hex
{
public:
    // ---------------------------------------------------------------------------
    // bytesToString
    //
    // Converte un array di byte in stringa esadecimale uppercase separata da spazi.
    // Esempio: {0xFF, 0x0A} -> "FF 0A"
    // ---------------------------------------------------------------------------
    static std::string bytesToString(const std::vector<uint8_t>& bytes)
    {
        std::stringstream ss;
        ss << std::uppercase << std::hex;
        for (size_t i = 0; i < bytes.size(); ++i)
        {
            if (i > 0) ss << " ";
            ss << std::setw(2) << std::setfill('0') << (int)bytes[i];
        }
        return ss.str();
    }

    // ---------------------------------------------------------------------------
    // stringToBytes
    //
    // Converte una stringa esadecimale in array di byte.
    // Accetta formati con o senza spazi: "FF0A" oppure "FF 0A" oppure "FF:0A"
    // Lancia std::invalid_argument se la stringa contiene caratteri non hex
    // o ha lunghezza dispari (dopo aver rimosso i separatori).
    // Esempio: "FF 0A 3B" -> {0xFF, 0x0A, 0x3B}
    // ---------------------------------------------------------------------------
    static std::vector<uint8_t> stringToBytes(const std::string& hex)
    {
        // Rimuovi spazi e separatori comuni
        std::string clean;
        for (char c : hex)
        {
            if (c == ' ' || c == ':' || c == '-') continue;
            if (!std::isxdigit((unsigned char)c))
                throw std::invalid_argument("Carattere non hex: " + std::string(1, c));
            clean += (char)std::toupper((unsigned char)c);
        }

        if (clean.size() % 2 != 0)
            throw std::invalid_argument("Stringa hex di lunghezza dispari");

        std::vector<uint8_t> bytes;
        bytes.reserve(clean.size() / 2);
        for (size_t i = 0; i < clean.size(); i += 2)
            bytes.push_back(static_cast<uint8_t>(std::stoul(clean.substr(i, 2), nullptr, 16)));

        return bytes;
    }
};

