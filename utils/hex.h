#pragma once
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>

class Hex
{
public:

    /*
    toString()

    Converte array byte in stringa esadecimale.
    */
    static std::string bytesToString(const std::vector<uint8_t>& bytes) {
        std::stringstream ss;
        ss << std::uppercase << std::hex;
        for (size_t i = 0; i < bytes.size(); i++) {
            if (i > 0) ss << " ";  // Aggiungi spazio tra i byte
            ss << std::setw(2) << std::setfill('0') << (int)bytes[i];
        }
        return ss.str();
    }
};
