#pragma once
#include <vector>
#include <string>
#include <cstdint>

class ATRParser {
public:
    /*
    getCardType()

    Determina il tipo di card dall'ATR.
    */
    static std::string getCardType(const std::vector<uint8_t>& atr);

    /*
    toString()

    Converte ATR in stringa formattata.
    */
    // static std::string toString(const std::vector<uint8_t>& atr);
};