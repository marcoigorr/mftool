#include "atr_parser.h"
#include "hex.h"
#include <sstream>
#include <iomanip>

std::string ATRParser::getCardType(const std::vector<uint8_t>& atr) {
    if (atr.empty()) {
        return "Unknown";
    }

    // Identifica il tipo di card dall'ATR
    // MIFARE Ultralight: 3B 8F 80 01 80 4F 0C A0 00 00 03 06 ...
    // MIFARE Classic 1K: 3B 8F 80 01 80 4F 0C A0 00 00 03 06 ...
    // ISO-DEP (NFC-A): 3B 8F 80 01 80 4F ...

    std::string atrHex = Hex::bytesToString(atr);

    if (atrHex.find("3B 8F 80") == 0) {
        if (atrHex.find("03 06") != std::string::npos) {
            return "MIFARE Ultralight / Classic";
        }
        return "MIFARE Type";
    }

    if (atrHex.find("3B") == 0) {
        return "ISO-DEP (NFC-A)";
    }

    return "Unknown Card Type";
}
