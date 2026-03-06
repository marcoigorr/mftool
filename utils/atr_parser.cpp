#include "atr_parser.h"
#include "hex.h"
#include <sstream>
#include <iomanip>

std::string ATRParser::getCardType(const std::vector<uint8_t>& atr) {
    if (atr.empty()) {
        return "Unknown";
    }

    // Struttura ATR:
    // [0]=Initial Header, [1]=T0, [2]=TD1, [3]=TD2, [4]=T1, [5]=Tk, [6]=Length,
    // [7-9]=RID, [10-12]=Standard, [13-14]=Card Name, [15-17]=RFU, [18-19]=Reserved, [20]=TCK

    if (atr.size() < 15) {
        return "Unknown";
    }

    // Verifica header MIFARE
    if (atr[0] == 0x3B && atr[1] == 0x8F && atr[2] == 0x80) {
        
        // Controlla i byte 13-14 (Card Name)
        uint8_t cardId = atr[13];
        uint8_t cardSubId = atr[14];

        if (cardId == 0x00) {
            switch (cardSubId) {
                case 0x01:
                    return "MIFARE Classic 1K";
                case 0x02:
                    return "MIFARE Classic 4K";
                case 0x03:
                    return "MIFARE Ultralight";
                case 0x26:
                    return "MIFARE Mini";
                default:
                    return "MIFARE Type";
            }
        }
    }

    // ISO-DEP (NFC-A) generico
    if (atr[0] == 0x3B) {
        return "ISO-DEP (NFC-A)";
    }

    return "Unknown Card Type";
}
