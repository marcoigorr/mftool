#include "atr_parser.h"
#include "hex.h"
#include <sstream>
#include <iomanip>

// ---------------------------------------------------------------------------
// getCardType
//
// Identifica il tipo di carta dal ATR generato dall'ACR122U.
//
// Struttura ATR per carte ISO 14443-A (NXP) su ACR122U (20 byte):
//   3B 8F 80 01 80 4F 0C A0 00 00 03 06 [D0] [D1] [D2] [D3] [D4] [D5] [D6] [TCK]
//
// Il byte D2 (indice 14) identifica il tipo di carta:
//   0x01 = MIFARE Classic 1K
//   0x02 = MIFARE Classic 4K
//   0x03 = MIFARE Ultralight / NTAG
//   0x04 = MIFARE Classic Mini
//   0x10 = MIFARE DESFire
//
// Riferimento: ACR122U Application Programming Interface V2.04
// ---------------------------------------------------------------------------
std::string ATRParser::getCardType(const std::vector<uint8_t>& atr)
{
    if (atr.empty())
        return "Unknown";

    // ATR standard ACR122U per carte NXP ISO 14443-A = 20 byte
    // Header fisso: 3B 8F 80 01 80 4F 0C A0 00 00 03 06
    const std::vector<uint8_t> nxpHeader = {
        0x3B, 0x8F, 0x80, 0x01, 0x80, 0x4F, 0x0C,
        0xA0, 0x00, 0x00, 0x03, 0x06
    };

    if (atr.size() == 20 &&
        std::equal(nxpHeader.begin(), nxpHeader.end(), atr.begin()))
    {
        // Byte all'indice 14 = tipo carta
        switch (atr[14])
        {
            case 0x01: return "MIFARE Classic 1K";
            case 0x02: return "MIFARE Classic 4K";
            case 0x03: return "MIFARE Ultralight / NTAG";
            case 0x04: return "MIFARE Classic Mini";
            case 0x10: return "MIFARE DESFire";
            default:   return "NXP ISO 14443-A (unknown subtype)";
        }
    }

    // ATR MIFARE DESFire (formato breve)
    if (atr.size() >= 4 && atr[0] == 0x3B && atr[1] == 0x81)
        return "MIFARE DESFire";

    // ATR generico ISO 14443-B
    if (atr.size() >= 1 && atr[0] == 0x3B)
        return "ISO 14443-B Card";

    return "Unknown Card Type (ATR: " + Hex::bytesToString(atr) + ")";
}
