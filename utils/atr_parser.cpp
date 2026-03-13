/**
 * @file atr_parser.cpp
 * @brief Implementazione del parser ATR per l'identificazione del tipo di carta NFC.
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
#include "atr_parser.h"
#include "hex.h"


std::string ATRParser::getCardType(const std::vector<uint8_t>& atr)
{
    if (atr.empty())
        return "Unknown";

    // ATR standard ACR122U per carte NXP ISO 14443-A = 20 byte
    // Header fisso: 3B 8F 80 01 80 4F 0C A0 00 00 03 06
    const std::vector<uint8_t> nxp_header = {
        0x3B, 0x8F, 0x80, 0x01, 0x80, 0x4F, 0x0C,
        0xA0, 0x00, 0x00, 0x03, 0x06
    };

    if (atr.size() == 20 &&
        std::equal(nxp_header.begin(), nxp_header.end(), atr.begin()))
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
