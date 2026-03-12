/**
 * @file access_bits.cpp
 * @brief Implementazione della decodifica Access Bits MIFARE Classic.
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
#include "access_bits.h"


AccessBits AccessBits::decode(const std::vector<uint8_t>& t)
{
    AccessBits ab;

    // Servono almeno i byte 6-8 del trailer
    if (t.size() < 10) return ab;

    // Verifica della consistenza: ogni nibble deve essere il complemento del corrispondente
    ab.valid =
        ((t[6] & 0x0F) == ((~t[7] >> 4) & 0x0F)) &&
        ((t[6] >>  4)  == ((~t[8])       & 0x0F)) &&
        ((t[7] & 0x0F) == ((~t[8] >> 4)  & 0x0F));

    if (!ab.valid) return ab;

    for (int b = 0; b < 4; ++b)
    {
        ab.c1[b]  = (t[7] >> (4 + b)) & 1;
        ab.c2[b]  = (t[8] >>       b) & 1;
        ab.c3[b]  = (t[8] >> (4 + b)) & 1;
        ab.idx[b] = (ab.c1[b] << 2) | (ab.c2[b] << 1) | ab.c3[b];
    }

    return ab;
}

const char* AccessBits::dataDescShort(uint8_t index)
{
    // Formato: r:key w:key I:key D:key
	// r = read, w = write, I = increment, D = decrement/transfer/restore
    static const char* table[8] = {
        "r:A|B w:A|B I:A|B D:A|B",  // 0: transport
        "r:A|B w:-   I:-   D:A|B",  // 1: value (non-rechargeable)
        "r:A|B w:-   I:-   D:-  ",  // 2: read-only
        "r:B   w:B   I:-   D:-  ",  // 3
        "r:A|B w:B   I:-   D:-  ",  // 4
        "r:B   w:-   I:-   D:-  ",  // 5: read-only (B)
        "r:A|B w:B   I:B   D:A|B",  // 6: value block
        "r:-   w:-   I:-   D:-  ",  // 7: blocked
    };
    return (index < 8) ? table[index] : "?";
}

const char* AccessBits::trailerDescShort(uint8_t index)
{
    static const char* table[8] = {
        "KB-rw: A  acc-r: A  [KB readable]",      // 0: KeyB leggibile!
        "default  acc-rw: A  KB-rw: A",           // 1: default transport
        "acc-r: A  KB-r: A",                      // 2: no writes
        "KA-w: B  acc-r: A|B  acc-w: B  KB-w: B", // 3
        "KA-w: B  KB-w: B  acc-r: A|B",           // 4
        "acc-r: A|B  acc-w: B",                   // 5
        "write-protect  acc-r: A|B",              // 6
        "locked  acc-r: A|B",                     // 7
    };
    return (index < 8) ? table[index] : "?";
}

const char* AccessBits::dataDescFull(uint8_t index)
{
    // Stesso formato compatto di dataDescShort, con etichetta aggiuntiva
    static const char* table[8] = {
        "R:A|B W:A|B I:A|B D:A|B  [transport]",
        "R:A|B W:-   I:-   D:A|B  [value-NR]",
        "R:A|B W:-   I:-   D:-    [read-only]",
        "R:B   W:B   I:-   D:-  ",
        "R:A|B W:B   I:-   D:-  ",
        "R:B   W:-   I:-   D:-    [read-only B]",
        "R:A|B W:B   I:B   D:A|B  [value]",
        "R:-   W:-   I:-   D:-    [blocked]",
    };
    return (index < 8) ? table[index] : "?";
}

const char* AccessBits::trailerDescFull(uint8_t index)
{
    static const char* table[8] = {
        "KeyB readable  KA-w: A  acc-r: A  KB-rw: A",
        "default        acc-rw: A  KB-rw: A",
        "               acc-r: A  KB-r: A",
        "               KA-w: B  acc-r: A|B  acc-w: B  KB-w: B",
        "               KA-w: B  KB-w: B  acc-r: A|B",
        "               acc-r: A|B  acc-w: B",
        "write-protect  acc-r: A|B",
        "locked         acc-r: A|B",
    };
    return (index < 8) ? table[index] : "?";
}
