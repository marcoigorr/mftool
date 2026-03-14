/**
 * @file block_type.cpp
 * @brief Implementazione del rilevamento del tipo di blocco MIFARE Classic.
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
#include "block_type.h"


BlockType detectBlockType(int sector, int relBlock, const std::vector<uint8_t>& data)
{
    // Il blocco 0 del settore 0 è sempre il Manufacturer Block
    if (sector == 0 && relBlock == 0) return BlockType::Manufacturer;

    // Il blocco 3 di ogni settore è sempre il Sector Trailer
    if (relBlock == 3)                return BlockType::Trailer;

    // Verifica struttura Value Block (spec MIFARE Classic):
    //   byte[0..3]  = valore (little-endian)
    //   byte[4..7]  = ~valore
    //   byte[8..11] = valore (copia)
    //   byte[12,14] = indirizzo
    //   byte[13,15] = ~indirizzo
    if (data.size() == 16)
    {
        bool is_value = true;
        for (int i = 0; i < 4 && is_value; ++i)
        {
            if (data[i] != data[i + 8])           is_value = false;
            if (data[i] != (uint8_t)~data[i + 4]) is_value = false;
        }
        if (data[12] != data[14])            is_value = false;
        if (data[12] != (uint8_t)~data[13]) is_value = false;

        if (is_value) return BlockType::Value;
    }

    return BlockType::Data;
}

const char* blockTypeLabel(BlockType type)
{
    switch (type)
    {
        case BlockType::Manufacturer: return "Manufacturer Block  [read-only]";
        case BlockType::Trailer:      return "Sector Trailer";
        case BlockType::Value:        return "Value Block";
        case BlockType::Data:         return "Data Block";
    }
    return "Unknown";
}