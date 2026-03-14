/**
 * @file value_block.cpp
 * @brief Implementazione della costruzione del Value Block MIFARE Classic.
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
#include "value_block.h"
#include <sstream>
#include <iomanip>


std::array<uint8_t, 16> ValueBlock::create(int32_t value, uint8_t address)
{
    std::array<uint8_t, 16> block{};

    block[0] = value & 0xFF;
    block[1] = (value >> 8) & 0xFF;
    block[2] = (value >> 16) & 0xFF;
    block[3] = (value >> 24) & 0xFF;

    block[4] = ~block[0];
    block[5] = ~block[1];
    block[6] = ~block[2];
    block[7] = ~block[3];

    block[8] = block[0];
    block[9] = block[1];
    block[10] = block[2];
    block[11] = block[3];

    block[12] = address;
    block[13] = ~address;
    block[14] = address;
    block[15] = ~address;

    return block;
}

std::string ValueBlock::summary(int32_t value, uint8_t address)
{
    const auto raw = create(value, address);

    std::ostringstream ss;
    ss << "    Value   : " << std::dec << value
       << "  0x" << std::uppercase << std::hex
       << std::setw(8) << std::setfill('0') << static_cast<uint32_t>(value) << "\n"
       << "    Address : " << std::dec << static_cast<int>(address)
       << "  0x" << std::uppercase << std::hex
       << std::setw(2) << std::setfill('0') << static_cast<int>(address) << "\n"
       << "    Raw     : ";

    for (size_t i = 0; i < raw.size(); ++i)
    {
        if (i > 0) ss << " ";
        ss << std::uppercase << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(raw[i]);
    }

    return ss.str();
}