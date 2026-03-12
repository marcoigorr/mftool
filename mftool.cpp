/**
 * @file mftool.cpp
 * @brief Punto di ingresso dell'applicazione mftool.
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
#include "cli/command_parser.h"
#include "utils/logger.h"


int main() {
    try {
        CommandParser parser;
        parser.run();
        return 0;
    }
    catch (const std::exception& e) {
        Logger::error(std::string("Unexpected error: ") + e.what());
        return 1;
    }
}