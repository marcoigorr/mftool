/**
 * @file logger.h
 * @brief Classe Logger per la stampa di messaggi diagnostici con livelli di severità.
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
#pragma once
#include <iostream>
#include <string>

// Undefine Windows macros that conflict with our enum values
#ifdef ERROR
    #undef ERROR
#endif
#ifdef DEBUG
    #undef DEBUG
#endif
#ifdef WARNING
    #undef WARNING
#endif
#ifdef INFO
    #undef INFO
#endif

/**
 * @brief Logger statico con filtraggio per livello di severità.
 *
 * Tutti i metodi sono statici; non è necessario istanziare la classe.
 * Il livello corrente filtra i messaggi con priorità inferiore.
 */
class Logger
{
public:
    /**
     * @brief Livelli di severità del log, in ordine crescente.
     */
    enum class LogLevel {
        DEBUG   = 0, ///< Messaggi di debug dettagliati.
        INFO    = 1, ///< Informazioni operative generali.
        WARNING = 2, ///< Avvisi non bloccanti.
        ERROR   = 3  ///< Errori che compromettono l'operazione corrente.
    };

    /**
     * @brief Imposta il livello minimo di log visualizzato.
     *
     * @param level Livello di soglia; i messaggi con priorità inferiore vengono soppressi.
     */
    static void setLogLevel(LogLevel level) { m_currentLogLevel = level; }

    /**
     * @brief Restituisce il livello di log attualmente attivo.
     *
     * @return Livello di log corrente.
     */
    static LogLevel getLogLevel() { return m_currentLogLevel; }

    /**
     * @brief Stampa un messaggio di debug su stdout (solo se il livello è DEBUG).
     *
     * @param msg Testo del messaggio.
     */
    static void debug(const std::string& msg)
    {
        if (m_currentLogLevel <= LogLevel::DEBUG)
            std::cout << "[DEBUG] " << msg << "\n";
    }

    /**
     * @brief Stampa un messaggio informativo su stdout (se il livello è <= INFO).
     *
     * @param msg Testo del messaggio.
     */
    static void info(const std::string& msg)
    {
        if (m_currentLogLevel <= LogLevel::INFO)
            std::cout << "[INFO]  " << msg << "\n";
    }

    /**
     * @brief Stampa un avviso su stdout (se il livello è <= WARNING).
     *
     * @param msg Testo del messaggio.
     */
    static void warning(const std::string& msg)
    {
        if (m_currentLogLevel <= LogLevel::WARNING)
            std::cout << "[WARN]  " << msg << "\n";
    }

    /**
     * @brief Stampa un messaggio di errore su stderr (se il livello è <= ERROR).
     *
     * @param msg Testo del messaggio.
     */
    static void error(const std::string& msg)
    {
        if (m_currentLogLevel <= LogLevel::ERROR)
            std::cerr << "[ERROR] " << msg << "\n";
    }

private:
    static Logger::LogLevel m_currentLogLevel; ///< Livello di log corrente (default: DEBUG).
};