#pragma once
#include <iostream>

class Logger
{
public:
    /**
     * @brief Log di debug (dettagli tecnici per sviluppatori)
     * Colore: Cyan
     */
    static void debug(const std::string& msg)
    {
        std::cout << "\033[36m[DEBUG]\033[0m " << msg << std::endl;
    }

    /**
     * @brief Log informativo (operazioni normali)
     * Colore: Verde
     */
    static void info(const std::string& msg)
    {
        std::cout << "\033[32m[INFO]\033[0m " << msg << std::endl;
    }

    /**
     * @brief Log di warning (attenzione, potenziale problema)
     * Colore: Giallo
     */
    static void warning(const std::string& msg)
    {
        std::cout << "\033[33m[WARNING]\033[0m " << msg << std::endl;
    }

    /**
     * @brief Log di errore (operazione fallita)
     * Colore: Rosso
     */
    static void error(const std::string& msg)
    {
        std::cerr << "\033[31m[ERROR]\033[0m " << msg << std::endl;
    }
};