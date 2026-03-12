/**
 * @file logger.cpp
 * @brief Definizione della variabile statica del livello di log della classe Logger.
 */
#include "logger.h"

// Livello di log predefinito all'avvio dell'applicazione.
Logger::LogLevel Logger::currentLogLevel = Logger::LogLevel::DEBUG;
