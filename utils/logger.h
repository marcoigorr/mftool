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

class Logger
{
public:
    enum class LogLevel {
        DEBUG   = 0,
        INFO    = 1,
        WARNING = 2,
        ERROR   = 3
    };

    static void setLogLevel(LogLevel level) { currentLogLevel = level; }
    static LogLevel getLogLevel()           { return currentLogLevel; }

    static void debug(const std::string& msg)
    {
        if (currentLogLevel <= LogLevel::DEBUG)
            std::cout << "[DEBUG] " << msg << "\n";
    }

    static void info(const std::string& msg)
    {
        if (currentLogLevel <= LogLevel::INFO)
            std::cout << "[INFO]  " << msg << "\n";
    }

    static void warning(const std::string& msg)
    {
        if (currentLogLevel <= LogLevel::WARNING)
            std::cout << "[WARN]  " << msg << "\n";
    }

    static void error(const std::string& msg)
    {
        if (currentLogLevel <= LogLevel::ERROR)
            std::cerr << "[ERROR] " << msg << "\n";
    }

private:
    static LogLevel currentLogLevel;
};