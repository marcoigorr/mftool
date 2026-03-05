#pragma once
#include <string>
#include <memory>

class PCSCReader;

class CommandParser
{
public:
    CommandParser();
    ~CommandParser();

    void run();

private:
    std::unique_ptr<PCSCReader> reader;

    void showHelp() const;
    bool initializeReader();
};
