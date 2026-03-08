#include "cli/command_parser.h"
#include "utils/logger.h"


int main() {
    try {
		CommandParser parser;
		parser.run2();
		return 0;
	}
	catch (const std::exception& e) {
		Logger::error(std::string("Unexpected error: ") + e.what());
		return 1;
	}
}