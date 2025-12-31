#include "StackInspector.hpp"
#include <iostream>
#include <string>
#include <cstdlib>

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "usage: " << argv[0] 
                  << " <pid> <executable>\n";
        return 1;
    }

    pid_t pid = std::stoi(argv[1]);
    std::string exe = argv[2];

    StackInspector inspector(pid, exe);
    inspector.inspect(10);

    return 0;
}
