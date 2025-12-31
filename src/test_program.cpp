#include <iostream>
#include <thread>
#include <chrono>

int work(int x) {
    return x * 2;
}

int main() {
    int a = 21;
    int b = work(a);
    std::cout << b << std::endl;

    while (true)
        std::this_thread::sleep_for(std::chrono::seconds(1));
}
