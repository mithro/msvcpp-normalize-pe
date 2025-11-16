// tests/fixtures/sources/complex.cpp
// Realistic program for testing PE with imports and multiple sections
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <numeric>

int compute(const std::vector<int>& data) {
    return std::accumulate(data.begin(), data.end(), 0);
}

int main() {
    std::vector<int> numbers = {1, 2, 3, 4, 5};
    std::cout << "Sum: " << compute(numbers) << std::endl;
    return 0;
}
