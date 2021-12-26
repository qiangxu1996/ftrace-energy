#include<chrono>
#include<iostream>

int main(int argc, char const *argv[])
{
	auto now = std::chrono::steady_clock::now().time_since_epoch();
	auto us = std::chrono::duration_cast<std::chrono::microseconds>(now);
	std::cout << us.count() << std::endl;
	return 0;
}
