cmake_minimum_required(VERSION 3.10)
project(DNSResolver)

set(CMAKE_CXX_STANDARD 17)

include_directories(/usr/local/include)

link_directories(/usr/local/lib)

find_package(Poco REQUIRED COMPONENTS Util Net)

add_executable(dns_resolver main.cpp)

target_link_libraries(dns_resolver PRIVATE Poco::Util Poco::Net)
