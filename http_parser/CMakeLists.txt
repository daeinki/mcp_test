cmake_minimum_required(VERSION 3.10)
project(http_parser)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find jsoncpp package
find_package(PkgConfig REQUIRED)
pkg_check_modules(JSONCPP REQUIRED jsoncpp)

include_directories(${JSONCPP_INCLUDE_DIRS})

add_executable(http_parser main.cpp)
target_link_libraries(http_parser ${JSONCPP_LIBRARIES})
