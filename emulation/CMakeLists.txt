cmake_minimum_required(VERSION 3.10)
project(MCPSimulation)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find jsoncpp package
find_package(PkgConfig REQUIRED)
pkg_check_modules(JSONCPP REQUIRED jsoncpp)

include_directories(${JSONCPP_INCLUDE_DIRS})

add_executable(mcp_simulation main.cpp)
target_link_libraries(mcp_simulation ${JSONCPP_LIBRARIES})
