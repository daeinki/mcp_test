# CMakeLists.txt
cmake_minimum_required(VERSION 3.10)
project(FastMCP)

# Set C++ standard
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find JsonCpp
find_package(PkgConfig REQUIRED)
pkg_check_modules(JSONCPP jsoncpp)

# Check if JsonCpp was found
if(NOT JSONCPP_FOUND)
    message(FATAL_ERROR "JsonCpp not found. Please install libjsoncpp-dev.")
endif()

include_directories(${JSONCPP_INCLUDE_DIRS})
include_directories(include)

# Library sources
set(LIBRARY_SOURCES
    src/fastmcp.cpp
)

# Create the FastMCP library
add_library(fastmcp ${LIBRARY_SOURCES})
target_link_libraries(fastmcp ${JSONCPP_LIBRARIES})

# Create calculator example
add_executable(calculator_example examples/calculator_example.cpp)
target_link_libraries(calculator_example fastmcp ${JSONCPP_LIBRARIES})

# Google Test for unit testing
find_package(GTest)
if(GTEST_FOUND)
    enable_testing()
    include_directories(${GTEST_INCLUDE_DIRS})
    
    # Create test executable
    add_executable(fastmcp_test tests/fastmcp_test.cpp)
    target_link_libraries(fastmcp_test fastmcp ${JSONCPP_LIBRARIES} ${GTEST_LIBRARIES} pthread)
    
    # Add test
    add_test(NAME FastMCPTest COMMAND fastmcp_test)
else()
    message(WARNING "Google Test not found. Tests will not be built.")
endif()

# Installation
install(TARGETS fastmcp DESTINATION lib)
install(FILES include/fastmcp.h DESTINATION include)
