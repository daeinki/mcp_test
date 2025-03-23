cmake_minimum_required(VERSION 3.10)
project(MCPValidatorTest)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find jsoncpp package
find_package(PkgConfig REQUIRED)
pkg_check_modules(JSONCPP REQUIRED jsoncpp)

# Add include directories
include_directories(${JSONCPP_INCLUDE_DIRS})

# Add source files
set(SOURCES
    main.cpp
    MCPValidator.cpp
    MCPClientValidator.cpp
    MCPServerValidator.cpp
)

# Add header files
set(HEADERS
    MCPValidator.h
    MCPClientValidator.h
    MCPServerValidator.h
)

# Add executable
add_executable(mcp_validator_test ${SOURCES} ${HEADERS})

# Link libraries
target_link_libraries(mcp_validator_test ${JSONCPP_LIBRARIES})

# Add installation target
install(TARGETS mcp_validator_test DESTINATION bin)
