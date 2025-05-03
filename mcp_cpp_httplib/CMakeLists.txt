cmake_minimum_required(VERSION 3.5)
project(MCPTransport)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(CURL REQUIRED)
# JsonCpp를 pkg-config를 통해 찾기
find_package(PkgConfig REQUIRED)
pkg_check_modules(JSONCPP REQUIRED jsoncpp)

include_directories(${CURL_INCLUDE_DIRS})
include_directories(${JSONCPP_INCLUDE_DIRS})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

add_executable(mcp_cpp_httplib src/mcp_cpp_httplib.cpp)
target_link_libraries(mcp_cpp_httplib pthread ${JSONCPP_LIBRARIES} uuid)
