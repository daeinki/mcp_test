cmake_minimum_required(VERSION 3.5)
project(MCPTransport)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(CURL REQUIRED)
# JsonCpp를 pkg-config를 통해 찾기
find_package(PkgConfig REQUIRED)
pkg_check_modules(JSONCPP REQUIRED jsoncpp)

include_directories(${CURL_INCLUDE_DIRS})
include_directories(${JSONCPP_INCLUDE_DIRS})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

# 프로젝트 내 모든 cpp 파일 추가
add_library(mcp-transport 
    src/HttpTransportServer.cpp
    src/HttpTransportClient.cpp
)

# 라이브러리 링크
target_link_libraries(mcp-transport 
    ${CURL_LIBRARIES} 
    ${JSONCPP_LIBRARIES} 
    pthread
)

# server executable
add_executable(server src/main_server.cpp)
target_link_libraries(server mcp-transport)

# client executable
add_executable(client src/main_client.cpp)
target_link_libraries(client mcp-transport)


add_executable(mcp_sse_server src/mcp_sse_server.cpp)
target_link_libraries(mcp_sse_server pthread)

add_executable(mcp_server_gpt src/mcp_server_gpt.cpp)
target_link_libraries(mcp_server_gpt pthread ${JSONCPP_LIBRARIES} )

add_executable(mcp_sse_ok src/mcp_sse_ok.cpp)
target_link_libraries(mcp_sse_ok pthread ${JSONCPP_LIBRARIES} )

