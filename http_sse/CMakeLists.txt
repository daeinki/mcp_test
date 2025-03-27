# CMakeLists.txt
cmake_minimum_required(VERSION 3.10)
project(McpTransport)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# jsoncpp 라이브러리 찾기
find_package(PkgConfig REQUIRED)
pkg_check_modules(JSONCPP REQUIRED jsoncpp)

# libcurl 라이브러리 찾기
find_package(CURL REQUIRED)

# 소스 파일 추가
set(SOURCES
    McpTransportClient.cpp
    McpTransportServer.cpp
    main.cpp
)

# 헤더 파일 추가
set(HEADERS
    McpTransport.h
)

# 실행 파일 생성
add_executable(mcp_test ${SOURCES} ${HEADERS})

# include 디렉토리 추가
target_include_directories(mcp_test PRIVATE ${JSONCPP_INCLUDE_DIRS} ${CURL_INCLUDE_DIRS})

# 라이브러리 링크
target_link_libraries(mcp_test ${JSONCPP_LIBRARIES} ${CURL_LIBRARIES} pthread)

# 설치 규칙 추가
install(TARGETS mcp_test DESTINATION bin)
