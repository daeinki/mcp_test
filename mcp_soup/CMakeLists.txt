cmake_minimum_required(VERSION 3.5)
project(mcp_server)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)

# libsoup-2.4, glib-2.0, jsoncpp via pkg-config
pkg_check_modules(LIBSOUP REQUIRED libsoup-3.0)
pkg_check_modules(GLIB    REQUIRED glib-2.0)
pkg_check_modules(JSONCPP REQUIRED jsoncpp)

# Include dirs from pkg-config
include_directories(
  ${LIBSOUP_INCLUDE_DIRS}
  ${GLIB_INCLUDE_DIRS}
  ${JSONCPP_INCLUDE_DIRS}
)

# Library search paths
link_directories(
  ${LIBSOUP_LIBRARY_DIRS}
  ${GLIB_LIBRARY_DIRS}
  ${JSONCPP_LIBRARY_DIRS}
)

# Our executable
add_executable(mcp_server server.cpp)

# Respect any extra compile flags (e.g. -pthread, warning flags)
target_compile_options(mcp_server PRIVATE
  ${LIBSOUP_CFLAGS_OTHER}
  ${GLIB_CFLAGS_OTHER}
  ${JSONCPP_CFLAGS_OTHER}
)

# Link against libsoup, glib, jsoncpp
target_link_libraries(mcp_server PRIVATE
  ${LIBSOUP_LIBRARIES}
  ${GLIB_LIBRARIES}
  ${JSONCPP_LIBRARIES}
)
