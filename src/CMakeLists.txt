cmake_minimum_required(VERSION 3.16)
project(LogSOCAgent CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include nlohmann/json from deps/
include_directories(${CMAKE_SOURCE_DIR}/deps)

# Find libcurl
find_package(CURL REQUIRED)

add_executable(agent agent.cpp)
target_link_libraries(agent CURL::libcurl)

# Windows-specific: link ws2_32 for libcurl static builds
if(WIN32)
    target_link_libraries(agent ws2_32)
endif()

# Install
install(TARGETS agent DESTINATION bin)
