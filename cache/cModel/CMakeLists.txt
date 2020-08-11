cmake_minimum_required(VERSION 3.10)

# set the project name
project(starflowModel)
set(CMAKE_CXX_STANDARD 11)

SET(CMAKE_CXX_FLAGS -pthread)

set(SOURCE_FILES starflowModel.cpp)

# add the executable
add_executable(starflowModel ${SOURCE_FILES})
target_link_libraries(starflowModel ${PCAP_LIBRARY})
