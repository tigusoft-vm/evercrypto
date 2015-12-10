cmake_minimum_required(VERSION 2.4)
project(get_random_bytes)

set(CMAKE_CXX_FLAGS
        "${CMAKE_CXX_FLAGS} -pipe -Ofast -std=c++11 -pthread"
        )

set(SOURCE_FILES
        ./get_random_bytes.cpp
        ./c_random_generator.hpp
        )

add_executable(
        get_random_bytes ${SOURCE_FILES}
)


add_custom_target(
        run
        COMMAND ./get_random_bytes
        DEPENDS get_random_bytes
        WORKING_DIRECTORY .
)
