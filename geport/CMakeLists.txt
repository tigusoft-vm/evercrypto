cmake_minimum_required(VERSION 2.4)
project(geport_implementation)

set(CMAKE_CXX_FLAGS
        "${CMAKE_CXX_FLAGS} -pipe -Ofast -std=c++11 -pthread"
        )

set(SOURCE_FILES
#        correctness_test.cpp
        main.cpp
        ../external/sha_src/sha512.cpp ../external/sha_src/sha512.hpp ../external/sha_src/sha256.cpp ../external/sha_src/sha256.hpp #sha libs
        c_crypto_geport.hpp #geport signature
        ../external/c_random_generator.hpp
        )

add_executable(
        geport_implementation ${SOURCE_FILES}
)


add_custom_target(
        run
        COMMAND ./geport_implementation
        DEPENDS geport_implementation
        WORKING_DIRECTORY .
)
