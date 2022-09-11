cmake_minimum_required(VERSION 2.6)
project(apex_linux)
set(OUT apex_linux)

add_executable ( ${OUT}
    src/main.cpp )


set_target_properties(${OUT} PROPERTIES LINKER_LANGUAGE CXX)


set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wall -DNDEBUG -Wno-format-truncation -Wno-strict-aliasing -O2 -s")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wno-format-truncation -Wno-strict-aliasing")

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()
target_link_libraries(${OUT} rx "-Wall -DNDEBUG -pthread -s -O2")
