cmake_minimum_required(VERSION 3.18.1)

project("wekit")

add_library(wekit SHARED
        wekit_lib.cpp)

find_library(log-lib log)

target_link_libraries(wekit
        ${log-lib}
        z
)
