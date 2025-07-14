cmake_minimum_required(VERSION 3.16)

# When this repository is used as an ESP-IDF component the CMake file is
# executed in script mode. Including the project build system in this case
# results in an error ("define_property command is not scriptable").  Only
# include the ESP-IDF project infrastructure when this file is processed as the
# top level project.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    include($ENV{IDF_PATH}/tools/cmake/project.cmake)
    project(wifi_captive_portal)
endif()
