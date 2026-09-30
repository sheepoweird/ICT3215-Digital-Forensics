# This file was automatically generated for projects
# without default 'CMakeLists.txt' file.

FILE(GLOB_RECURSE app_sources ${CMAKE_SOURCE_DIR}/src/*.*)

idf_component_register(SRCS "main.c" "st7305.c" "font8x16.c"
                       INCLUDE_DIRS "."
                       REQUIRES bt nvs_flash esp_driver_spi esp_driver_gpio)
