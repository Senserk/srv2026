cmake_minimum_required(VERSION 3.16)
project(release_agent C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra -Wpedantic)

add_executable(release-agent src/main.c src/session.c)
target_include_directories(release-agent PRIVATE include)

enable_testing()
add_test(NAME normal_run COMMAND release-agent)
