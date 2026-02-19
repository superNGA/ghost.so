cmake_minimum_required(VERSION 3.10)
project(ghostso LANGUAGES C)

message(STATUS "C compiler:       ${CMAKE_C_COMPILER}")
message(STATUS "Compiler ID:      ${CMAKE_C_COMPILER_ID}")
message(STATUS "Compiler version: ${CMAKE_C_COMPILER_VERSION}")

# C++ standard
set(CMAKE_C_STANDARD          17)
set(CMAKE_C_STANDARD_REQUIRED ON)

SET(SOURCE
    "src/main.c"
    "src/TargetBrief/TargetBrief_t.c"
    "src/ShellCode/ShellCode.c"
    "src/Util/Terminal/ConsoleSystem.c"
)

add_executable(${PROJECT_NAME} ${SOURCE})
