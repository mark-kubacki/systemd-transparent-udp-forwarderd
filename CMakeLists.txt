cmake_minimum_required(VERSION 2.8.8)

project(UDPForwarderd)

enable_language(C)

set(CMAKE_CPP_FLAGS "${CMAKE_CPP_FLAGS} -Wall -Werror=implicit-function-declaration -Wsign-compare -Wmissing-field-initializers -Wno-implicit-int -Wp,-D_FORTIFY_SOURCE=2")
set(CMAKE_C_FLAGS "${CMAKE_CPP_FLAGS} ${CMAKE_C_FLAGS} -Os -fpic -fpie -fstack-protector-strong")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-s -Wl,-O1 -Wl,-z,relro -Wl,-z,now -Wl,-z,nodynamic-undefined-weak -Wl,--as-needed -Wl,--gc-sections -fwhole-program")
add_definitions(-D_GNU_SOURCE)

file(GLOB SOURCES "*.c")

add_executable(systemd-transparent-udp-forwarderd ${SOURCES})
TARGET_LINK_LIBRARIES(systemd-transparent-udp-forwarderd systemd)
