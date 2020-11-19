cmake_minimum_required(VERSION 3.17)
project(EnclaveCoin)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

######## Intel SGX ###########################################################

# https://github.com/xzhangxa/SGX-CMake
set(SGX_HW OFF)
#set(SGX_MODE Debug)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)
find_package(SGX REQUIRED)
include_directories(${SGX_INCLUDE_DIR})

# SGX utils
include_directories(utils)
file(GLOB uUTILS utils/*.cpp)

######## Third Party #########################################################

# https://github.com/tplgy/cppcodec
include_directories(third_party/cppcodec)

##############################################################################

file(GLOB ENCLAVE_DESCRIPTION )
file(GLOB T_ENCLAVE_SRC enclave/*.cpp enclave/src/*.cpp enclave/edge/*.cpp)
file(GLOB U_APP_SRC app/*.cpp app/src/*.cpp)

add_enclave_library(LxEnclave
        SRCS              ${T_ENCLAVE_SRC}
        EDL               enclave/meta/enclave.edl
        EDL_SEARCH_PATHS  enclave)

target_include_directories(LxEnclave PRIVATE enclave)

enclave_sign(LxEnclave
        KEY     enclave/meta/enclave_private.pem
        CONFIG  enclave/meta/enclave.config.xml)

add_untrusted_executable(LxApp
        SRCS              ${U_APP_SRC} ${uUTILS}
        EDL               enclave/meta/enclave.edl
        EDL_SEARCH_PATHS  enclave)
target_include_directories(LxApp PRIVATE app)
add_dependencies(LxApp LxEnclave-sign)

#add_untrusted_library(LxLib SHARED
#        SRCS              ${U_APP_SRC}
#        EDL               enclave/Enclave.edl
#        EDL_SEARCH_PATHS  enclave)
#target_include_directories(LxLib PRIVATE app)

#add_dependencies(LxLib LxEnclave-sign)
