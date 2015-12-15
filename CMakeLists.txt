cmake_minimum_required(VERSION 3.1)

# define the HAVE_ENDIAN_H to use the host endian.h
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DHAVE_ENDIAN_H -DHAVE_POSIX_FILEMAP -std=c++11")

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/bin")

set(SOURCE_FILES
        CmdUtils.h
        CmdUtils.cpp
        DexCatch.cpp
        DexCatch.h
        DexClass.cpp
        DexClass.h
        DexDataMap.cpp
        DexDataMap.h
        DexDebugInfo.cpp
        DexDebugInfo.h
        DexFile.cpp
        DexFile.h
        DexInlines.cpp
        DexOpcodes.cpp
        DexOpcodes.h
        DexOptData.cpp
        DexOptData.h
        DexProto.cpp
        DexProto.h
        DexSwapVerify.cpp
        DexUtf.cpp
        DexUtf.h
        InstrUtils.cpp
        InstrUtils.h
        Leb128.cpp
        Leb128.h
        OptInvocation.cpp
        OptInvocation.h
        sha1.cpp
        sha1.h
        SysUtil.cpp
        SysUtil.h
        vm/Common.h
        safe-iop/safe_iop.h
        safe-iop/safe_iop.c)

include_directories(
        ${PROJECT_SOURCE_DIR}/safe-iop
)

add_library(wdex SHARED ${SOURCE_FILES})
target_link_libraries(wdex z)