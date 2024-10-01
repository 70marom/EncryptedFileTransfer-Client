cmake_minimum_required(VERSION 3.29)
project(client)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native")

set(BOOST_ROOT C:/Users/70mar/Desktop/boost_1_86_0)
find_package(Boost REQUIRED)

include_directories(${Boost_INCLUDE_DIRS})
add_subdirectory(C:/Users/70mar/OneDrive/EncryptedFileTransfer/client/Cypto++Cmake)

add_executable(client main.cpp
        TransferFile.cpp
        TransferFile.h
        MeFile.cpp
        MeFile.h
        Session.cpp
        Session.h
        Request.cpp
        Request.h
        ProtocolHandler.cpp
        ProtocolHandler.h
        RSAWrapper.h
        RSAWrapper.cpp
        util.cpp
        util.h
        Base64Wrapper.cpp
        Base64Wrapper.h
        AESWrapper.cpp
        AESWrapper.h
)

target_link_libraries(client ${Boost_LIBRARIES} ws2_32 cryptopp::cryptopp)
