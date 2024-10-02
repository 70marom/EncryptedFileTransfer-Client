#include "ProtocolHandler.h"
#include "util.h"
#include <iostream>

bool processResponse(uint8_t* header) {
    int code = header[1] | (header[2] << 8);
    switch(code) {
        case 1600:
            std::cout << "Registration in server is successful!" << std::endl;
            return true;
        case 1601:
            std::cerr << "Error: server failed to register client! Name might have been taken." << std::endl;
            return false;
        case 1602:
            std::cout << "AES key has been received from server." << std::endl;
            return true;
        case 1603:
            std::cout << "CRC for sent file has been received from server." << std::endl;
            return true;
        case 1604:
            return true;
        case 1605:
            std::cout << "Login in server is successful!" << std::endl;
            return true;
        case 1606:
            std::cerr << "Error: failed to login in server! A registration is needed." << std::endl;
            return false;
        case 1607:
            std::cerr << "Error: server received unknown request. Please try again." << std::endl;
            return false;
        default:
            std::cerr << "Error: unknown response code " << code << " received from server!" << std::endl;
            return false;
    }
}

Request createRegisterRequest(const std::string &name) {
    uint8_t clientID[16] = {};
    uint8_t version = 3;
    uint16_t code = 825;
    std::vector<uint8_t> payload;
    for(int i = 0; i < name.length(); i++)
        payload.push_back(name[i]);
    payload.push_back('\0');
    return { clientID, version, code, payload };
}

Request createLoginRequest(const std::string &name, const std::string& clientID) {
    uint8_t clientIDarray[16];
    hexStringToByteArray(clientID, clientIDarray);
    uint8_t version = 3;
    uint16_t code = 827;
    std::vector<uint8_t> payload;
    for(int i = 0; i < name.length(); i++)
        payload.push_back(name[i]);
    payload.push_back('\0');
    return { clientIDarray, version, code, payload };
}

Request createPublicKeyRequest(const std::string &name, const std::string& clientID, const std::string &publicKey) {
    uint8_t clientIDarray[16];
    hexStringToByteArray(clientID, clientIDarray);
    uint8_t version = 3;
    uint16_t code = 826;
    std::vector<uint8_t> payload;
    for(int i = 0; i < name.length(); i++)
        payload.push_back(name[i]);
    for(int i = static_cast<int>(name.length()); i < 255; i++)
        payload.push_back('\0');
    for (int i = 0; i < publicKey.length(); i++)
        payload.push_back(publicKey[i]);
    return { clientIDarray, version, code, payload };
}

Request createSendFileRequest(const std::string& clientID, uint32_t contentSize, uint32_t originalSize, uint16_t packetNumber, uint16_t totalPackets, const std::string& fileName, const std::string& fileContent) {
    uint8_t clientIDarray[16];
    hexStringToByteArray(clientID, clientIDarray);
    uint8_t version = 3;
    uint16_t code = 828;
    std::vector<uint8_t> payload;

    payload.push_back(contentSize & 0xFF);
    payload.push_back((contentSize >> 8) & 0xFF);
    payload.push_back((contentSize >> 16) & 0xFF);
    payload.push_back((contentSize >> 24) & 0xFF);

    payload.push_back(originalSize & 0xFF);
    payload.push_back((originalSize >> 8) & 0xFF);
    payload.push_back((originalSize >> 16) & 0xFF);
    payload.push_back((originalSize >> 24) & 0xFF);

    payload.push_back(packetNumber & 0xFF);
    payload.push_back((packetNumber >> 8) & 0xFF);

    payload.push_back(totalPackets & 0xFF);
    payload.push_back((totalPackets >> 8) & 0xFF);

    for(int i = 0; i < fileName.length(); i++)
        payload.push_back(fileName[i]);
    for(int i = static_cast<int>(fileName.length()); i < 255; i++)
        payload.push_back('\0');

    for(int i = 0; i < fileContent.length(); i++)
        payload.push_back(fileContent[i]);
    return { clientIDarray, version, code, payload };
}

Request createCRCFailedRequest(const std::string& clientID, const std::string& fileName) {
    uint8_t clientIDarray[16];
    hexStringToByteArray(clientID, clientIDarray);
    uint8_t version = 3;
    uint16_t code = 901;
    std::vector<uint8_t> payload;
    for(int i = 0; i < fileName.length(); i++)
        payload.push_back(fileName[i]);
    for(int i = static_cast<int>(fileName.length()); i < 255; i++)
        payload.push_back('\0');
    return { clientIDarray, version, code, payload };
}

Request createFileTransferFailedRequest(const std::string& clientID, const std::string& fileName) {
    uint8_t clientIDarray[16];
    hexStringToByteArray(clientID, clientIDarray);
    uint8_t version = 3;
    uint16_t code = 902;
    std::vector<uint8_t> payload;
    for(int i = 0; i < fileName.length(); i++)
        payload.push_back(fileName[i]);
    for(int i = static_cast<int>(fileName.length()); i < 255; i++)
        payload.push_back('\0');
    return { clientIDarray, version, code, payload };
}

Request createFileTransferSucceededRequest(const std::string& clientID, const std::string& fileName) {
    uint8_t clientIDarray[16];
    hexStringToByteArray(clientID, clientIDarray);
    uint8_t version = 3;
    uint16_t code = 900;
    std::vector<uint8_t> payload;
    for(int i = 0; i < fileName.length(); i++)
        payload.push_back(fileName[i]);
    for(int i = static_cast<int>(fileName.length()); i < 255; i++)
        payload.push_back('\0');
    return { clientIDarray, version, code, payload };
}