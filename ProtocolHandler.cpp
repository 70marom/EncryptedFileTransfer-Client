#include "ProtocolHandler.h"
#include "util.h"
#include <iostream>

bool processResponse(uint8_t* header) {
    int code = header[1] | (header[2] << 8);
    switch(code) {
        case REGISTRATION_SUCCESS:
            std::cout << "Registration in server is successful!" << std::endl;
            return true;
        case REGISTRATION_FAILED:
            std::cerr << "Error: server failed to register client! Name might have been taken." << std::endl;
            return false;
        case PUBLIC_KEY_RECEIVED:
            std::cout << "AES key has been received from server." << std::endl;
            return true;
        case FILE_RECEIVED:
            std::cout << "CRC for sent file has been received from server." << std::endl;
            return true;
        case CONFIRMATION:
            return true;
        case LOGIN_SUCCESS:
            std::cout << "Login in server is successful!" << std::endl;
            return true;
        case LOGIN_FAILED:
            std::cerr << "Error: failed to login in server! A registration is needed." << std::endl;
            return false;
        case SERVER_ERROR:
            std::cerr << "Error: server responded with an error!" << std::endl;
            return false;
        default:
            std::cerr << "Error: unknown response code " << code << " received from server!" << std::endl;
            return false;
    }
}

Request createRegisterRequest(const std::string &name) {
    uint8_t clientID[CLIENT_ID_SIZE] = {};
    uint8_t version = VERSION;
    uint16_t code = REGISTRATION;
    std::vector<uint8_t> payload;
    for(int i = 0; i < name.length(); i++) // add name to payload
        payload.push_back(name[i]);
    payload.push_back('\0'); // add null terminator
    return { clientID, version, code, payload };
}

Request createLoginRequest(const std::string &name, const std::string& clientID) {
    uint8_t clientIDarray[CLIENT_ID_SIZE];
    hexStringToByteArray(clientID, clientIDarray); // convert clientID to byte array
    uint8_t version = VERSION;
    uint16_t code = LOGIN;
    std::vector<uint8_t> payload;
    for(int i = 0; i < name.length(); i++) // add name to payload
        payload.push_back(name[i]); // add null terminator
    payload.push_back('\0');
    return { clientIDarray, version, code, payload };
}

Request createPublicKeyRequest(const std::string &name, const std::string& clientID, const std::string &publicKey) {
    uint8_t clientIDarray[CLIENT_ID_SIZE];
    hexStringToByteArray(clientID, clientIDarray); // convert clientID to byte array
    uint8_t version = VERSION;
    uint16_t code = SEND_PUBLIC_KEY;
    std::vector<uint8_t> payload;
    for(int i = 0; i < name.length(); i++) // add name to payload
        payload.push_back(name[i]); // add null terminator
    for(int i = static_cast<int>(name.length()); i < NAME_LENGTH; i++) // fill the rest of the 255 bytes with null terminators
        payload.push_back('\0');
    for (int i = 0; i < publicKey.length(); i++) // add public key to payload
        payload.push_back(publicKey[i]);
    return { clientIDarray, version, code, payload };
}

Request createSendFileRequest(const std::string& clientID, uint32_t contentSize, uint32_t originalSize, uint16_t packetNumber, uint16_t totalPackets, const std::string& fileName, const std::string& fileContent) {
    uint8_t clientIDarray[CLIENT_ID_SIZE];
    hexStringToByteArray(clientID, clientIDarray); // convert clientID to byte array
    uint8_t version = VERSION;
    uint16_t code = SEND_FILE;
    std::vector<uint8_t> payload;
    // add content size, original size, packet number, and total packets to payload in little endian format
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
    for(int i = static_cast<int>(fileName.length()); i < NAME_LENGTH; i++)
        payload.push_back('\0');

    for(int i = 0; i < fileContent.length(); i++) // add file content to payload
        payload.push_back(fileContent[i]);
    return { clientIDarray, version, code, payload };
}

Request createCRCFailedRequest(const std::string& clientID, const std::string& fileName) {
    uint8_t clientIDarray[CLIENT_ID_SIZE];
    hexStringToByteArray(clientID, clientIDarray); // convert clientID to byte array
    uint8_t version = VERSION;
    uint16_t code = INVALID_CRC;
    std::vector<uint8_t> payload;
    for(int i = 0; i < fileName.length(); i++)
        payload.push_back(fileName[i]);
    for(int i = static_cast<int>(fileName.length()); i < NAME_LENGTH; i++)
        payload.push_back('\0');
    return { clientIDarray, version, code, payload };
}

Request createFileTransferFailedRequest(const std::string& clientID, const std::string& fileName) {
    uint8_t clientIDarray[CLIENT_ID_SIZE];
    hexStringToByteArray(clientID, clientIDarray);
    uint8_t version = VERSION;
    uint16_t code = FILE_TRANSFER_FAILED;
    std::vector<uint8_t> payload;
    for(int i = 0; i < fileName.length(); i++)
        payload.push_back(fileName[i]);
    for(int i = static_cast<int>(fileName.length()); i < NAME_LENGTH; i++)
        payload.push_back('\0');
    return { clientIDarray, version, code, payload };
}

Request createFileTransferSucceededRequest(const std::string& clientID, const std::string& fileName) {
    uint8_t clientIDarray[CLIENT_ID_SIZE];
    hexStringToByteArray(clientID, clientIDarray);
    uint8_t version = VERSION;
    uint16_t code = FILE_TRANSFER_SUCCEEDED;
    std::vector<uint8_t> payload;
    for(int i = 0; i < fileName.length(); i++)
        payload.push_back(fileName[i]);
    for(int i = static_cast<int>(fileName.length()); i < NAME_LENGTH; i++)
        payload.push_back('\0');
    return { clientIDarray, version, code, payload };
}