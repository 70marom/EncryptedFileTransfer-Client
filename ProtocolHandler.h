#ifndef PROTOCOLHANDLER_H
#define PROTOCOLHANDLER_H
#include "Request.h"

const int VERSION = 3;
const int NAME_LENGTH = 255;

enum ResponseCode {
    REGISTRATION_SUCCESS = 1600,
    REGISTRATION_FAILED = 1601,
    PUBLIC_KEY_RECEIVED = 1602,
    FILE_RECEIVED = 1603,
    CONFIRMATION = 1604,
    LOGIN_SUCCESS = 1605,
    LOGIN_FAILED = 1606,
    SERVER_ERROR = 1607
};

enum RequestCode {
    REGISTRATION = 825,
    SEND_PUBLIC_KEY = 826,
    LOGIN = 827,
    SEND_FILE = 828,
    FILE_TRANSFER_SUCCEEDED = 900,
    INVALID_CRC = 901,
    FILE_TRANSFER_FAILED = 902
};

enum ResponseStatus {
    FAILURE = 0,
    SUCCESS = 1,
    GENERAL_ERROR = 2,
    REGISTRATION_REQUIRED = 3
};

ResponseStatus processResponse(uint8_t* header);
Request createRegisterRequest(const std::string &name);
Request createLoginRequest(const std::string &name, const std::string& clientID);
Request createPublicKeyRequest(const std::string &name, const std::string& clientID, const std::string &publicKey);
Request createSendFileRequest(const std::string& clientID, uint32_t contentSize, uint32_t originalSize, uint16_t packetNumber, uint16_t totalPackets, const std::string& fileName, const std::string& fileContent);
Request createCRCFailedRequest(const std::string& clientID, const std::string& fileName);
Request createFileTransferFailedRequest(const std::string& clientID, const std::string& fileName);
Request createFileTransferSucceededRequest(const std::string& clientID, const std::string& fileName);


#endif //PROTOCOLHANDLER_H
