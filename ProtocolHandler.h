#ifndef PROTOCOLHANDLER_H
#define PROTOCOLHANDLER_H
#include "Request.h"

bool processResponse(uint8_t* header);
Request createRegisterRequest(const std::string &name);
Request createLoginRequest(const std::string &name, const std::string& clientID);
Request createPublicKeyRequest(const std::string &name, const std::string& clientID, const std::string &publicKey);
Request createSendFileRequest(const std::string& clientID, uint32_t contentSize, uint32_t originalSize, uint16_t packetNumber, uint16_t totalPackets, const std::string& fileName, const std::string& fileContent);

#endif //PROTOCOLHANDLER_H
