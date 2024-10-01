#ifndef UTIL_H
#define UTIL_H
#include <cstdint>
#include <string>
#include <vector>

std::string binaryToHexAscii(const std::vector<uint8_t>& data);
void hexStringToByteArray(const std::string& hexString, uint8_t* byteArray);
bool createPrivateKeyFile(const std::string& privateKey);
std::string getPrivateKey();

#endif //UTIL_H
