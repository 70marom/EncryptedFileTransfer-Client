#include "util.h"
#include <iomanip>
#include <ios>
#include <fstream>
#include <iostream>

std::string binaryToHexAscii(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    for (uint8_t byte : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return oss.str();
}

void hexStringToByteArray(const std::string& hexString, uint8_t* byteArray) {
    for (size_t i = 0; i < hexString.length(); i += 2) {
        std::string byteString = hexString.substr(i, 2);
        byteArray[i / 2] = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
    }
}

bool createPrivateKeyFile(const std::string& privateKey) {
    std::ofstream file("priv.key");
    if (file.is_open()) {
        file.write(privateKey.c_str(), privateKey.length());
        file.close();
        std::cout << "priv.key file created with your private key." << std::endl;
        return true;
    }
    else {
        std::cerr << "Error: failed to create priv.key file!" << std::endl;
        return false;
    }
}

std::string getPrivateKey() {
    std::ifstream file("priv.key");
    if (file.is_open()) {
        std::string privateKey((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();
        return privateKey;
    }
    else {
        std::cerr << "Error: failed to open priv.key file and retrieve private key!" << std::endl;
        return "";
    }
}
