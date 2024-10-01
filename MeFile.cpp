#include "MeFile.h"
#include "util.h"
#include <fstream>
#include <iomanip>
#include <iostream>

MeFile::MeFile() {
    std::ifstream me("me.info");
    if(me.is_open()) {
        std::getline(me, name);
        std::getline(me, clientID);
        std::getline(me, privateKey);
        me.close();
        exists = true;
    }
    else {
        name = "";
        clientID = "";
        privateKey = "";
        exists = false;
    }
}

std::string MeFile::getName() {
    return name;
}

std::string MeFile::getClientID() {
    return clientID;
}

std::string MeFile::getPrivateKey() {
    return privateKey;
}

bool MeFile::getExists() {
    return exists;
}

bool MeFile::createMeFile(std::string name, std::vector<uint8_t> uuid) {
    std::ofstream me("me.info");
    if(me.is_open()) {
        me << name << std::endl;
        std::string uuidString = binaryToHexAscii(uuid);
        for(const char ch : uuidString) {
            me << ch;
            clientID += ch;
        }
        me << std::endl;
        me.close();
        exists = true;
        this->name = name;
        std::cout << "me.info file created with your UUID." << std::endl;;
        return true;
    }
    else {
        std::cerr << "Error: failed to create me.info file!" << std::endl;
        return false;
    }
}

bool MeFile::writePrivateKey(const std::string& privateKey) {
    std::ofstream me("me.info", std::ios_base::app);
    if(me.is_open()) {
        me << privateKey;
        me.close();
        this->privateKey = privateKey;
        return true;
    }
    else {
        std::cerr << "Error: failed to write private key to me.info!" << std::endl;
        return false;
    }
}