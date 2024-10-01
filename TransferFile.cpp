#include "TransferFile.h"
#include <fstream>
#include <iostream>

TransferFile::TransferFile() {
    std::ifstream transfer("transfer.info");
    if(transfer.is_open()) {
        std::string line;
        std::getline(transfer, line);
        setAddressPort(line);
        std::getline(transfer, name);
        if(name.length() > 100)
            name = "";
        std::getline(transfer, file);
        transfer.close();
    }
    else {
        std::cerr << "Error: failed to open transfer.info!" << std::endl;
        address = "";
        port = "";
        name = "";
        file = "";
    }
}

std::string TransferFile::getAddress() {
    return address;
}

std::string TransferFile::getPort() {
    return port;
}

std::string TransferFile::getName() {
    return name;
}

std::string TransferFile::getFile() {
    return file;
}

void TransferFile::setAddressPort(std::string line) {
    int index = line.find(':');
    if (index != std::string::npos) {
        address = line.substr(0, index);
        port = line.substr(index + 1);
    } else {
        address = "";
        port = "";
    }
}
