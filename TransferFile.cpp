#include "TransferFile.h"
#include <fstream>
#include <iostream>

TransferFile::TransferFile() {
    std::ifstream transfer("transfer.info"); // open transfer.info file to read
    if(transfer.is_open()) {
        std::string line;
        std::getline(transfer, line);
        setAddressPort(line); // extract address and port from the first line
        std::getline(transfer, name);
        if(name.length() > 100) // check if name is too long
            name = "";
        std::getline(transfer, file); // get the file name to transfer
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
    if (index != std::string::npos) { // if ':' is found
        address = line.substr(0, index); // extract address
        port = line.substr(index + 1); // extract port
    } else { // if ':' is not found
        address = "";
        port = "";
    }
}
