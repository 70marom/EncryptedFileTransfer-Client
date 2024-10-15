#include <iostream>
#include <filesystem>
#include <fstream>
#include "Session.h"
#include "Request.h"
#include "ProtocolHandler.h"
#include "RSAKeys.h"
#include "AESKey.h"
#include "Base64.h"
#include "util.h"
#include "CRC.h"

Session::Session(tcp::socket& socket, TransferFile& transfer) {
    this->socket = &socket;
    this->transfer = &transfer;
}

void Session::session() {
    bool loginFailed = false;
    if(me.getExists()) { // if me.info exists, try to login
        if(!loginClient())
            return;
        response = getResponse();
        if(response.empty())
            return;

        if(response.size() == 1 && response.at(0) == 0) // server failed to login client
            loginFailed = true;
        else {
            handleLoginResponse(); // server sent AES key
            if(aesKey.empty())
                return;
        }
    }
    if(!me.getExists() || loginFailed) {
        if(!registerClient())
            return;
        response = getResponse();
        if(response.empty())
            return;
        if(!handleRegisterResponse())
            return;
    }
    int tries = fileTransferProcess(); // send file to server and save number of tries
    if(tries == -1)
        return;

    if(tries == 4) { // if file transfer failed after 4 tries, send file transfer failed message to server
        fileTransferFailed();
        return;
    }

    fileTransferSucceeded(); // if file transfer succeeded, send file transfer succeeded message to server
}

std::vector<uint8_t> Session::getResponse() {
    uint8_t header[7]; // 1 byte for version, 2 bytes for code and 4 bytes for payload size
    try {
        boost::asio::read(*socket, boost::asio::buffer(header, sizeof(header)));
    } catch(std::exception&) {
        std::cerr << "Error: failed to get response from the server!" << std::endl;
        return {};
    }
    int payloadSize = header[3] | (header[4] << 8) | (header[5] << 16) | (header[6] << 24); // extract in little endian
    std::vector<uint8_t> payload(payloadSize);
    try { // read payload
        boost::asio::read(*socket, boost::asio::buffer(payload.data(), payloadSize));
    } catch(std::exception&) {
        std::cerr << "Error: failed to get response from the server!" << std::endl;
        return {};
    }

    ResponseStatus status = processResponse(header);
    if(status == REGISTRATION_REQUIRED) {
        std::vector<uint8_t> loginFailedVector;
        loginFailedVector.push_back(0);
        return loginFailedVector; // return this vector to identify login failure and a registration is needed
    }
    if(status == FAILURE)
        return {};
    return payload;
}

void Session::handleLoginResponse() {
    std::string privateKey = getPrivateKey(); // get private key from file priv.key
    if (privateKey.empty())
        return;
    privateKey = Base64::decode(privateKey);
    RSAKeys rsa(privateKey);
    std::string aesKeyEncrypted(response.begin() + 16, response.end()); // extract AES key from response
    aesKey = rsa.decrypt(aesKeyEncrypted); // decrypt AES key with private key
    std::cout << "Received AES key from the server and decrypted it." << std::endl;
}

bool Session::handleRegisterResponse() {
    if(!me.createMeFile(transfer->getName(), response))
        return false;
    RSAKeys rsa; // generate RSA keys
    std::cout << "Generated RSA public and private keys." << std::endl;
    std::string privateKeyBase64 = Base64::encode(rsa.getPrivateKey());
    if(!createPrivateKeyFile(privateKeyBase64)) // save private key to file priv.key
        return false;
    privateKeyBase64.erase(std::remove(privateKeyBase64.begin(), privateKeyBase64.end(), '\n'), privateKeyBase64.end());
    if(!me.writePrivateKey(privateKeyBase64)) // save private key to me.info
        return false;
    if(!sendPublicKey(rsa.getPublicKey())) // send public key to server
        return false;
    response = getResponse();
    if(response.empty())
        return false;
    std::string aesKeyEncrypted(response.begin() + 16, response.end()); // extract AES key from response
    aesKey = rsa.decrypt(aesKeyEncrypted); // decrypt AES key with private key
    return true;
}


bool Session::registerClient() {
    if(transfer->getName().empty()) {
        std::cerr << "Error: no name in transfer.info! Can't register." << std::endl;
        return false;
    }
    try { // send register request
        createRegisterRequest(transfer->getName()).send(*socket);
    } catch(std::exception&) {
        std::cerr << "Error: failed to send register request!" << std::endl;
        return false;
    }
    return true;
}

bool Session::loginClient() {
    if(me.getName().empty()) {
        std::cerr << "Error: no name in me.info! Can't login." << std::endl;
        return false;
    }
    if(me.getClientID().empty()) {
        std::cerr << "Error: no ID in me.info! Can't login." << std::endl;
        return false;
    }
    try { // send login request
        createLoginRequest(me.getName(), me.getClientID()).send(*socket);
    } catch(std::exception&) {
        std::cerr << "Error: failed to send login request!" << std::endl;
        return false;
    }
    return true;
}

bool Session::sendPublicKey(const std::string& publicKey) {
    try {
        createPublicKeyRequest(me.getName(), me.getClientID(), publicKey).send(*socket);
    } catch(std::exception&) {
        std::cerr << "Error: failed to send public key to the server!" << std::endl;
        return false;
    }
    return true;
}

bool Session::sendFile() {
    if(transfer->getFile().empty()) {
        std::cerr << "Error: no file in transfer.info! Can't send file." << std::endl;
        return false;
    }
    if(transfer->getFile().length() > 255) {
        std::cerr << "Error: file name " << transfer->getFile() << " is too long (more than 255 characters)! Can't send file." << std::endl;
        return false;
    }
    if(!std::filesystem::exists(transfer->getFile())) { // check if file exists
        std::cerr << "Error: file " << transfer->getFile() << " doesn't exist! Can't send file." << std::endl;
        return false;
    }

    std::ifstream file(transfer->getFile(), std::ios::binary); // open file in binary mode
    if(!file.is_open()) {
        std::cerr << "Error: failed to open file " << transfer->getFile() << "! Can't send file." << std::endl;
        return false;
    }

    uintmax_t originalSize = std::filesystem::file_size(transfer->getFile()); // get file size in bytes
    if(originalSize > std::numeric_limits<uint32_t>::max()) { // check if file is too large for the protocol (4 bytes to store the size)
        std::cerr << "Error: file " << transfer->getFile() << " is too large (more than 4GB)! Can't send file." << std::endl;
        return false;
    }

    uint32_t encryptedSize = originalSize + 16 - (originalSize % 16); // calculate size of encrypted file
    AESKey aes(reinterpret_cast<const unsigned char*>(aesKey.c_str()), aesKey.length());

    std::vector<uint8_t> buffer(PACKET_SIZE);
    uint16_t totalPackets = (encryptedSize + PACKET_SIZE - 1) / PACKET_SIZE; // calculate total number of packets needed to send the file

    std::cout << "Sending file " << transfer->getFile() << " to the server in " << totalPackets << " packets." << std::endl;
    for(uint16_t packet = 1; packet <= totalPackets; packet++) {
        file.read(reinterpret_cast<char*>(buffer.data()), PACKET_SIZE); // read PACKET_SIZE bytes from file
        std::streamsize bytesRead = file.gcount(); // get number of bytes read
        if (bytesRead < PACKET_SIZE) // if less than PACKET_SIZE bytes were read, fill the rest with zeros
            std::fill(buffer.begin() + bytesRead, buffer.end(), 0);
        // encrypt the buffer using AES key and send it to the server
        std::string encrypted = aes.encrypt(reinterpret_cast<const char*>(buffer.data()), PACKET_SIZE);
        try {
            createSendFileRequest(me.getClientID(), encryptedSize, originalSize, packet, totalPackets, transfer->getFile(), encrypted).send(*socket);
        } catch(std::exception&) {
            std::cerr << "Error: failed to send file " << transfer->getFile() << " to the server!" << std::endl;
            file.close();
            return false;
        }
        std::cout << "Sent packet " << packet << " of " << totalPackets << " to the server." << std::endl;
    }
    file.close();
    std::cout << "Finished sending file " << transfer->getFile() << " to the server." << std::endl;
    return true;
}

int Session::fileTransferProcess() {
    int tries = 0;
    do {
        if(!sendFile())
            return -1;
        response = getResponse();
        if(response.empty())
            return -1;
        // extract server's CRC from response, stored in little endian
        uint32_t serverCRC = response[response.size() - 4] | (response[response.size() - 3] << 8) | (response[response.size() - 2] << 16) | (response[response.size() - 1] << 24);
        unsigned long clientCRC = fileCRC(transfer->getFile()); // calculate the file's CRC on the client side
        if(clientCRC == -1)
            return -1;

        std::cout << "Server CRC: " << serverCRC << std::endl;
        std::cout << "Client CRC: " << clientCRC << std::endl;

        if(clientCRC == serverCRC) // if server's CRC matches client's CRC, break the loop
            break;
        // if server's CRC doesn't match client's CRC, send a CRC failed request to the server
        std::cout << "Warning: server's CRC doesn't match client's CRC!" << std::endl;
        if(tries < 3)
            std::cout << "Retrying file transfer. Retry number " << tries + 1 << " of 4." << std::endl;
        try {
            createCRCFailedRequest(me.getClientID(), transfer->getFile()).send(*socket);
        } catch(std::exception&) {
            std::cerr << "Error: failed to send CRC failed request to the server!" << std::endl;
            return -1;
        }

        tries++;
    } while(tries <= 3); // try up to 4 times to send the file to the server
    return tries;
}

void Session::fileTransferFailed() {
    std::cerr << "Error: server's CRC doesn't match client's CRC after 4 tries! File transfer failed." << std::endl;
    try {
        createFileTransferFailedRequest(me.getClientID(), transfer->getFile()).send(*socket);
    } catch(std::exception&) {
        std::cerr << "Error: failed to send file transfer failed request to the server!" << std::endl;
        return;
    }
    response = getResponse();
    if(response.empty())
        return;
    std::cout << "Server received file transfer failed message. Disconnecting from server." << std::endl;
}

void Session::fileTransferSucceeded() {
    std::cout << "Server's CRC matches client's CRC! File transfer succeeded." << std::endl;
    try {
        createFileTransferSucceededRequest(me.getClientID(), transfer->getFile()).send(*socket);
    } catch(std::exception&) {
        std::cerr << "Error: failed to send file transfer succeeded message to the server!" << std::endl;
        return;
    }
    response = getResponse();
    if(response.empty())
        return;
    std::cout << "Server received confirmation of file transfer successful. Disconnecting from server." << std::endl;
}
