#ifndef SESSION_H
#define SESSION_H
#include <boost/asio.hpp>

#include "MeFile.h"
#include "TransferFile.h"

using boost::asio::ip::tcp;

class Session {
    tcp::socket* socket;
    TransferFile* transfer;
    MeFile me;
    std::vector<uint8_t> response;
    std::string aesKey;
public:
    Session(tcp::socket& socket, TransferFile& transfer);
    void session();
private:
    std::vector<uint8_t> getResponse();
    void handleLoginResponse();
    bool handleRegisterResponse();
    bool registerClient();
    bool loginClient();
    bool sendPublicKey(const std::string& publicKey);
    bool sendFile();
    int fileTransferProcess();
    void fileTransferFailed();
    void fileTransferSucceeded();
};

#endif //SESSION_H
