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
public:
    Session(tcp::socket& socket, TransferFile& transfer);
    void session();
private:
    std::vector<uint8_t> getResponse();
    bool registerClient();
    bool loginClient();
    bool sendPublicKey(const std::string& publicKey);
    bool sendFile(const std::string& aesKey);
};

#endif //SESSION_H
