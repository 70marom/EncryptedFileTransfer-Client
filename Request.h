#ifndef REQUEST_H
#define REQUEST_H
#include <cstdint>
#include <vector>
#include <boost/asio/ip/tcp.hpp>

const int CLIENT_ID_SIZE = 16;

struct Header {
    uint8_t clientID[CLIENT_ID_SIZE];
    uint8_t version;
    uint16_t code;
    uint32_t payloadSize;
};

class Request {
    Header header{};
    std::vector<uint8_t> payload;
public:
    Request(uint8_t clientID[CLIENT_ID_SIZE], uint8_t version, uint16_t code, std::vector<uint8_t>& payload);
    void send(boost::asio::ip::tcp::socket& socket);
};



#endif //REQUEST_H
