#ifndef REQUEST_H
#define REQUEST_H
#include <cstdint>
#include <vector>
#include <boost/asio/ip/tcp.hpp>

struct Header {
    uint8_t clientID[16];
    uint8_t version;
    uint16_t code;
    uint32_t payloadSize;
};

class Request {
    Header header{};
    std::vector<uint8_t> payload;
public:
    Request(uint8_t clientID[16], uint8_t version, uint16_t code, std::vector<uint8_t>& payload);
    void send(boost::asio::ip::tcp::socket& socket);
};



#endif //REQUEST_H
