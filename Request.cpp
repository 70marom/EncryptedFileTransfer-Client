#include "Request.h"
#include <boost/asio/write.hpp>

Request::Request(uint8_t clientID[CLIENT_ID_SIZE], uint8_t version, uint16_t code, std::vector<uint8_t>& payload) {
    for(int i = 0; i < CLIENT_ID_SIZE; i++)
        header.clientID[i] = clientID[i];
    header.version = version;
    header.code = code;
    header.payloadSize = static_cast<uint32_t>(payload.size()); // get the size of the payload and cast it to 4 bytes
    this->payload = payload;
}

void Request::send(boost::asio::ip::tcp::socket& socket) {
    std::vector<uint8_t> buffer;

    for(uint8_t byte : header.clientID)
        buffer.push_back(byte);
    // add version, code, and payload size to buffer in little endian order
    buffer.push_back(header.version);

    buffer.push_back(header.code & 0xFF);
    buffer.push_back((header.code >> 8) & 0xFF);

    buffer.push_back(header.payloadSize & 0xFF);
    buffer.push_back((header.payloadSize >> 8) & 0xFF);
    buffer.push_back((header.payloadSize >> 16) & 0xFF);
    buffer.push_back((header.payloadSize >> 24) & 0xFF);

    for(uint8_t byte : payload)
        buffer.push_back(byte);
    // send the request to the server
    boost::asio::write(socket, boost::asio::buffer(buffer, buffer.size()));
}