#include <iostream>
#include <boost/asio.hpp>
#include "Session.h"
#include "TransferFile.h"

using boost::asio::ip::tcp;

int main() {
    TransferFile transfer; // get info from transfer.info
    try {
        boost::asio::io_context io_context;
        tcp::resolver resolver(io_context);
        tcp::socket socket(io_context);
        boost::asio::connect(socket, resolver.resolve(transfer.getAddress(), transfer.getPort()));
        std::cout << "Connecting to " << transfer.getAddress() << ":" << transfer.getPort() << std::endl;
        Session session(socket, transfer);
        session.session(); // start session with server
        socket.close();
        std::cout << "Disconnected from " << transfer.getAddress() << ":" << transfer.getPort() << std::endl;
    } catch(std::exception& e) {
        std::cerr << "Error: failed to connect to server! Check IP and port in transfer.info." << std::endl;
    }
    return 0;
}
