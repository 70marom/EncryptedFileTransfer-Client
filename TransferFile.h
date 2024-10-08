#ifndef TRANSFERFILE_H
#define TRANSFERFILE_H
#include <string>

const size_t PACKET_SIZE = 1024;

class TransferFile {
    std::string address;
    std::string port;
    std::string name;
    std::string file;
public:
    TransferFile();
    std::string getAddress();
    std::string getPort();
    std::string getName();
    std::string getFile();
private:
    void setAddressPort(std::string line);
};

#endif //TRANSFERFILE_H
