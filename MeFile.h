#ifndef MEFILE_H
#define MEFILE_H
#include <cstdint>
#include <string>
#include <vector>

class MeFile {
    std::string name;
    std::string clientID;
    std::string privateKey;
    bool exists;
public:
    MeFile();
    std::string getName();
    std::string getClientID();
    std::string getPrivateKey();
    bool getExists();
    bool createMeFile(std::string name, std::vector<uint8_t> clientID);
    bool writePrivateKey(const std::string& privateKey);
};

#endif //MEFILE_H
