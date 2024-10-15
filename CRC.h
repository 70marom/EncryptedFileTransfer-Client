#ifndef CKSUM_H
#define CKSUM_H
#include <string>

unsigned long fileCRC(const std::string& fileName);
unsigned long memcrc(char * b, size_t n);


#endif //CKSUM_H
