#pragma once

#include <string>


class AESKey
{
public:
	static const unsigned int DEFAULT_KEYLENGTH = 32;
private:
	unsigned char _key[DEFAULT_KEYLENGTH];
	AESKey(const AESKey& aes);
public:
	AESKey(const unsigned char* key, unsigned int size);
	~AESKey();

	const unsigned char* getKey() const;

	std::string encrypt(const char* plain, unsigned int length);
	std::string decrypt(const char* cipher, unsigned int length);
};