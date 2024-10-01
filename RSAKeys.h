#pragma once

#include <osrng.h>
#include <rsa.h>
#include <string>


class RSAKeys
{
public:
	static const unsigned int BITS = 1024;

private:
	CryptoPP::AutoSeededRandomPool _rng;
	CryptoPP::RSA::PrivateKey _privateKey;

	RSAKeys(const RSAKeys& rsaprivate);
	RSAKeys& operator=(const RSAKeys& rsaprivate);
public:
	RSAKeys();
	RSAKeys(const std::string& key);
	~RSAKeys();

	std::string getPrivateKey() const;
	std::string getPublicKey() const;

	std::string decrypt(const std::string& cipher);
	std::string decrypt(const char* cipher, unsigned int length);
};
