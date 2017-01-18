// decrypt.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <cassert>
#include <iostream>
#include <fstream>
#include <iterator>
#include <algorithm>
#include <vector>
#include <thread>

using std::endl;

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "des.h"
//using CryptoPP::DES_EDE3;
using CryptoPP::DES_EDE2;

#include "modes.h"
using CryptoPP::CBC_Mode;

#include "secblock.h"
using CryptoPP::SecByteBlock;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include "md5.h"
#include "sha.h"

// Just a convinient type to handle byte array
using ByteVector = std::vector<byte>;

// Alphabet and it dimension
const char ALPHABET[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
constexpr int ALPHABET_LENGTH = sizeof(ALPHABET)/sizeof(char) - 1;
constexpr int TOTAL_NUMBER_OF_VALUES = ALPHABET_LENGTH * ALPHABET_LENGTH * ALPHABET_LENGTH;

const char * RESULT_FILE_NAME = "out.dat";

// String blocks from input file
ByteVector g_initVector;
std::string g_cypher;
ByteVector g_checkValue;

// Sync thread flag
bool g_taskCompleted = false;

// Mutex for case when different passwords generate same digest
std::mutex  g_collisionMutex;

ByteVector getInputFileData(const std::string & fileName);
void saveBinaryToFile(const std::string & fileName, const std::string & text);
inline std::string getPasswordByValue(int position);
void decryptCypher(int startRange, int endRange);

int main(int argc, char ** argv)
{
	assert("000" == getPasswordByValue(0));
	assert("ZZZ" == getPasswordByValue(TOTAL_NUMBER_OF_VALUES - 1));

	if (argc != 2)
	{
		std::cout << "Usage: decrypt.exe <input filename>" << '\n';
		exit(1);
	}
	std::string fileName(argv[1]);

	try 
	{
		ByteVector fileData = getInputFileData(fileName);
		g_initVector = ByteVector (fileData.begin(), fileData.begin() + DES_EDE2::BLOCKSIZE);
		g_cypher     = std::string(fileData.begin() + DES_EDE2::BLOCKSIZE, fileData.end() - CryptoPP::SHA256::DIGESTSIZE);
		g_checkValue = ByteVector (fileData.end() - CryptoPP::SHA256::DIGESTSIZE, fileData.end());
#ifdef _DEBUG
		std::cout << "Read " << fileData.size() << " bytes from file " << fileName.c_str() << std::endl;
		std::cout << "IV     : " << g_initVector.size() << std::endl;
		std::cout << "cyper  : " << g_cypher.size() << std::endl;
		std::cout << "sha256 : " << g_checkValue.size() << std::endl;
#endif
		int numberThreads = std::thread::hardware_concurrency();
		std::vector<std::thread> pool(numberThreads);
		int subrangeSize = TOTAL_NUMBER_OF_VALUES / numberThreads;

		for (int i = 0; i < numberThreads; ++i)
		{
			int startValue = subrangeSize*i;
			int endValue = (i == (numberThreads - 1)) ? TOTAL_NUMBER_OF_VALUES : subrangeSize*(i+1);
			pool[i] = std::thread(decryptCypher, startValue, endValue);
		}
		for (int i = 0; i < numberThreads; ++i) {
			pool[i].join();
		}
	}
	catch (std::exception & e)
	{
		std::cout << "Error occured: " << e.what();
		exit(1);
	}

	return 0;
}

/*
   Read file to byte array.
   Throws runtime_error exception in case file can'nt be read.
*/
ByteVector getInputFileData(const std::string & fileName)
{
	std::ifstream is(fileName, std::ios::binary);
	is.unsetf(std::ios::skipws);

	if (!is.is_open())
	{
		throw std::runtime_error("Error while opening file! Maybe the file doesn't exist.");
	}
	std::istream_iterator<char> start(is), end;
	return ByteVector(start, end);
}

void saveBinaryToFile(const std::string & fileName, const std::string & text)
{
	std::ofstream os(fileName, std::ios::out);
	os.write(text.c_str(), text.size());
}

/*
   Calculate password by value from range [0..ALPHABET_LENGTH^3-1].
   Alphabet: 0..9a-zA-Z (i.e. 62-base scale of notation).
   The max value is 62^2*61 + 62^1*61 + 61^0*61 = 62^3-1 = 238'327
*/
inline std::string getPasswordByValue(int value) {
	
	int pows[] = { ALPHABET_LENGTH*ALPHABET_LENGTH, ALPHABET_LENGTH, 1}; // powers of ALPHABET_LENGTH
	char data[4]{};

	for (int i = 0; i < 3; ++i) {
		int pos = value / pows[i];
		value = value % pows[i];
		data[i] = ALPHABET[pos];
	}
	return data;
}

/*
   Perform decrypting in range.
   Min(startRange) = 0
   Max(endRange) = 62^3 (excluded)
*/
void decryptCypher(int startRange, int endRange)
try
{
	/*
	Target file has the following format:
	1. 8 bytes of initial value for Triple DES
	2. encrypted block
	3. 32 bytes of SHA256 from original text
	*/

	for (int i = startRange; i < endRange; ++i)
	{
		SecByteBlock key(DES_EDE2::DEFAULT_KEYLENGTH);

		ByteVector digestMD5(CryptoPP::Weak::MD5::DIGESTSIZE);
		std::string password = getPasswordByValue(i);

		CryptoPP::Weak::MD5 md5Engine;
		md5Engine.CalculateDigest(digestMD5.data(),
			reinterpret_cast <const byte *> (password.c_str()),
			password.length());

		std::copy(digestMD5.begin(), digestMD5.end(), stdext::checked_array_iterator<byte*>(key.begin(), digestMD5.size()));

		std::string recovered;
		CBC_Mode<DES_EDE2>::Decryption decryptEngine;
		decryptEngine.SetKeyWithIV(key, key.size(), g_initVector.data());

		StringSource stringSource(g_cypher, true,
			new StreamTransformationFilter(decryptEngine,
				new StringSink(recovered), CryptoPP::BlockPaddingSchemeDef::NO_PADDING
			)
		);

		ByteVector digest(CryptoPP::SHA256::DIGESTSIZE);
		CryptoPP::SHA256().CalculateDigest(digest.data(), reinterpret_cast <const byte *> (recovered.data()), recovered.size());

		if (std::equal(g_checkValue.begin(), g_checkValue.end(), digest.begin()))
		{
			g_collisionMutex.lock();
			if (!g_taskCompleted) {
				g_taskCompleted = true;
				std::cout << "FOUND PASSWORD! " << password << std::endl;
				std::cout << "result saved to " << RESULT_FILE_NAME << std::endl;
				saveBinaryToFile(RESULT_FILE_NAME, recovered);
			}
			g_collisionMutex.unlock();
		}
		if (g_taskCompleted)
		{
			break;
		}
	}
}
catch (std::exception & e) {
	std::lock_guard<std::mutex> lock(g_collisionMutex);
	std::cout << "Exception in thread " << e.what() << std::endl;
}
