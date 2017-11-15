#include "cuckoo.h"
#define NDEBUG
#include <cassert>
#include <math.h>
#include <cstring>
#include <cstdlib>
#include <openssl/sha.h>

Cuckoo::Cuckoo(unsigned probability, unsigned entries) {
    assert(probability < 256);
    assert(entries < pow(2,32));

    unsigned fingerprintSize = probability + 3;
    unsigned bytes = ceil((float)(fingerprintSize * entries * BucketSize) / 8.0);
    bytes += 5;
    m_digest = new char[bytes];
    m_digestSize = bytes;
    memset(m_digest, 0, bytes);
    m_digest[0] = (char)probability;
    bigEndianWrite(m_digest, 1, 4, entries);
}
Cuckoo::~Cuckoo() {
    delete m_digest;
}

void Cuckoo::add(std::string URL, std::string ETag, unsigned maxcount) {
    unsigned fingerprintSize = m_digest[0];
    unsigned long entries = bigEndianRead((const unsigned char*)m_digest, 1, 4);

}

void Cuckoo::bigEndianWrite(char* digest, unsigned startPosition, size_t length, unsigned long number) {
    const unsigned long digit = 0xff;
    for (int i = length - 1; i >= 0; --i) {
        unsigned long temp = number & digit;
        digest[startPosition + i] = temp;
        number >>= 8;
    }
}

unsigned long Cuckoo::bigEndianRead(const unsigned char* digest, unsigned startPosition, size_t length) {
    unsigned long readNumber = 0;
    for (unsigned i = 0; i < length; ++i) {
        readNumber <<= 8;
        readNumber += digest[startPosition + i];
    }
    return readNumber;
}

std::string Cuckoo::key(std::string URL, std::string ETag) {
    // TODO(yoav): Convert to ascii.
    std::string keyString = URL;
    // TODO(yoav): Only add the double quotes if they are not already there.
    if (!ETag.empty())
        keyString += "\"" + ETag + "\"";
    return keyString;
}

unsigned Cuckoo::hash(std::string key, unsigned entries) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, key.c_str(), key.size());
    SHA256_Final(hash, &sha256);
    // Truncate to 32 bits
    unsigned long hashValue = bigEndianRead((const unsigned char *)hash, SHA256_DIGEST_LENGTH - 4, 4);
    // Modulo to find the slot in the hash table
    return hashValue % entries;
}

unsigned long Cuckoo::fingerprint(std::string key, unsigned fingerprintSize) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, key.c_str(), key.size());
    SHA256_Final(hash, &sha256);
    unsigned long fingerprint;
    for (unsigned i = SHA256_DIGEST_LENGTH * 8 - fingerprintSize; i >= fingerprintSize; i -= fingerprintSize) {
        fingerprint = readFingerprint((char*)hash, SHA256_DIGEST_LENGTH, i, fingerprintSize);
        if (fingerprint != 0)
            break;
    }
    if (fingerprint == 0)
        fingerprint = 1;
    return fingerprint;
}

unsigned long Cuckoo::readFingerprint(const char* hash, unsigned length, unsigned positionInBits, unsigned fingerprintSizeInBits) {
    const float Bits = 8.0;
    unsigned endPositionInBits = positionInBits + fingerprintSizeInBits;
    unsigned startPositionInBytes = floor((float)positionInBits / Bits);
    unsigned endPositionInBytes = ceil((float)endPositionInBits / Bits);
    unsigned lengthInBytes = endPositionInBytes - startPositionInBytes;
    unsigned long hashValue = bigEndianRead((const unsigned char *)(hash), startPositionInBytes, lengthInBytes);
    unsigned extraBitsAtStart = positionInBits - startPositionInBytes * Bits;
    unsigned extraBitsAtEnd = endPositionInBytes * Bits - endPositionInBits;
    unsigned extraBytes = sizeof(hashValue) - lengthInBytes;
    // TODO(yoav): There's probably a better way to do this, but I'm too jetlagged to think.
    hashValue <<= extraBytes * (unsigned)Bits + extraBitsAtStart;
    hashValue >>= extraBytes * (unsigned)Bits + extraBitsAtStart + extraBitsAtEnd;
    return hashValue;
}

unsigned char hex(unsigned char input) {
    if (input >= '0' && input <= '9')
        return input - '0';
    if (input >= 'a' && input <= 'f') {
        return 10 + input - 'a';
    }
    if (input >= 'A' && input <= 'F') {
        return 10 + input - 'A';
    }
    return 0;
}

void Cuckoo::runTests() {
    // Test bigEndianRead
    std::string hashStr = "1234567";
    unsigned long hashNumber = bigEndianRead((const unsigned char*)hashStr.c_str(), 1, 4);
    if (hashNumber != 842216501) {
        printf("Fail - hashNumber %lu", hashNumber);
    }
    // Test bigEndianWrite
    char testDigest[10];
    testDigest[0] = 49;
    bigEndianWrite(testDigest, 1, 4, 842216501);
    testDigest[5] = 0;
    if (testDigest != std::string("12345")) {
        printf("Fail - bigEndianWrite got %s\n", testDigest);
    }
    // Test readFingerprint
    hashStr = "0123456789abcdef";
    char fingerprintHash[16];
    strncpy(fingerprintHash, hashStr.c_str(), 16);
    unsigned long fingerprintValue = readFingerprint(fingerprintHash, 16, 121, 7);
    if (fingerprintValue != 102)
        printf("FAIL - readFingerprint %lu\n", fingerprintValue);
    fingerprintValue = readFingerprint(fingerprintHash, 16, 117, 7);
    if (fingerprintValue!= 86)
        printf("FAIL - readFingerprint %lu\n", fingerprintValue);
    char shaInStr[65] = "2442a9b40768c5ccff9366514374eeca86fd6a3156b11d5f7aaad7b1e3fbbb08";
    char fingerprintHash2[32];
    for (int i = 0; i < 32; ++i) {
        unsigned char letter = hex(shaInStr[2*i]) * 16 + hex(shaInStr[2*i+1]);
        fingerprintHash2[i] = letter;
    }
    fingerprintValue = readFingerprint(fingerprintHash2, 32, 247, 9);
    if (fingerprintValue!= 264)
        printf("FAIL - readFingerprint %lu\n", fingerprintValue);

    // Test hash calculation
    std::string keyStr = key("https://example.com/bla.gif", "34bfac");
    unsigned long hashValue = hash(keyStr, 2513);
    if (hashValue != 1233)
        printf("FAIL - hash calculation %lu\n", hashValue);

    // Test fingerprint
    keyStr = key("https://example.com/bla.gif", "34bfac");
    fingerprintValue = fingerprint(keyStr, 9);
    if (fingerprintValue != 264)
        printf("FAIL - fingerprint calculation %lu\n", fingerprintValue);
}
