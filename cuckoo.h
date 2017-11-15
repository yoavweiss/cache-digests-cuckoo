#ifndef Cuckoo_H
#define Cuckoo_H

#include <string>

class Cuckoo {

public:
    Cuckoo(unsigned probability, unsigned entries);
    ~Cuckoo();
    const char* getDigest();

    static void add(char* digest, std::string URL, std::string ETag, unsigned maxcount);
    static void remove(char* digest, std::string URL, std::string ETag);
    static bool query(const char* digest, std::string URL, std::string ETag);

    // For testing only
    void runTests();
private:

    static unsigned long fingerprint(std::string key, unsigned fingerprintSize);
    static unsigned hash(std::string key, unsigned entries);
    static std::string key(std::string URL, std::string ETag);
    static void bigEndianWrite(char* digest, unsigned startPosition, size_t length, unsigned long number);
    static unsigned long bigEndianRead(const unsigned char* digest, unsigned startPosition, size_t length);
    static unsigned long readFingerprint(const char* hash, unsigned length, unsigned positionInBits, unsigned fingerprintSizeInBits);

    char* m_digest;
    size_t m_digestSize;
    const size_t BucketSize = 4;


};
#endif
