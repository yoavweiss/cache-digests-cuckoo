#ifndef Cuckoo_H
#define Cuckoo_H

#include <string>

class Cuckoo {

public:
    Cuckoo(unsigned probability, unsigned entries);
    ~Cuckoo();
    const char* getDigest();

    void add(std::string URL, std::string ETag, unsigned maxcount);
    void remove(std::string URL, std::string ETag);
    bool query(std::string URL, std::string ETag);

    // For testing only
    void runTests();
private:

    unsigned long fingerprint(std::string key, unsigned fingerprintSize);
    unsigned hash(std::string key, unsigned entries);
    std::string key(std::string URL, std::string ETag);
    static void bigEndianWrite(char* digest, unsigned startPosition, size_t length, unsigned long number);
    unsigned long bigEndianRead(const unsigned char* digest, unsigned startPosition, size_t length);
    unsigned long readFingerprint(const char* hash, unsigned length, unsigned positionInBits, unsigned fingerprintSizeInBits);

    char* m_digest;
    size_t m_digestSize;
    const size_t BucketSize = 4;


};
#endif
