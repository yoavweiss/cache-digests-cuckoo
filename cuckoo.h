#ifndef Cuckoo_H
#define Cuckoo_H

#include <string>

class Cuckoo {

public:
    Cuckoo(unsigned probability, unsigned entries);
    ~Cuckoo();
    unsigned char* getDigest() { return m_digest; }
    size_t getDigestSize() { return m_digestSize; }

    static unsigned add(unsigned char* digest, size_t digestSize, std::string URL, std::string ETag, unsigned maxcount);
    static void remove(unsigned char* digest, size_t digestSize, std::string URL, std::string ETag);
    static bool query(const unsigned char* digest, size_t digestSize, std::string URL, std::string ETag);

    // For testing only
    void runTests();
private:

    static unsigned long fingerprint(std::string key, unsigned fingerprintSize);
    static unsigned hash(std::string key, unsigned entries);
    static std::string key(std::string URL, std::string ETag);
    static void bigEndianWrite(unsigned char* digest, unsigned startPosition, size_t length, unsigned long number);
    static unsigned long bigEndianRead(const unsigned char* digest, unsigned startPosition, size_t length);
    static unsigned long readFingerprint(const unsigned char* hash, unsigned positionInBits, unsigned fingerprintSizeInBits);
    static void writeFingerprint(unsigned char* hash, unsigned positionInBits, unsigned fingerprintSizeInBits, unsigned long fingerprintValue);

    unsigned char* m_digest;
    size_t m_digestSize;
    // Let `b` be the bucket size, defined as 4.
    static const size_t BucketSize = 4;


};
#endif
