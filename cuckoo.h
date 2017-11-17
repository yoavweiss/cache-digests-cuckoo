// Copyright 2017 Akamai Technologies, Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef Cuckoo_H
#define Cuckoo_H

#include <string>

class Cuckoo {

public:
    Cuckoo(unsigned probability, unsigned entries, int maxCount);
    ~Cuckoo();
    unsigned char* getDigest() { return m_digest; }
    size_t getDigestSize() { return m_digestSize; }

    unsigned add(std::string URL, std::string ETag);
    void remove(std::string URL, std::string ETag);
    bool query(std::string URL, std::string ETag);

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
    //* `maxcount` - max number of cuckoo hops
    int m_maxCount;
    // Let `b` be the bucket size, defined as 4.
    static const size_t BucketSize = 4;


};
#endif
