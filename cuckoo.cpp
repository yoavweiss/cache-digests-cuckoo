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

#include "cuckoo.h"
#include <cassert>
#include <math.h>
#include <cstring>
#include <cstdlib>
#include <openssl/sha.h>

// ### Creating a digest {#creating}
Cuckoo::Cuckoo(unsigned probability, unsigned entries, int maxCount) {
    // Given the following inputs:
    // * `P`, an integer smaller than 256, that indicates the probability of a false positive that is acceptable, expressed as `1/2\*\*P`.
    // * `N`, an integer that represents the number of entries - a prime number smaller than 2\*\*32
    assert(probability < 256);
    assert(entries < pow(2,32));

    // 1. Let `f` be the number of bits per fingerprint, calculated as `P + 3`
    unsigned fingerprintSize = probability + 3;

    // 3. Let `allocated` be the closest power of 2 that is larger than `N`.
    unsigned logEntries = ceil(log2(entries));
    unsigned allocationEntries = (unsigned)pow(2, logEntries);
    // 4. Let `bytes` be `f`\*`allocated`\*`b`/8 rounded up to the nearest integer
    unsigned bytes = ceil((float)(fingerprintSize * allocationEntries * BucketSize) / 8.0);
    // 5. Add 5 to `bytes`
    bytes += 5;
    // 6. Allocate memory of `bytes` and set it to zero. Assign it to `digest-value`.
    m_digest = new unsigned char[bytes];
    memset(m_digest, 0, bytes);

    // 7. Set the first byte to `P`
    m_digest[0] = (char)fingerprintSize;
    // 8. Set the second till fifth bytes to `N` in big endian form
    bigEndianWrite(m_digest, 1, 4, entries);

    m_digestSize = bytes;
    m_maxCount = maxCount;
}

Cuckoo::~Cuckoo() {
    delete m_digest;
}

// ### Adding a URL to the Digest-Value {#adding}
unsigned Cuckoo::add(std::string URL, std::string ETag) {
    //Given the following inputs:
    //
    //* `URL` a string corresponding to the Effective Request URI ({{RFC7230}}, Section 5.5) of a cached
    //response {{RFC7234}}
    //* `ETag` a string corresponding to the entity-tag {{RFC7232}} of a cached response {{RFC7234}} (if
    //the ETag is available; otherwise, null);
    //* `maxcount` - max number of cuckoo hops
    //* `digest-value`
    int maxCount = m_maxCount;
    unsigned char* digest = m_digest;
    size_t digestSize = m_digestSize;

    // 1. Let `f` be the value of the first byte of `digest-value`.
    unsigned fingerprintSize = digest[0];
    // 3. Let `N` be the value of the second to fifth bytes of `digest-value` in big endian form.
    unsigned long entries = bigEndianRead(digest, 1, 4);
    // 4. Let `key` be the return value of {{key}} with `URL` and `ETag` as inputs.
    std::string keyStr = key(URL, ETag);
    // 5. Let `h1` be the return value of {{hash}} with `key` and `N` as inputs.
    unsigned long h1 = hash(keyStr, entries);
    // 6. Let `fingerprint` be the return value of {{fingerprint}} with `key` and `f` as inputs.
    unsigned long destinationFingerprintValue = fingerprint(keyStr, fingerprintSize);
    char fingerprintString[20];
    while (maxCount) {
        // 7. Let `fingerprint-string` be the value of `fingerprint` in base 10, expressed as a string.
        sprintf((char*)fingerprintString, "%lu", destinationFingerprintValue);
        // 8. Let `h2` be the return value of {{hash}} with `fingerprint-string` and `N` as inputs, XORed with `h1`.
        unsigned long h2 = hash(std::string(fingerprintString), entries);
        h2 ^= h1;
        // 9. Let `h` be either `h1` or `h2`, picked in random.
        int randomNumber = rand() % 2;
        unsigned long h = (randomNumber != 0) ? h1 : h2;
        // 10. Let `position_start` be 40 + `h` * `f` \* `b`.
        unsigned positionStart = 40 + h * fingerprintSize * BucketSize;
        // 11. Let `position_end` be `position_start` + `f` \* `b`.
        unsigned positionEnd = positionStart + fingerprintSize * BucketSize;
        // Make sure we're not writing outside the table.
        assert(ceil(positionEnd / 8) <= digestSize);
        unsigned long fingerprintValue;
        // 12. While `position_start` < `position_end`:
        while (positionStart < positionEnd) {
            // 1. Let `bits` be `f` bits from `digest_value` starting at `position_start`.
            fingerprintValue = readFingerprint(digest, positionStart, fingerprintSize);
            // 2. If `bits` is all zeros, set `bits` to `fingerprint` and terminate these steps.
            if (fingerprintValue == 0) {
                writeFingerprint(digest, positionStart, fingerprintSize, destinationFingerprintValue);
                return maxCount;
            }
            // 3. Add `f` to `position_start`.
            positionStart += fingerprintSize;
        }
        // 13. Substract `f` from `position_start`.
        positionStart -= fingerprintSize;
        // 14. Let `fingerprint` be the `f` bits starting at `position_start`.
        writeFingerprint(digest, positionStart, fingerprintSize, destinationFingerprintValue);
        destinationFingerprintValue = fingerprintValue;
        // 15. Let `h1` be `h`
        h1 = h;
        // 16. Substract 1 from `maxcount`.
        --maxCount;
        // 17. If `maxcount` is zero, return an error.
        // 18. Go to step 7.
    }
    printf("ERROR - maxcount reached\n");
    return 0;
}

// ### Querying the Digest for a Value {#querying}
bool Cuckoo::query(std::string URL, std::string ETag) {
    //Given the following inputs:
    //
    //* `URL` a string corresponding to the Effective Request URI ({{RFC7230}}, Section 5.5) of a cached
    //response {{RFC7234}}.
    //* `ETag` a string corresponding to the entity-tag {{RFC7232}} of a cached response {{RFC7234}} (if
    //the ETag is available; otherwise, null).
    //* `digest-value`, an array of bits.
    const unsigned char* digest = m_digest;
    size_t digestSize = m_digestSize;

    // 1. Let `f` be the value of the first byte of `digest-value`.
    unsigned fingerprintSize = digest[0];
    // 3. Let `N` be the value of the second to fifth bytes of `digest-value` in big endian form.
    unsigned long entries = bigEndianRead(digest, 1, 4);
    // 4. Let `key` be the return value of {{key}} with `URL` and `ETag` as inputs.
    std::string keyStr = key(URL, ETag);
    // 5. Let `h1` be the return value of {{hash}} with `key` and `N` as inputs.
    unsigned long h1 = hash(keyStr, entries);
    // 6. Let `fingerprint` be the return value of {{fingerprint}} with `key` and `f` as inputs.
    unsigned long destinationFingerprintValue = fingerprint(keyStr, fingerprintSize);
    // 7. Let `fingerprint-string` be the value of `fingerprint` in base 10, expressed as a string.
    char fingerprintString[20];
    sprintf((char*)fingerprintString, "%lu", destinationFingerprintValue);
    // 8. Let `h2` be the return value of {{hash}} with `fingerprint` and `N` as inputs, XORed with `h1`.
    unsigned long h2 = hash(std::string(fingerprintString), entries) ^ h1;
    unsigned long hashes[2];
    // 9. Let `h` be `h1`.
    hashes[0] = h1;
    hashes[1] = h2;
    for (int i = 0; i < 2; ++i) {
        unsigned long h = hashes[i];
        // 10. Let `position_start` be 40 + `h` \* `f` \* `b`.
        unsigned positionStart = 40 + h * fingerprintSize * BucketSize;
        // 11. Let `position_end` be `position_start` + `f` \* `b`.
        unsigned positionEnd = positionStart + fingerprintSize * BucketSize;
        unsigned long fingerprintValue;
        // Make sure we're not reading beyond the table.
        assert(ceil(positionStart / 8) <= digestSize);
        // 12. While `position_start` < `position_end`:
        while (positionStart < positionEnd) {
            // 1. Let `bits` be `f` bits from `digest_value` starting at `position_start`.
            fingerprintValue = readFingerprint(digest, positionStart, fingerprintSize);
            // 2. If `bits` is `fingerprint`, return true
            if (fingerprintValue == destinationFingerprintValue) {
                return true;
            }
            // 3. Add `f` to `position_start`.
            positionStart += fingerprintSize;
        }
        // 13. If `h` is not `h2`, set `h` to `h2` and return to step 10.
    }
    // 14. Return false.
    return false;
}

// ### Removing a URL to the Digest-Value {#removing}
void Cuckoo::remove(std::string URL, std::string ETag) {
    // Given the following inputs:
    //
    // * `URL` a string corresponding to the Effective Request URI ({{RFC7230}}, Section 5.5) of a cached
    // response {{RFC7234}}
    // * `ETag` a string corresponding to the entity-tag {{RFC7232}} of a cached response {{RFC7234}} (if
    // the ETag is available; otherwise, null);
    // * `digest-value`
    unsigned char* digest = m_digest;
    size_t digestSize = m_digestSize;

    // 1. Let `f` be the value of the first byte of `digest-value`.
    unsigned fingerprintSize = digest[0];
    // 3. Let `N` be the value of the second to fifth bytes of `digest-value` in big endian form.
    unsigned long entries = bigEndianRead(digest, 1, 4);
    // 4. Let `key` be the return value of {{key}} with `URL` and `ETag` as inputs.
    std::string keyStr = key(URL, ETag);
    // 5. Let `h1` be the return value of {{hash}} with `key` and `N` as inputs.
    unsigned long h1 = hash(keyStr, entries);
    // 6. Let `fingerprint` be the return value of {{fingerprint}} with `key` and `f` as inputs.
    unsigned long destinationFingerprintValue = fingerprint(keyStr, fingerprintSize);
    // 7. Let `fingerprint-string` be the value of `fingerprint` in base 10, expressed as a string.
    char fingerprintString[20];
    sprintf((char*)fingerprintString, "%lu", destinationFingerprintValue);
    // 8. Let `h2` be the return value of {{hash}} with `fingerprint-string` and `N` as inputs, XORed with `h1`.
    unsigned long h2 = hash(std::string(fingerprintString), entries) ^ h1;
    unsigned long hashes[2];
    // 9. Let `h` be `h1`.
    hashes[0] = h1;
    hashes[1] = h2;
    for (int i = 0; i < 2; ++i) {
        unsigned long h = hashes[i];
        // 10. Let `position_start` be 40 + `h` \* `f` \* `b`.
        unsigned positionStart = 40 + h * fingerprintSize * BucketSize;
        // 11. Let `position_end` be `position_start` + `f` \* `b`.
        unsigned positionEnd = positionStart + fingerprintSize * BucketSize;
        unsigned long fingerprintValue;
        // Make sure we're not reading outside the table.
        assert(ceil(positionStart / 8) <= digestSize);
        // 12. While `position_start` < `position_end`:
        while (positionStart < positionEnd) {
            // 1. Let `bits` be `f` bits from `digest_value` starting at `position_start`.
            fingerprintValue = readFingerprint(digest, positionStart, fingerprintSize);
            // 2. If `bits` is `fingerprint`, set `bits` to all zeros and terminate these steps.
            if (fingerprintValue == destinationFingerprintValue) {
                writeFingerprint(digest, positionStart, fingerprintSize, 0);
                return;
            }
            // 3. Add `f` to `position_start`.
            positionStart += fingerprintSize;
        }
        // 13. If `h` is not `h2`, set `h` to `h2` and return to step 10.
    }
}

// ### Computing the key {#key}
std::string Cuckoo::key(std::string URL, std::string ETag) {
    // Given the following inputs:
    //
    // * `URL`, an array of characters
    // * `ETag`, an array of characters
    // 1. Let `key` be `URL` converted to an ASCII string by percent-encoding as appropriate {{RFC3986}}.
    // TODO(yoav): Convert to ascii.
    std::string keyString = URL;
    // 2. If `ETag` is not null:
    if (!ETag.empty()) {
        // 1. Append `ETag` to `key` as an ASCII string, including both the `weak` indicator (if present) and double quotes, as per {{RFC7232}}, Section 2.3.
        // TODO(yoav): Only add the double quotes if they are not already there.
        keyString += "\"" + ETag + "\"";
    }
    return keyString;
}

// ### Computing a Hash Value {#hash}
unsigned Cuckoo::hash(std::string key, unsigned entries) {
    // Given the following inputs:
    //
    // * `key`, an array of characters.
    // * `N`, an integer

    // 1. Let `hash-value` be the SHA-256 message digest {{RFC6234}} of `key`, truncated to 32 bits, expressed as an integer.
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, key.c_str(), key.size());
    SHA256_Final(hash, &sha256);
    // Truncate to 32 bits
    unsigned long hashValue = bigEndianRead((const unsigned char *)hash, SHA256_DIGEST_LENGTH - 4, 4);
    // 2. Return `hash-value` modulo N.
    return hashValue % entries;
}

// ### Computing a fingerprint value {#fingerprint}
unsigned long Cuckoo::fingerprint(std::string key, unsigned fingerprintSize) {
    // Given the following inputs:
    //
    // * `key`, an array of characters
    // * `f`, an integer indicating the number of output bits

    assert(fingerprintSize > 0);
    // 1. Let `hash-value` be the SHA-256 message digest {{RFC6234}} of `key`, expressed as an integer.
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, key.c_str(), key.size());
    SHA256_Final(hash, &sha256);
    unsigned long fingerprintValue;
    // Note: the implementation below diverges from the literal specified steps, but achieves the same goals.
    // 2. Let `h` be the number of bits in `hash-value`
    // 3. Let `fingerprint-value` be 0
    // 4. While `fingerprint-value` is 0 and `h` > `f`:
    for (unsigned i = SHA256_DIGEST_LENGTH * 8 - fingerprintSize; i >= fingerprintSize; i -= fingerprintSize) {
        // 1. Let `fingerprint-value` be the `f` least significant bits of `hash-value`.
        // 2. Let `hash-value` be the `h`-`f` most significant bits of `hash-value`.
        // 3. Substract `f` from `h`.
        fingerprintValue = readFingerprint(hash, i, fingerprintSize);
        if (fingerprintValue != 0)
            break;
    }
    // 5. If `fingerprint-value` is 0, let `fingerprint-value` be 1.
    if (fingerprintValue == 0)
        fingerprintValue = 1;
    // 6. Return `fingerprint-value`.
    return fingerprintValue;
}

// Utility functions below

void Cuckoo::bigEndianWrite(unsigned char* digest, unsigned startPosition, size_t length, unsigned long number) {
    const unsigned long digit = 0xff;
    for (int i = length - 1; i >= 0; --i) {
        unsigned long temp = number & digit;
        digest[startPosition + i] = (unsigned char)temp;
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

unsigned long Cuckoo::readFingerprint(const unsigned char* hash, unsigned positionInBits, unsigned fingerprintSizeInBits) {
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

void Cuckoo::writeFingerprint(unsigned char* hash, unsigned positionInBits, unsigned fingerprintSizeInBits, unsigned long fingerprintValue) {
    const float Bits = 8.0;
    unsigned endPositionInBits = positionInBits + fingerprintSizeInBits;
    unsigned startPositionInBytes = floor((float)positionInBits / Bits);
    unsigned endPositionInBytes = ceil((float)endPositionInBits / Bits);
    unsigned lengthInBytes = endPositionInBytes - startPositionInBytes;
    unsigned long hashValue = bigEndianRead((const unsigned char *)(hash), startPositionInBytes, lengthInBytes);
    unsigned extraBitsAtStart = positionInBits - startPositionInBytes * Bits;
    unsigned extraBitsAtEnd = endPositionInBytes * Bits - endPositionInBits;
    unsigned extraBytes = sizeof(hashValue) - lengthInBytes;
    unsigned long bitmap = -1;
    bitmap >>= extraBitsAtEnd + fingerprintSizeInBits;
    bitmap <<= extraBitsAtEnd + fingerprintSizeInBits;
    bitmap += (unsigned)(pow(2, extraBitsAtEnd)) - 1;
    hashValue &= bitmap;
    fingerprintValue <<= extraBitsAtEnd;
    hashValue |= fingerprintValue;
    bigEndianWrite(hash, startPositionInBytes, lengthInBytes, hashValue);
}

// !!! Test only code from here on out !!!
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
    unsigned char testDigest[10];
    testDigest[0] = 49;
    bigEndianWrite(testDigest, 1, 4, 842216501);
    testDigest[5] = 0;
    if ((char*)testDigest != std::string("12345")) {
        printf("Fail - bigEndianWrite got %s\n", testDigest);
    }
    // Test readFingerprint
    hashStr = "0123456789abcdef";
    unsigned char fingerprintHash[17];
    fingerprintHash[16] = 0;
    strncpy((char*)fingerprintHash, hashStr.c_str(), 16);
    unsigned long fingerprintValue = readFingerprint(fingerprintHash, 121, 7);
    if (fingerprintValue != 102)
        printf("FAIL - readFingerprint %lu\n", fingerprintValue);
    fingerprintValue = readFingerprint(fingerprintHash, 117, 7);
    if (fingerprintValue!= 86)
        printf("FAIL - readFingerprint %lu\n", fingerprintValue);
    char shaInStr[65] = "2442a9b40768c5ccff9366514374eeca86fd6a3156b11d5f7aaad7b1e3fbbb08";
    unsigned char fingerprintHash2[32];
    for (int i = 0; i < 32; ++i) {
        unsigned char letter = hex(shaInStr[2*i]) * 16 + hex(shaInStr[2*i+1]);
        fingerprintHash2[i] = letter;
    }
    fingerprintValue = readFingerprint(fingerprintHash2, 247, 9);
    if (fingerprintValue!= 264)
        printf("FAIL - readFingerprint %lu\n", fingerprintValue);


    // Test writeFingerprint
    writeFingerprint(fingerprintHash, 8, 8, 90);
    writeFingerprint(fingerprintHash, 20, 4, 5);
    writeFingerprint(fingerprintHash, 28, 3, 6);
    if (strcmp((const char*)fingerprintHash, "0Z5=456789abcdef"))
        printf("FAIL - writeFingerprint %s\n", fingerprintHash);

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
