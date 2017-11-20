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
#include <fstream>
#include <vector>

int main() {
    const unsigned MaxCount = 500;
    const unsigned DigestSize = 1021;
    const unsigned URLNumber = 3250;

    // Create a digest
    Cuckoo cuckoo(8, DigestSize, MaxCount);

    // Run a set of sanity tests
    cuckoo.runTests();

    unsigned char* digest = cuckoo.getDigest();
    size_t digestSize = cuckoo.getDigestSize();

    std::vector<std::string> urls;
    for (int i = 0; i < URLNumber; ++i) {
        urls.push_back(std::to_string(i));
    }
    unsigned minmaxcount = 500;
    for (auto& url : urls) {
        unsigned maxcount = cuckoo.add(url, std::string());
        if (maxcount < minmaxcount)
            minmaxcount = maxcount;
    }
    printf("Maximum cucko pushes %u\n", MaxCount - minmaxcount);

    // Write the digest to disk
    std::ofstream outfile;
    outfile.open("digest.bin", std::ios::binary);
    if (outfile.is_open()) {
        outfile.write((const char*)cuckoo.getDigest(), cuckoo.getDigestSize());
        outfile.close();
    }

    // See if the URLs are in the digest
    for (auto& url : urls) {
        if (!cuckoo.query(url, std::string()))
            printf("FAIL - %s is not in the digest\n", url.c_str());
    }
    if (cuckoo.query("blabla", std::string()))
        printf("FAIL - blabla should not be in the digest\n");

    // Remove from the digest
    for (auto& url : urls) {
        cuckoo.remove(url, std::string());
    }
    // Make sure that the URLs are no longer in the digest
    for (auto& url : urls) {
        if (cuckoo.query(url, std::string()))
            printf("FAIL - %s is still in the digest\n", url.c_str());
    }
}
