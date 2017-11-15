#include "cuckoo.h"
#include <fstream>
#include <vector>

int main() {

    // Create a digest
    Cuckoo cuckoo(256, 2503);

    // Run a set of sanity tests
    cuckoo.runTests();

    const unsigned MaxCount = 500;
    unsigned char* digest = cuckoo.getDigest();
    size_t digestSize = cuckoo.getDigestSize();

    // Get a list of URLs from chrome://cache and add them to the digest
    std::ifstream infile("cache_resources.txt");
    std::string url;
    std::vector<std::string> urls;
    while (std::getline(infile, url)) {
        urls.push_back(url);
    }
    infile.close();
    for (auto& url : urls) {
        Cuckoo::add(cuckoo.getDigest(), url, std::string(), MaxCount);
    }
    // Write the digest to disk
    std::ofstream outfile;
    outfile.open("digest.bin", std::ios::binary);
    if (outfile.is_open()) {
        outfile.write((const char*)cuckoo.getDigest(), cuckoo.getDigestSize());
        outfile.close();
    }
    // Get a list of URLs from chrome://cache and query to see they're in the digest
    for (auto& url : urls) {
        if (!Cuckoo::query(cuckoo.getDigest(), url, std::string()))
            printf("FAIL - %s is not in the digest\n", url.c_str());
    }
    if (Cuckoo::query(cuckoo.getDigest(), "blabla", std::string()))
        printf("FAIL - blabla should not be in the digest\n");
    // Remove from the digest
    for (auto& url : urls) {
        Cuckoo::remove(cuckoo.getDigest(), url, std::string());
        if (Cuckoo::query(cuckoo.getDigest(), url, std::string()))
            printf("FAIL - %s is still in the digest\n", url.c_str());
    }

}
