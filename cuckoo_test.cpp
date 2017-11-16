#include "cuckoo.h"
#include <fstream>
#include <vector>

int main() {
    const unsigned MaxCount = 500;

    // Create a digest
    Cuckoo cuckoo(8, 2039, MaxCount);

    // Run a set of sanity tests
    cuckoo.runTests();

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

    // Get a list of URLs from chrome://cache and query to see they're in the digest
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
    for (auto& url : urls) {
        if (cuckoo.query(url, std::string()))
            printf("FAIL - %s is still in the digest\n", url.c_str());
    }
}
