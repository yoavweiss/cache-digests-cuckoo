#include "cuckoo.h"
#include <fstream>

int main() {

    // Create a digest
    Cuckoo cuckoo(256, 7919);

    // Run a set of sanity tests
    cuckoo.runTests();

    const unsigned MaxCount = 500;
    unsigned char* digest = cuckoo.getDigest();
    size_t digestSize = cuckoo.getDigestSize();

    // Get a list of URLs from chrome://cache
    std::ifstream infile("cache_resources.txt");
    std::string url;
    while (std::getline(infile, url)) {
        printf("Adding %s\n", url.c_str());
        Cuckoo::add(cuckoo.getDigest(), url, std::string(), MaxCount);
    }
    infile.close();
    std::ofstream outfile;
    outfile.open("digest.bin", std::ios::binary);
    if (outfile.is_open()) {
        outfile.write((const char*)digest, digestSize);
        outfile.close();
    }

}
