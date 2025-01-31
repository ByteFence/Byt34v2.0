#include <iostream>
#include <thread>
#include <vector>
#include <filesystem>
#include <mutex>
#include <openssl/sha.h> // For SHA-256
#include <fstream>       // For file reading
#include <sstream>       // For converting hash to string
using namespace std;
namespace fs = std::filesystem;

std::mutex printMutex; // for sync

string computehash(const string& rootDir){
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    ifstream file(rootDir,std::ios::binary);
    if(!file) return "error opening";
    char buffer[4096];
    while(file.read(buffer,sizeof(buffer))){
        SHA256_Update(&sha256,buffer,file.gcount());
    }
    //SHA256_Update(&sha256,buffer,file.gcount());
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash,&sha256);
    stringstream ss;
    for(int i=0;i<SHA256_DIGEST_LENGTH;i++)
    {
        ss<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)hash[i];
    }
    return ss.str();
}

void dir(const fs::path& dirPath) {
    try {
        for (const auto& entry : fs::directory_iterator(dirPath)) {
            {
                std::lock_guard<std::mutex> lock(printMutex);
                std::cout << "Scannning..."<<entry.path() << std::endl;
            }
            if(fs::is_regular_file(entry.status()))
            {
                string hashval = computehash(entry.path().string());
                lock_guard<mutex>lock(printMutex);
                cout<<"file: "<<entry.path()<<" | Hash: "<<hashval<<'\n';
            }
        }
    } 
    catch (const fs::filesystem_error& e) {
        std::lock_guard<std::mutex> lock(printMutex);
        std::cerr << "Error accessing " << dirPath << ": " << e.what() << std::endl;
    }
}

int main() {

    string inputpath;
    cout<<"Enter path to scan: ";
    getline(cin,inputpath);
    fs::path rootDir(inputpath);
    //fs::path rootDir = "C:/Users/Heemanshu/Desktop/All files";

    std::vector<std::thread> threads;
    int ct=0;
    try {
        dir(rootDir);
        for (const auto& entry : fs::directory_iterator(rootDir)) {
            if (fs::is_directory(entry.status())) {
                threads.emplace_back(dir, entry.path());
                ct++;
            }
        }
    } 
    catch (const fs::filesystem_error& e) {
        std::lock_guard<std::mutex> lock(printMutex);
        std::cerr << "Error accessing " << rootDir << ": " << e.what() << std::endl;
        return 1;
    }
    for (auto& t : threads) {
        t.join();
    }
    std::cout<<ct;
    return 0;
}
