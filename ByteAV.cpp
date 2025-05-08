#define _CRT_SECURE_NO_WARNINGS
#include "ByteAV.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <openssl/evp.h>
#include <mutex>
#include <yara.h>


using namespace std;
namespace fs = std::filesystem;

std::unordered_set<std::string> yaraMatchedFiles;
static std::mutex printMutex;
static const string quarantineFolder = R"(C:\ByteAV\Quarantine)";

void quarantineFile(const std::string& filePath) {
    fs::create_directories(quarantineFolder);
    fs::path dest = fs::path(quarantineFolder) / fs::path(filePath).filename();
    try {
        fs::rename(filePath, dest);
        std::lock_guard<std::mutex> lk(printMutex);
        std::cout << "[INFO] Quarantined " << dest << "\n";
    }
    catch (...) {
        std::cerr << "[ERROR] Quarantine failed\n";
    }
}

void deleteFile(const std::string& filePath) {
    try {
        fs::remove(filePath);
        std::lock_guard<std::mutex> lk(printMutex);
        std::cout << "[INFO] Deleted " << filePath << "\n";
    }
    catch (...) {
        std::cerr << "[ERROR] Delete failed\n";
    }
}

std::unordered_set<std::string> loadSha256Hashes(const std::string& filename) {
    std::unordered_set<std::string> db;
    std::ifstream f(filename);
    std::string line;
    while (getline(f, line)) {
        if (!line.empty()) db.insert(line);
    }
    std::cout << "[INFO] Loaded " << db.size() << " hashes\n";
    return db;
}

std::string computeHash(const std::string& path) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    std::ifstream f(path, std::ios::binary);
    char buf[4096];
    while (f.read(buf, sizeof(buf))) {
        EVP_DigestUpdate(ctx, buf, f.gcount());
    }
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned len = 0;
    EVP_DigestFinal_ex(ctx, out, &len);
    EVP_MD_CTX_free(ctx);

    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned i = 0; i < len; i++) ss << std::setw(2) << (int)out[i];
    return ss.str();
}

YR_RULES* compileYaraRules(const std::string& rulePath) {
    if (yr_initialize() != ERROR_SUCCESS) {
        std::cerr << "YARA init failed\n";
        return nullptr;
    }

    YR_COMPILER* cmp = nullptr;
    yr_compiler_create(&cmp);
    FILE* fp = fopen(rulePath.c_str(), "r");

    if (!fp) {
        std::cerr << "Cannot open rule file\n";
        yr_compiler_destroy(cmp);
        return nullptr;
    }

    if (yr_compiler_add_file(cmp, fp, nullptr, rulePath.c_str()) > 0) {
        std::cerr << "Errors compiling " << rulePath << "\n";
        fclose(fp);
        yr_compiler_destroy(cmp);
        return nullptr;
    }

    fclose(fp);
    YR_RULES* rules = nullptr;
    yr_compiler_get_rules(cmp, &rules);
    yr_compiler_destroy(cmp);
    return rules;
}

int yaraCallback(YR_SCAN_CONTEXT*, int msg, void* message_data, void* user_data) {
    if (msg != CALLBACK_MSG_RULE_MATCHING) return CALLBACK_CONTINUE;
    auto* filePath = static_cast<std::string*>(user_data);
    auto* rule = reinterpret_cast<YR_RULE*>(message_data);

    yaraMatchedFiles.insert(*filePath);

    fs::create_directory("yara_logs");
    std::ofstream log("yara_logs/" + fs::path(*filePath).stem().string() + ".txt", std::ios::app);
    log << "File: " << *filePath << "\n";
    log << "Matched Rule: " << rule->identifier << "\n";

    if (rule->tags) {
        const char* p = rule->tags;
        while (*p != '\0') {
            log << p << ": TRUE\n";
            p += std::strlen(p) + 1;
        }
    }

    log << "--------------------------------\n";
    return CALLBACK_CONTINUE;
}

void scanDirectory(const fs::path& dir,
    const std::unordered_set<std::string>& db,
    std::vector<std::pair<std::string, std::string>>& normal,
    std::vector<std::pair<std::string, std::string>>& malicious,
    YR_RULES* yaraRules) {
    for (const auto& e : fs::recursive_directory_iterator(dir)) {
        if (!fs::is_regular_file(e.status())) continue;
        auto p = e.path().string();
        auto h = computeHash(p);
        if (yaraRules) {
            yr_rules_scan_file(yaraRules, p.c_str(), 0, yaraCallback, &p, 0);
        }

        std::lock_guard<std::mutex> lk(printMutex);
        std::cout << "Scanning: " << p << "\n";
        if (db.count(h) || yaraMatchedFiles.count(p)) {
            malicious.emplace_back(p, h);
        }
        else {
            normal.emplace_back(p, h);
        }
    }
}
