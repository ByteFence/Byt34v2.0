#pragma once
#include <string>
#include <unordered_set>
#include <vector>
#include <filesystem>
#include <yara.h>
#include <functional>

extern std::unordered_set<std::string> yaraMatchedFiles;
extern std::unordered_set<std::string> malwareHashes;

// File operations
void quarantineFile(const std::string& filePath);
void deleteFile(const std::string& filePath);

// Hash operations
std::unordered_set<std::string> loadSha256Hashes(const std::string& filename);
std::string computeHash(const std::string& filePath);

// YARA compilation and callback
YR_RULES* compileYaraRules(const std::string& rulePath);
int yaraCallback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data);

// Directory scanner
void scanDirectory(const std::filesystem::path& dir,
    const std::unordered_set<std::string>& db,
    std::vector<std::pair<std::string, std::string>>& normal,
    std::vector<std::pair<std::string, std::string>>& malicious,
    YR_RULES* yaraRules);

// Modular scan + cleanup
void yaraScanFile(const std::string& filePath, YR_RULES* rules, std::function<void(const std::string&)> onMatch);

void destroyYaraRules(YR_RULES* rules);