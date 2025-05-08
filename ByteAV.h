#pragma once
#include <string>
#include <unordered_set>
#include <vector>
#include <filesystem>
#include <yara.h>

extern std::unordered_set<std::string> yaraMatchedFiles;

void quarantineFile(const std::string& filePath);
void deleteFile(const std::string& filePath);
std::unordered_set<std::string> loadSha256Hashes(const std::string& filename);
std::string computeHash(const std::string& filePath);
YR_RULES* compileYaraRules(const std::string& rulePath);
int yaraCallback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data);
void scanDirectory(const std::filesystem::path& dir,
    const std::unordered_set<std::string>& db,
    std::vector<std::pair<std::string, std::string>>& normal,
    std::vector<std::pair<std::string, std::string>>& malicious,
    YR_RULES* yaraRules);
