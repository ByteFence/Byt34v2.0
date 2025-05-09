// byteav_yara_util.cpp
#include "ByteAV.h"
#include <iostream>
#include <mutex>
#include <string>
#include <fstream>
#include <filesystem>

namespace fs = std::filesystem;
extern std::vector<std::pair<std::string, std::string>> scanResults;
extern std::vector<std::string> logs;
extern std::unordered_set<std::string> yaraMatchedFiles;

// YARA utilities helper functions
static std::mutex yaraLogMutex;

// Function to destroy YARA rules
void destroyYaraRules(YR_RULES* rules) {
    if (rules) {
        yr_rules_destroy(rules);
    }
    yr_finalize();
}

// Modular scan function with callback for handling matches
void yaraScanFile(const std::string& filePath, YR_RULES* rules, std::function<void(const std::string&)> onMatch) {
    if (!rules || !fs::exists(filePath)) {
        return;
    }

    // Use a safer approach for callback data
    struct CallbackData {
        std::string filepath;
        std::function<void(const std::string&)> callback;
    };

    // Create callback data on the heap (will be freed after scan)
    auto* callbackData = new CallbackData{ filePath, onMatch };

    int result = yr_rules_scan_file(rules, filePath.c_str(), 0,
        [](YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) -> int {
            if (message != CALLBACK_MSG_RULE_MATCHING) return CALLBACK_CONTINUE;

            auto* data = static_cast<CallbackData*>(user_data);
            if (!data) return CALLBACK_ERROR;

            auto* rule = reinterpret_cast<YR_RULE*>(message_data);
            if (!rule) return CALLBACK_ERROR;

            std::lock_guard<std::mutex> lock(yaraLogMutex);

            // Add to global matched files set
            yaraMatchedFiles.insert(data->filepath);

            try {
                // Create detailed log
                fs::create_directory("yara_logs");
                std::ofstream log("yara_logs/" + fs::path(data->filepath).stem().string() + ".txt", std::ios::app);
                log << "File: " << data->filepath << "\n";
                log << "Matched Rule: " << rule->identifier << "\n";

                if (rule->tags) {
                    const char* tag = rule->tags;
                    while (*tag != '\0') {
                        log << "Tag: " << tag << "\n";
                        tag += std::strlen(tag) + 1;
                    }
                }

                log << "--------------------------------\n";

                // Execute callback with rule name
                if (data->callback) {
                    data->callback(rule->identifier);
                }
            }
            catch (const std::exception& e) {
                std::cerr << "[ERROR] Exception in YARA callback: " << e.what() << std::endl;
            }

            return CALLBACK_CONTINUE;
        },
        callbackData,
        0);

    // Always clean up the heap-allocated callback data
    delete callbackData;

    if (result != ERROR_SUCCESS && result != ERROR_TOO_MANY_MATCHES) {
        std::cerr << "[ERROR] YARA scan failed for file: " << filePath << std::endl;
    }
}
