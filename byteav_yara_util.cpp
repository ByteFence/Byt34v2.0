// Add this to ByteAV.cpp or separate file if you prefer modularity
#include "ByteAV.h"
#include <yara.h>
#include <iostream>

void yaraScanFile(const std::string& filePath, YR_RULES* rules, std::function<void(const std::string&)> onMatch) {
    auto callback = [](YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) -> int {
        if (message == CALLBACK_MSG_RULE_MATCHING) {
            YR_RULE* rule = (YR_RULE*)message_data;
            auto* fn = static_cast<std::function<void(const std::string&)>*>(user_data);
            (*fn)(rule->identifier);
        }
        return CALLBACK_CONTINUE;
        };

    if (yr_rules_scan_file(rules, filePath.c_str(), 0, callback, &onMatch, 0) != ERROR_SUCCESS) {
        std::cerr << "[YARA] Failed to scan file: " << filePath << "\n";
    }
}

void destroyYaraRules(YR_RULES* rules) {
    if (rules) {
        yr_rules_destroy(rules);
        yr_finalize();
    }
}
