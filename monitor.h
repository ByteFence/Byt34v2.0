// monitor.h
#pragma once
#include <string>
#include <filesystem>
#include <atomic>
#include <yara.h>

// Fixed function declarations
void startDirectoryMonitor(const std::filesystem::path& dirToWatch, YR_RULES* rules, std::atomic<bool>& stopFlag);
void stopDirectoryMonitor();
void scanFileWithYara(const std::string& filePath, YR_RULES* rules);