// monitor.h
#pragma once
#include <string>
#include <filesystem>
#include <atomic>
#include <yara.h>

void startDirectoryMonitor(const std::filesystem::path& dirToWatch, YR_RULES* rules, std::atomic<bool>& stopFlag);
void stopDirectoryMonitor();
