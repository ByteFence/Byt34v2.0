#include "monitor.h"
#include "ByteAV.h"
#include <windows.h>
#include <thread>
#include <iostream>
#include <chrono>

static std::thread watcherThread;
static std::atomic<bool>* stopFlagPtr = nullptr;

extern std::vector<std::pair<std::string, std::string>> scanResults;
extern std::vector<std::string> logs;

void scanFileWithYara(const std::string& filePath, YR_RULES* rules) {
    yaraScanFile(filePath, rules, [&](const std::string& ruleName) {
        scanResults.push_back({ filePath, "Matched" });
        logs.push_back("[MONITOR] Matched: " + filePath + " (" + ruleName + ")");
        });
}

void watchLoop(std::filesystem::path dir, YR_RULES* rules, std::atomic<bool>& stopFlag) {
    HANDLE hDir = CreateFileW(
        dir.wstring().c_str(), FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS, nullptr);

    if (hDir == INVALID_HANDLE_VALUE) {
        std::cerr << "[Monitor] Failed to open directory." << std::endl;
        return;
    }

    char buffer[1024];
    DWORD bytesReturned;

    while (!stopFlag.load()) {
        if (ReadDirectoryChangesW(hDir, buffer, sizeof(buffer), FALSE,
            FILE_NOTIFY_CHANGE_FILE_NAME, &bytesReturned,
            nullptr, nullptr)) {

            FILE_NOTIFY_INFORMATION* fni = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buffer);
            do {
                std::wstring filename(fni->FileName, fni->FileNameLength / sizeof(wchar_t));
                auto fullPath = dir / filename;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                scanFileWithYara(fullPath.string(), rules);

                if (fni->NextEntryOffset == 0) break;
                fni = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(reinterpret_cast<BYTE*>(fni) + fni->NextEntryOffset);
            } while (true);
        }
    }

    CloseHandle(hDir);
}

void startDirectoryMonitor(const std::filesystem::path& dirToWatch, YR_RULES* rules, std::atomic<bool>& stopFlag) {
    stopFlagPtr = &stopFlag;
    watcherThread = std::thread(watchLoop, dirToWatch, rules, std::ref(stopFlag));
}

void stopDirectoryMonitor() {
    if (stopFlagPtr) stopFlagPtr->store(true);
    if (watcherThread.joinable()) watcherThread.join();
}
