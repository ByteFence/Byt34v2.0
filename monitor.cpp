// monitor.cpp
#include "monitor.h"
#include "ByteAV.h"
#include <windows.h>
#include <thread>
#include <iostream>
#include <chrono>
#include <mutex>
#include <atomic>
#include <fstream>
#include <filesystem>

static std::thread watcherThread;
static std::atomic<bool>* stopFlagPtr = nullptr;
static std::mutex resultsMutex;

extern std::vector<std::pair<std::string, std::string>> scanResults;
extern std::vector<std::string> logs;
extern std::unordered_set<std::string> malwareHashes;

void scanFileWithYara(const std::string& filePath, YR_RULES* rules) {
    try {
        // First check if file exists and is accessible
        if (!std::filesystem::exists(filePath)) {
            std::cout << "[MONITOR] File no longer exists: " << filePath << std::endl;
            return;
        }

        // Check if file is still being written to
        bool fileReady = false;
        for (int attempt = 0; attempt < 5; attempt++) {
            try {
                // Try to open the file for reading - if it's locked for writing this might fail
                std::ifstream test(filePath, std::ios::binary);
                if (test.good()) {
                    fileReady = true;
                    test.close();
                    break;
                }
                test.close();
            }
            catch (...) {
                // If we can't open it, wait and retry
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        if (!fileReady) {
            std::cout << "[MONITOR] File not accessible (might be locked): " << filePath << std::endl;
            return;
        }

        // Compute hash safely
        std::string hash;
        try {
            hash = computeHash(filePath);
        }
        catch (const std::exception& e) {
            std::cerr << "[ERROR] Failed to compute hash for " << filePath << ": " << e.what() << std::endl;
            return;
        }

        bool isMaliciousHash = false;

        // Check if the file hash is in our malware database
        if (malwareHashes.count(hash)) {
            isMaliciousHash = true;
        }

        // Use a local copy of the string for the lambda to avoid dangling reference
        std::string filePathCopy = filePath;
        std::string hashCopy = hash;

        // Perform YARA scan with proper error handling
        try {
            yaraScanFile(filePath, rules, [filePathCopy, hashCopy](const std::string& ruleName) {
                try {
                    std::lock_guard<std::mutex> lock(resultsMutex);
                    scanResults.push_back({ filePathCopy, hashCopy });
                    logs.push_back("[MONITOR] Malicious file detected: " + filePathCopy + " (" + ruleName + ")");
                    std::cout << "[ALERT] Malicious file detected: " << filePathCopy << " (Rule: " << ruleName << ")" << std::endl;

                    // Here you can add automatic quarantine actions if desired
                    // quarantineFile(filePathCopy);
                }
                catch (const std::exception& e) {
                    std::cerr << "[ERROR] Exception in YARA callback: " << e.what() << std::endl;
                }
                });
        }
        catch (const std::exception& e) {
            std::cerr << "[ERROR] YARA scan failed: " << e.what() << std::endl;
            return;
        }

        // If the file was not detected by YARA but has a known malicious hash
        if (isMaliciousHash && !yaraMatchedFiles.count(filePath)) {
            std::lock_guard<std::mutex> lock(resultsMutex);
            scanResults.push_back({ filePath, hash });
            logs.push_back("[MONITOR] Malicious file detected by hash: " + filePath);
            std::cout << "[ALERT] Malicious file detected by hash: " << filePath << std::endl;

            // Here you can add automatic quarantine actions if desired
            // quarantineFile(filePath);
        }

        // If the file is clean (no YARA match and not in hash database)
        if (!isMaliciousHash && !yaraMatchedFiles.count(filePath)) {
            std::lock_guard<std::mutex> lock(resultsMutex);
            scanResults.push_back({ filePath, hash });
            logs.push_back("[MONITOR] Clean file: " + filePath);
            std::cout << "[INFO] Clean file detected: " << filePath << std::endl;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "[ERROR] Exception scanning file " << filePath << ": " << e.what() << std::endl;
    }
}

void watchLoop(std::filesystem::path dir, YR_RULES* rules, std::atomic<bool>* stopFlag) {
    try {
        // Create directory if it doesn't exist
        if (!std::filesystem::exists(dir)) {
            std::filesystem::create_directories(dir);
        }

        HANDLE hDir = CreateFileW(
            dir.wstring().c_str(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
            nullptr);

        if (hDir == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            std::cerr << "[Monitor] Failed to open directory: " << dir.string()
                << " (Error: " << error << ")" << std::endl;
            return;
        }

        std::cout << "[MONITOR] Successfully started monitoring: " << dir.string() << std::endl;

        OVERLAPPED overlapped = { 0 };
        overlapped.hEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
        if (!overlapped.hEvent) {
            CloseHandle(hDir);
            std::cerr << "[Monitor] Failed to create event" << std::endl;
            return;
        }

        BYTE buffer[16384] = { 0 }; // Using a larger buffer for more notifications
        DWORD bytesReturned = 0;

        // Start the first async monitoring request
        BOOL success = ReadDirectoryChangesW(
            hDir,
            buffer,
            sizeof(buffer),
            TRUE,  // Watch subdirectories too
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_CREATION,
            &bytesReturned,
            &overlapped,
            nullptr);

        if (!success && GetLastError() != ERROR_IO_PENDING) {
            DWORD error = GetLastError();
            std::cerr << "[MONITOR] Initial ReadDirectoryChangesW failed: " << error << std::endl;
            CloseHandle(overlapped.hEvent);
            CloseHandle(hDir);
            return;
        }

        while (!stopFlag->load()) {
            // Wait for notification or timeout
            DWORD waitStatus = WaitForSingleObject(overlapped.hEvent, 500);

            if (waitStatus == WAIT_OBJECT_0) {
                // Get result of the read operation
                if (!GetOverlappedResult(hDir, &overlapped, &bytesReturned, FALSE)) {
                    DWORD error = GetLastError();
                    std::cerr << "[MONITOR] GetOverlappedResult failed: " << error << std::endl;
                    break;
                }

                if (bytesReturned == 0) {
                    // Reset event for next wait
                    ResetEvent(overlapped.hEvent);

                    // Start a new read
                    success = ReadDirectoryChangesW(
                        hDir, buffer, sizeof(buffer), TRUE,
                        FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_CREATION,
                        &bytesReturned, &overlapped, nullptr);

                    if (!success && GetLastError() != ERROR_IO_PENDING) {
                        DWORD error = GetLastError();
                        std::cerr << "[Monitor] ReadDirectoryChangesW failed: " << error << std::endl;
                        break;
                    }
                    continue;
                }

                // Process the notification data
                FILE_NOTIFY_INFORMATION* fni = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buffer);

                do {
                    try {
                        if (fni->FileNameLength > 0) {
                            // Convert filename from wide string
                            std::wstring wfilename(fni->FileName, fni->FileNameLength / sizeof(wchar_t));
                            std::filesystem::path fullPath = dir / wfilename;

                            // Wait for file to be fully written
                            std::this_thread::sleep_for(std::chrono::milliseconds(300));

                            // Log file activity
                            std::string action;
                            switch (fni->Action) {
                            case FILE_ACTION_ADDED: action = "Added"; break;
                            case FILE_ACTION_MODIFIED: action = "Modified"; break;
                            case FILE_ACTION_RENAMED_NEW_NAME: action = "Renamed"; break;
                            default: action = "Changed"; break;
                            }

                            // Only process if the file is accessible and a regular file
                            if (std::filesystem::exists(fullPath)) {
                                try {
                                    if (std::filesystem::is_regular_file(fullPath)) {
                                        // Log the file change
                                        std::cout << "[MONITOR] File " << action << ": " << fullPath.string() << std::endl;

                                        // Thread-safe logging
                                        {
                                            std::lock_guard<std::mutex> lock(resultsMutex);
                                            logs.push_back("[MONITOR] File " + action + ": " + fullPath.string());
                                        }

                                        // Launch scan in a separate thread to avoid blocking the watcher
                                        std::thread scanThread([fullPath, rules]() {
                                            try {
                                                // Additional delay to ensure file is complete
                                                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                                                scanFileWithYara(fullPath.string(), rules);
                                            }
                                            catch (const std::exception& e) {
                                                std::cerr << "[ERROR] Exception in scan thread: " << e.what() << std::endl;
                                            }
                                            });
                                        scanThread.detach();
                                    }
                                }
                                catch (const std::exception& e) {
                                    std::cerr << "[ERROR] Exception checking file " << fullPath.string()
                                        << ": " << e.what() << std::endl;
                                }
                            }
                        }
                    }
                    catch (const std::exception& e) {
                        std::cerr << "[ERROR] Exception processing notification: " << e.what() << std::endl;
                    }

                    // Move to next notification
                    if (fni->NextEntryOffset == 0) break;
                    fni = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(
                        reinterpret_cast<BYTE*>(fni) + fni->NextEntryOffset);

                } while (fni && !stopFlag->load());

                // Reset the event and start a new read
                ResetEvent(overlapped.hEvent);
                memset(buffer, 0, sizeof(buffer));

                success = ReadDirectoryChangesW(
                    hDir, buffer, sizeof(buffer), TRUE,
                    FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_CREATION,
                    &bytesReturned, &overlapped, nullptr);

                if (!success && GetLastError() != ERROR_IO_PENDING) {
                    DWORD error = GetLastError();
                    std::cerr << "[MONITOR] ReadDirectoryChangesW failed: " << error << std::endl;
                    break;
                }
            }
            else if (waitStatus == WAIT_TIMEOUT) {
                // Just a timeout, continue waiting
                continue;
            }
            else {
                // Error in wait
                DWORD error = GetLastError();
                std::cerr << "[MONITOR] Wait failed: " << error << std::endl;
                break;
            }
        }

        // Clean up
        CancelIo(hDir);
        CloseHandle(overlapped.hEvent);
        CloseHandle(hDir);
    }
    catch (const std::exception& e) {
        std::cerr << "[MONITOR] Critical exception in watchLoop: " << e.what() << std::endl;
    }
}

void startDirectoryMonitor(const std::filesystem::path& dirToWatch, YR_RULES* rules, std::atomic<bool>& stopFlag) {
    stopFlagPtr = &stopFlag;

    // Make sure the directory exists
    if (!std::filesystem::exists(dirToWatch)) {
        std::filesystem::create_directories(dirToWatch);
    }

    // Log that monitoring is starting
    std::cout << "[MONITOR] Starting file monitoring for directory: " << dirToWatch.string() << std::endl;

    // Start the watcher thread - pass pointer to atomic bool
    watcherThread = std::thread(watchLoop, dirToWatch, rules, &stopFlag);
}

void stopDirectoryMonitor() {
    if (stopFlagPtr) {
        stopFlagPtr->store(true);
    }

    if (watcherThread.joinable()) {
        watcherThread.join();
    }

    std::cout << "[MONITOR] File monitoring stopped" << std::endl;
}
