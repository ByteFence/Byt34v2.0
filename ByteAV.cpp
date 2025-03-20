#include <iostream>
#include <thread>
#include <vector>
#include <filesystem>
#include <mutex>
#include <unordered_set>
#include <openssl/evp.h> // For SHA-256
#include <windows.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>

using namespace std;
namespace fs = std::filesystem;

std::mutex printMutex;

// Function to load malware hashes from CSV file (UNCHANGED)
unordered_set<string> loadSha256Hashes(const string& filename) {
    unordered_set<string> hashes;
    ifstream file(filename);
    if (!file.is_open()) {
        cerr << "Error: Could not open " << filename << endl;
        return hashes;
    }
    string line;
    while (getline(file, line)) {
        if (!line.empty()) {
            hashes.insert(line);
        }
    }
    file.close();
    cout << "Loaded " << hashes.size() << " SHA-256 hashes from database." << endl;
    return hashes;
}

// Function to compute SHA-256 hash of a file (UNCHANGED)
string computeHash(const string& filePath) {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) return "ERROR_CREATING_CTX";
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        return "ERROR_INITIALIZING_DIGEST";
    }
    ifstream file(filePath, ios::binary);
    if (!file) {
        EVP_MD_CTX_free(mdctx);
        return "ERROR_OPENING_FILE";
    }
    char buffer[4096];
    while (file.read(buffer, sizeof(buffer))) {
        if (EVP_DigestUpdate(mdctx, buffer, file.gcount()) != 1) {
            EVP_MD_CTX_free(mdctx);
            return "ERROR_UPDATING_DIGEST";
        }
    }
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    if (EVP_DigestFinal_ex(mdctx, hash, &length) != 1) {
        EVP_MD_CTX_free(mdctx);
        return "ERROR_FINALIZING_DIGEST";
    }
    EVP_MD_CTX_free(mdctx);
    stringstream ss;
    for (unsigned int i = 0; i < length; i++) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// ✅ Updated function: Scans recursively into subdirectories
void scanDirectory(const fs::path& dirPath, const unordered_set<string>& malwareHashes,
    vector<pair<string, string>>& normalFiles, vector<pair<string, string>>& maliciousFiles) {
    try {
        for (const auto& entry : fs::recursive_directory_iterator(dirPath)) { // 🔹 Now scanning subdirectories too
            {
                std::lock_guard<std::mutex> lock(printMutex);
                std::cout << "Scanning: " << entry.path() << std::endl;
            }
            if (fs::is_regular_file(entry.status())) {
                string fileHash = computeHash(entry.path().string());

                lock_guard<mutex> lock(printMutex);
                if (malwareHashes.find(fileHash) != malwareHashes.end()) {
                    maliciousFiles.push_back({ entry.path().string(), fileHash });
                }
                else {
                    normalFiles.push_back({ entry.path().string(), fileHash });
                }
            }
        }
    }
    catch (const fs::filesystem_error& e) {
        std::lock_guard<std::mutex> lock(printMutex);
        std::cerr << "Error accessing " << dirPath << ": " << e.what() << std::endl;
    }
}

// Function to print scan results (UNCHANGED)
void printScanResults(const vector<pair<string, string>>& normalFiles, const vector<pair<string, string>>& maliciousFiles) {
    if (!normalFiles.empty()) {
        cout << "\nScanned Normal Files:" << endl;
        cout << "-------------------------------------------------" << endl;
        cout << left << setw(40) << "Filename" << " | " << "File Hash" << endl;
        cout << "-------------------------------------------------" << endl;
        for (const auto& file : normalFiles) {
            cout << left << setw(40) << file.first << " | " << file.second << endl;
        }
        cout << "-------------------------------------------------" << endl;
    }

    if (!maliciousFiles.empty()) {
        cout << "\nMalicious Files Detected:" << endl;
        cout << "-------------------------------------------------" << endl;
        cout << left << setw(40) << "Filename" << " | " << "File Hash" << endl;
        cout << "-------------------------------------------------" << endl;
        for (const auto& file : maliciousFiles) {
            cout << left << setw(40) << file.first << " | " << file.second << endl;
        }
        cout << "-------------------------------------------------" << endl;
    }
    else {
        cout << "\nNo malicious files detected!" << endl;
    }
}

// Function to monitor a directory in real-time (UNCHANGED)
void monitorDirectory(const string& dirPath, const unordered_set<string>& malwareHashes) {
    HANDLE hDir = CreateFile(
        dirPath.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL);

    if (hDir == INVALID_HANDLE_VALUE) {
        cerr << "Error: Unable to monitor directory!" << endl;
        return;
    }

    char buffer[1024];
    DWORD bytesReturned;
    FILE_NOTIFY_INFORMATION* fileInfo;
    string fileName;

    cout << "\nReal-time monitoring active on: " << dirPath << endl;

    while (true) {
        if (ReadDirectoryChangesW(hDir, buffer, sizeof(buffer), TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
            &bytesReturned, NULL, NULL)) {

            fileInfo = (FILE_NOTIFY_INFORMATION*)buffer;
            int fileNameLength = fileInfo->FileNameLength / 2;
            fileName = string(fileNameLength, '\0');

            for (int i = 0; i < fileNameLength; i++) {
                fileName[i] = fileInfo->FileName[i];
            }

            string fullPath = dirPath + "\\" + fileName;

            if (fs::is_regular_file(fullPath)) {
                string fileHash = computeHash(fullPath);

                lock_guard<mutex> lock(printMutex);
                cout << "\n[Real-Time Scan] New file detected: " << fullPath << " | Hash: " << fileHash << endl;

                if (malwareHashes.find(fileHash) != malwareHashes.end()) {
                    cout << "⚠️ WARNING: Malicious file detected - " << fullPath << endl;
                }
                else {
                    cout << "[Real-Time Scan] File is clean: " << fullPath << endl;
                }
            }
        }
    }

    CloseHandle(hDir);
}

int main() {
    cout << "==========================================" << endl;
    cout << "Welcome to ByteAV - Simple Antivirus Scanner" << endl;
    cout << "==========================================" << endl << endl;

    string malwareDB = "sha256_only.csv";
    unordered_set<string> malwareHashes = loadSha256Hashes(malwareDB);

    if (malwareHashes.empty()) {
        cerr << "Malware database is empty. Scanning without detection enabled." << endl;
    }

    string inputPath;
    cout << "\nEnter the directory path to scan: ";
    getline(cin, inputPath);

    fs::path rootDir(inputPath);
    vector<pair<string, string>> normalFiles;
    vector<pair<string, string>> maliciousFiles;

    // ✅ Now scans subdirectories too
    scanDirectory(rootDir, malwareHashes, normalFiles, maliciousFiles);

    // Print the scan results
    printScanResults(normalFiles, maliciousFiles);

    // Start real-time monitoring after scanning
    thread monitorThread(monitorDirectory, inputPath, ref(malwareHashes));

    cout << "\nInitial Scan Completed! Real-time monitoring will continue...\n";

    monitorThread.join(); // Keep monitoring active

    return 0;
}
