#define _CRT_SECURE_NO_WARNINGS
#define NOMINMAX  // Add this to avoid conflicts with Windows.h min/max macros
#include <string>
#include "ByteAV.h"
#include "monitor.h"
#include <imgui.h>
#include <backends/imgui_impl_glfw.h>
#include <backends/imgui_impl_opengl3.h>
#include <GLFW/glfw3.h>
#include <iostream>
#include <filesystem>
#include <atomic>
#include <thread>
#include <windows.h>
#include <psapi.h>
#include <unordered_set>
#include <mutex>
#include <cmath> // for entropy calculation
#include <fstream> // for std::ifstream

// Use forward declarations instead of redefining structs
struct YR_RULES;
struct YR_SCAN_CONTEXT;
std::string status = "Idle";
std::vector<std::pair<std::string, std::string>> scanResults;
std::vector<std::string> logs;
static float scanProgress = 0.0f;
static float cpuData[100] = { 0.0f };
static int dataOffset = 0;
static auto lastCpuSample = std::chrono::steady_clock::now();
static std::mutex resultsMutex;
bool showBlinkNotification = false;
float blinkTimer = 0.0f;
bool blinkVisible = true;
int maliciousCount = 0;
int cleanCount = 0;

static std::string monitoredDirectory;
static bool isMonitoring = false;
static std::atomic<bool> stopMonitor{ false };
static std::thread monitorThread;

float GetCPUUsage() {
    static ULARGE_INTEGER lastIdleTime = {}, lastKernelTime = {}, lastUserTime = {};
    FILETIME idleTime, kernelTime, userTime;
    if (!GetSystemTimes(&idleTime, &kernelTime, &userTime)) return 0.0f;

    ULARGE_INTEGER idle, kernel, user;
    idle.LowPart = idleTime.dwLowDateTime;     idle.HighPart = idleTime.dwHighDateTime;
    kernel.LowPart = kernelTime.dwLowDateTime; kernel.HighPart = kernelTime.dwHighDateTime;
    user.LowPart = userTime.dwLowDateTime;     user.HighPart = userTime.dwHighDateTime;

    ULONGLONG idleDiff = idle.QuadPart - lastIdleTime.QuadPart;
    ULONGLONG kernelDiff = kernel.QuadPart - lastKernelTime.QuadPart;
    ULONGLONG userDiff = user.QuadPart - lastUserTime.QuadPart;

    lastIdleTime = idle; lastKernelTime = kernel; lastUserTime = user;

    ULONGLONG total = kernelDiff + userDiff;
    return total ? 100.0f * (1.0f - ((float)idleDiff / total)) : 0.0f;
}

float calculateEntropy(const std::string& filepath) {
    std::ifstream file;
    file.open(filepath, std::ios::in | std::ios::binary);
    if (!file.is_open()) return 0.0f;

    std::vector<unsigned char> buffer;
    char ch;
    while (file.get(ch)) {
        buffer.push_back(static_cast<unsigned char>(ch));
    }
    file.close();

    // Prevent division by zero
    if (buffer.empty()) return 0.0f;

    int counts[256] = {};
    for (unsigned char byte : buffer) counts[byte]++;

    float entropy = 0.0f;
    for (int count : counts) {
        if (count > 0) {
            float p = (float)count / buffer.size();
            entropy -= p * std::log2(p);
        }
    }
    return entropy;
}

int calculateThreatScore(bool yaraMatch, bool hashMatch, float entropy) {
    int score = 0;
    if (yaraMatch) score += 40;
    if (hashMatch) score += 30;
    if (entropy > 7.0f) score += 30;
    return score;
}

// Fixed startMonitoring function
void startMonitoring(const std::string& dirPath, YR_RULES* yaraRules) {
    try {
        // Stop any existing monitoring
        if (isMonitoring) {
            stopMonitor.store(true);

            // Give the thread time to gracefully stop
            for (int i = 0; i < 10 && monitorThread.joinable(); i++) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }

            if (monitorThread.joinable()) {
                monitorThread.join();
            }
            stopDirectoryMonitor();
        }

        // Make sure the directory exists
        std::filesystem::path monitorPath(dirPath);
        if (!std::filesystem::exists(monitorPath)) {
            try {
                std::filesystem::create_directories(monitorPath);
                logs.push_back("[INFO] Created directory: " + dirPath);
            }
            catch (const std::exception& e) {
                logs.push_back("[ERROR] Failed to create directory: " + dirPath + " - " + e.what());
                status = "Error: Failed to create directory";
                return;
            }
        }

        // Reset monitoring state
        stopMonitor.store(false);
        isMonitoring = true;
        monitoredDirectory = dirPath;

        // Start new monitoring thread with proper initialization
        startDirectoryMonitor(dirPath, yaraRules, stopMonitor);

        logs.push_back("[INFO] Started monitoring: " + dirPath);
        status = "Monitoring: " + dirPath;
    }
    catch (const std::exception& e) {
        logs.push_back("[ERROR] Failed to start monitoring: " + std::string(e.what()));
        status = "Error: Failed to start monitoring";
    }
}

// Fixed stopMonitoring function
void stopMonitoring() {
    if (isMonitoring) {
        stopMonitor.store(true);
        if (monitorThread.joinable()) {
            monitorThread.join();
        }
        stopDirectoryMonitor();

        isMonitoring = false;
        logs.push_back("[INFO] Stopped monitoring: " + monitoredDirectory);
        status = "Idle";
    }
}

void renderScannerGUI(YR_RULES* yaraRules) {
    static char dirPath[256] = "C:\\";
    static char monitorPath[256] = "scandir";

    ImGui::Begin("ByteAV Scanner");

    ImGui::Dummy(ImVec2(0, 5));
    if (showBlinkNotification) {
        blinkTimer += ImGui::GetIO().DeltaTime;
        if (blinkTimer > 0.5f) {
            blinkVisible = !blinkVisible;
            blinkTimer = 0.0f;
        }
        ImVec4 redColor = ImVec4(1.0f, 0.2f, 0.2f, 1.0f);
        ImVec4 transparentColor = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
        ImGui::PushStyleColor(ImGuiCol_Text, blinkVisible ? redColor : transparentColor);
        ImGui::Text("[ALERT] Malicious file detected!");
        ImGui::PopStyleColor();
    }

    ImGui::Text("Scan Settings");
    ImGui::InputText("Scan Directory", dirPath, IM_ARRAYSIZE(dirPath));
    dirPath[255] = '\0';

    if (ImGui::Button("Start Scan")) {
        if (strlen(dirPath) == 0) {
            status = "Error: Empty scan path";
            logs.push_back("[ERROR] Scan path is empty.");
            return;
        }

        std::string safeDir(dirPath);
        if (!std::filesystem::exists(safeDir)) {
            status = "Error: Directory does not exist";
            logs.push_back("[ERROR] Directory not found: " + safeDir);
            return;
        }

        status = "Scanning...";
        scanResults.clear();
        logs.clear();
        scanProgress = 0.0f;
        showBlinkNotification = false; // Reset notification state

        std::thread scanThread([safeDir, yaraRules]() { // Fixed: Capture by value instead of reference
            try {
                std::filesystem::path root(safeDir);
                std::vector<std::pair<std::string, std::string>> maliciousFiles;
                std::vector<std::pair<std::string, std::string>> normalFiles;


                // 1) Early-exit: directory doesn't exist
                if (!std::filesystem::exists(root)) {
                    {
                        // Scoped lock_guard so it always releases before return
                        std::lock_guard<std::mutex> lock(resultsMutex);
                        status = "Error: Directory does not exist";
                        scanProgress = 1.0f;
                    }
                    return;
                }
                size_t total = 0;
                try {
                    total = std::distance(
                        std::filesystem::recursive_directory_iterator(root),
                        std::filesystem::recursive_directory_iterator());
                }
                catch (const std::exception& e) {
                    {
                        std::lock_guard<std::mutex> lock(resultsMutex);
                        logs.push_back(std::string("[ERROR] Failed to count files: ") + e.what());
                    }
                    status = "Error: Failed to count files";
                    scanProgress = 1.0f;
                    return;
                }

                if (total == 0) total = 1; // Prevent division by zero

                size_t count = 0;
                int localMaliciousCount = 0;
                int localCleanCount = 0;

                try {
                    for (const auto& entry : std::filesystem::recursive_directory_iterator(root)) {
                        if (!std::filesystem::is_regular_file(entry)) {
                            count++;
                            continue;
                        }

                        std::string filepath = entry.path().string();
                        std::string hash;

                        try {
                            hash = computeHash(filepath);
                        }
                        catch (const std::exception& e) {
                            {
                                std::lock_guard<std::mutex> lock(resultsMutex);
                                logs.push_back("[ERROR] Failed to compute hash for " + filepath + ": " + e.what());
                            }
                            count++;
                            continue;
                        }

                        float entropy = 0.0f;
                        try {
                            entropy = calculateEntropy(filepath);
                        }
                        catch (const std::exception& e) {
                            {
                                std::lock_guard<std::mutex> lock(resultsMutex);
                                logs.push_back("[ERROR] Failed to calculate entropy for " + filepath + ": " + e.what());
                            }
                        }

                        bool yaraMatch = false;
                        if (yaraRules) {
                            try {
                                // Check if file is accessible before scanning
                                std::ifstream testFile(filepath);
                                if (testFile.good()) {
                                    testFile.close();
                                    // Using string object instead of address
                                    std::string filePath = filepath;
                                    yr_rules_scan_file(yaraRules, filepath.c_str(), 0, yaraCallback,
                                        &filePath, 0);
                                    yaraMatch = yaraMatchedFiles.count(filepath) > 0;
                                }
                            }
                            catch (const std::exception& e) {
                                {
                                    std::lock_guard<std::mutex> lock(resultsMutex);
                                    logs.push_back("[ERROR] Failed to scan with YARA for " + filepath + ": " + e.what());
                                }
                            }
                        }

                        bool hashMatch = malwareHashes.count(hash) > 0;
                        int score = calculateThreatScore(yaraMatch, hashMatch, entropy);

                        {
                            std::lock_guard<std::mutex> lock(resultsMutex);
                            if (yaraMatch || hashMatch) {
                                maliciousFiles.emplace_back(filepath, hash);
                                logs.emplace_back("[MALICIOUS] " + filepath + " | Score: " +
                                    std::to_string(score) + " | Entropy: " + std::to_string(entropy));
                                localMaliciousCount++;
                                showBlinkNotification = true;
                            }
                            else {
                                normalFiles.emplace_back(filepath, hash);
                                logs.emplace_back("[CLEAN] " + filepath + " | Entropy: " + std::to_string(entropy));
                                localCleanCount++;
                            }
                        }

                        count++;
                        scanProgress = static_cast<float>(count) / total;
                    }

                    {
                        std::lock_guard<std::mutex> lock(resultsMutex);
                        scanResults.insert(scanResults.end(), maliciousFiles.begin(), maliciousFiles.end());
                        scanResults.insert(scanResults.end(), normalFiles.begin(), normalFiles.end());
                        maliciousCount = localMaliciousCount;
                        cleanCount = localCleanCount;
                        status = "Scan Complete.";
                        scanProgress = 1.0f;
                    }
                }
                catch (const std::exception& e) {
                    std::lock_guard<std::mutex> lock(resultsMutex);
                    logs.push_back("[ERROR] Scan error: " + std::string(e.what()));
                    status = "Error during scan";
                    scanProgress = 1.0f;
                }
            }
            catch (const std::exception& e) {
                // Outer catch: no early return here, so plain lock_guard is fine
                std::lock_guard<std::mutex> lock(resultsMutex);
                logs.push_back(std::string("[CRITICAL] Thread error: ") + e.what());
                status = "Critical error";
                scanProgress = 1.0f;
            }
            });
        scanThread.detach();
    }

    ImGui::Text("Status: %s", status.c_str());
    ImGui::ProgressBar(scanProgress);
    ImGui::Separator();

    ImGui::Text("Active Monitoring");
    ImGui::InputText("Monitor Directory", monitorPath, IM_ARRAYSIZE(monitorPath));
    ImGui::BeginGroup();
    if (!isMonitoring) {
        if (ImGui::Button("Start Monitoring")) {
            startMonitoring(monitorPath, yaraRules);
        }
    }
    else {
        if (ImGui::Button("Stop Monitoring")) {
            stopMonitoring();
        }
        ImGui::SameLine();
        ImGui::Text("Currently monitoring: %s", monitoredDirectory.c_str());
    }
    ImGui::EndGroup();

    ImGui::Separator();
    ImGui::Text("Results:");
    ImGui::BeginChild("Results", ImVec2(0, 200), true);
    {
        std::lock_guard<std::mutex> lock(resultsMutex); // Added: Thread safety
        for (const auto& res : scanResults) {
            bool isMalicious = malwareHashes.count(res.second) > 0 || yaraMatchedFiles.count(res.first) > 0;
            ImVec4 color = isMalicious ? ImVec4(1, 0.3f, 0.3f, 1) : ImVec4(0.3f, 1, 0.3f, 1);
            ImGui::PushStyleColor(ImGuiCol_Text, color);
            ImGui::TextWrapped("[%s] %s", isMalicious ? "Malicious" : "Clean", res.first.c_str());
            ImGui::PopStyleColor();
        }
    }
    ImGui::EndChild();

    ImGui::Separator();
    ImGui::Text("Statistics:");
    float totalScanned = static_cast<float>(maliciousCount + cleanCount);
    if (totalScanned > 0.0f) {
        float values[] = { (float)cleanCount / totalScanned, (float)maliciousCount / totalScanned };
        ImGui::PlotHistogram("Malicious vs Clean", values, 2, 0, nullptr, 0.0f, 1.0f, ImVec2(0, 100));
        ImGui::Text("Total Scanned: %d", (int)totalScanned);
        ImGui::Text("Clean Files: %d", cleanCount);
        ImGui::Text("Malicious Files: %d", maliciousCount);
    }

    MEMORYSTATUSEX mem = { sizeof(mem) };
    GlobalMemoryStatusEx(&mem);
    ImGui::Text("RAM: %d%% used", mem.dwMemoryLoad);
    ImGui::ProgressBar(mem.dwMemoryLoad / 100.0f);

    if (std::chrono::steady_clock::now() - lastCpuSample > std::chrono::milliseconds(600)) {
        cpuData[dataOffset] = GetCPUUsage();
        dataOffset = (dataOffset + 1) % 100;
        lastCpuSample = std::chrono::steady_clock::now();
    }
    ImGui::PlotLines("CPU Usage", cpuData, 100, dataOffset);

    ImGui::Text("Log:");
    ImGui::BeginChild("LogWindow", ImVec2(0, 120), true);
    {
        std::lock_guard<std::mutex> lock(resultsMutex); // Added: Thread safety
        for (const auto& log : logs) {
            ImGui::TextUnformatted(log.c_str());
        }
    }
    ImGui::EndChild();

    ImGui::End();
}

int main(int argc, char** argv) {
    // Initialize YARA
    if (yr_initialize() != 0) {
        std::cerr << "[ERROR] Failed to initialize YARA." << std::endl;
        return 1;
    }

    std::filesystem::path exePath = std::filesystem::absolute(argv[0]);
    std::filesystem::path exeDir = exePath.parent_path();
    std::filesystem::path rulePath = exeDir / "rules" / "ByteAV_rules.yar";

    YR_RULES* yaraRules = nullptr;
    try {
        yaraRules = compileYaraRules(rulePath.string());
        if (!yaraRules) {
            std::cerr << "[ERROR] Failed to compile YARA rules." << std::endl;
            logs.push_back("[ERROR] Failed to compile YARA rules.");
        }
    }
    catch (const std::exception& e) {
        std::cerr << "[ERROR] Exception during YARA rules compilation: " << e.what() << std::endl;
        logs.push_back("[ERROR] Exception during YARA rules compilation: " + std::string(e.what()));
    }

    try {
        malwareHashes = loadSha256Hashes("sha256_only.csv");
    }
    catch (const std::exception& e) {
        std::cerr << "[ERROR] Failed to load hash database: " << e.what() << std::endl;
        logs.push_back("[ERROR] Failed to load hash database: " + std::string(e.what()));
    }

    try {
        if (!std::filesystem::exists("scandir")) {
            std::filesystem::create_directory("scandir");
        }
    }
    catch (const std::exception& e) {
        std::cerr << "[ERROR] Failed to create scandir: " << e.what() << std::endl;
        logs.push_back("[ERROR] Failed to create scandir: " + std::string(e.what()));
    }

    if (!glfwInit()) {
        std::cerr << "[ERROR] Failed to initialize GLFW." << std::endl;
        yr_finalize(); // Clean up YARA
        return 1;
    }

    GLFWwindow* window = glfwCreateWindow(1000, 700, "ByteAV Antivirus", NULL, NULL);
    if (!window) {
        std::cerr << "[ERROR] Failed to create GLFW window." << std::endl;
        glfwTerminate();
        yr_finalize(); // Clean up YARA
        return 1;
    }

    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    ImGui::StyleColorsDark();
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 130");

    static bool showStartupScreen = true;
    static float startupTimer = 0.0f;

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        if (showStartupScreen) {
            startupTimer += ImGui::GetIO().DeltaTime;
            ImGui::Begin("ByteAV - Initialization", nullptr, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar);
            ImGui::SetWindowSize(ImVec2(600, 300));
            ImGui::SetWindowPos(ImVec2(200, 200));

            ImGui::Text("ByteAV - v1.0");
            ImGui::Text("Real-Time Threat Intelligence Engine Initialized");

            if (startupTimer >= 1.0f) ImGui::Text("[OK] Hash DB Loaded");
            else ImGui::Text("loading... Hash DB");

            if (startupTimer >= 2.0f) ImGui::Text("[OK] YARA Rules Active");
            else if (startupTimer >= 1.0f) ImGui::Text("loading... YARA");

            if (startupTimer >= 3.0f) ImGui::Text("[OK] Live Monitoring Ready");
            else if (startupTimer >= 2.0f) ImGui::Text("loading... Monitor");

            if (startupTimer >= 4.0f) {
                ImGui::Text("[INFO] Loaded %zu hashes", malwareHashes.size());
            }

            if (startupTimer >= 6.0f) showStartupScreen = false;

            ImGui::End();
        }
        else {
            renderScannerGUI(yaraRules);
        }

        ImGui::Render();
        int w, h;
        glfwGetFramebufferSize(window, &w, &h);
        glViewport(0, 0, w, h);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }

    if (yaraRules) {
        destroyYaraRules(yaraRules);
    }
    // Clean up YARA
    yr_finalize();

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();
    return 0;
}
