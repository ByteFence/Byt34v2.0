#define _CRT_SECURE_NO_WARNINGS
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

static std::string status = "Idle";
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

std::unordered_set<std::string> malwareHashes;

static std::string monitoredDirectory;
static bool isMonitoring = false;
static std::atomic<bool> stopMonitor{ false };
static std::thread monitorThread;

extern void scanFileWithYara(const std::string& filePath, YR_RULES* rules);

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
// Fixed startMonitoring function from main.cpp
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

// Fixed stopMonitoring function from main.cpp
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

int main(int argc, char** argv) {
    std::filesystem::path exePath = std::filesystem::absolute(argv[0]);
    std::filesystem::path exeDir = exePath.parent_path();
    std::filesystem::path rulePath = exeDir / "rules" / "ByteAV_rules.yar";

    YR_RULES* yaraRules = compileYaraRules(rulePath.string());
    if (!yaraRules) {
        std::cerr << "[ERROR] Failed to compile YARA rules." << std::endl;
        return 1;
    }

    malwareHashes = loadSha256Hashes("sha256_only.csv");
    std::filesystem::create_directory("scandir");

    std::string defaultMonitorDir = "scandir";
    logs.push_back("[INFO] Default monitoring directory: " + defaultMonitorDir);

    if (!glfwInit()) {
        std::cerr << "[ERROR] Failed to initialize GLFW" << std::endl;
        destroyYaraRules(yaraRules);
        return 1;
    }

    GLFWwindow* window = glfwCreateWindow(1000, 700, "ByteAV Antivirus", NULL, NULL);
    if (!window) {
        std::cerr << "[ERROR] Failed to create window" << std::endl;
        glfwTerminate();
        destroyYaraRules(yaraRules);
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

    static char dirPath[256] = "C:\\";
    static char monitorPath[256] = "scandir";

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();
        ImGui::Begin("ByteAV Scanner");
        ImGui::Dummy(ImVec2(0, 5)); // small vertical gap
        if (showBlinkNotification) {
            blinkTimer += ImGui::GetIO().DeltaTime;
            if (blinkTimer > 0.5f) {
                blinkVisible = !blinkVisible;
                blinkTimer = 0.0f;
            }

            ImVec4 redColor = ImVec4(1.0f, 0.2f, 0.2f, 1.0f);
            ImVec4 transparentColor = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);

            // Reserve fixed height to prevent layout shifting
            ImGui::PushStyleColor(ImGuiCol_Text, blinkVisible ? redColor : transparentColor);
            ImGui::Text("[ALERT] Malicious file detected!");
            ImGui::PopStyleColor();
        }
        ImGui::Text("Scan Settings");
        ImGui::InputText("Scan Directory", dirPath, IM_ARRAYSIZE(dirPath));
        if (ImGui::Button("Start Scan")) {
            status = "Scanning...";
            scanResults.clear();
            logs.clear();
            scanProgress = 0.0f;

            std::thread scanThread([&]() {
                std::vector<std::pair<std::string, std::string>> normalFiles, maliciousFiles;
                std::filesystem::path root(dirPath);
                if (!std::filesystem::exists(root)) {
                    status = "Error: Directory does not exist";
                    scanProgress = 1.0f;
                    return;
                }

                maliciousCount = 0;
                cleanCount = 0;
                size_t total = std::distance(std::filesystem::recursive_directory_iterator(root), {});
                size_t count = 0;

                for (const auto& entry : std::filesystem::recursive_directory_iterator(root)) {
                    if (!std::filesystem::is_regular_file(entry)) {
                        count++;
                        continue;
                    }

                    std::string filepath = entry.path().string();
                    std::string hash = computeHash(filepath);

                    if (yaraRules) {
                        yr_rules_scan_file(yaraRules, filepath.c_str(), 0, yaraCallback, &filepath, 0);
                    }

                    std::lock_guard<std::mutex> lock(resultsMutex);
                    if (malwareHashes.count(hash) || yaraMatchedFiles.count(filepath)) {
                        maliciousFiles.emplace_back(filepath, hash);
                        logs.emplace_back("[MALICIOUS] " + filepath);
                        maliciousCount++;
                        showBlinkNotification = true;
                    }
                    else {
                        normalFiles.emplace_back(filepath, hash);
                        logs.emplace_back("[CLEAN] " + filepath);
                        cleanCount++;
                    }

                    count++;
                    scanProgress = static_cast<float>(count) / total;
                }

                {
                    std::lock_guard<std::mutex> lock(resultsMutex);
                    scanResults.insert(scanResults.end(), maliciousFiles.begin(), maliciousFiles.end());
                    scanResults.insert(scanResults.end(), normalFiles.begin(), normalFiles.end());
                }
                status = "Scan Complete.";
                scanProgress = 1.0f;

                strcpy(monitorPath, dirPath);
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
        for (const auto& res : scanResults) {
            bool isMalicious = malwareHashes.count(res.second) || yaraMatchedFiles.count(res.first);
            ImVec4 color = isMalicious ? ImVec4(1, 0.3f, 0.3f, 1) : ImVec4(0.3f, 1, 0.3f, 1);
            ImGui::PushStyleColor(ImGuiCol_Text, color);
            ImGui::TextWrapped("[%s] %s", isMalicious ? "Malicious" : "Clean", res.first.c_str());
            ImGui::PopStyleColor();
        }
        ImGui::EndChild();

        ImGui::Separator();
        ImGui::Text("Statistics:");
        float totalScanned = maliciousCount + cleanCount;
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
        for (const auto& log : logs) {
            ImGui::TextUnformatted(log.c_str());
        }
        ImGui::EndChild();

        ImGui::End();
        ImGui::Render();
        int w, h;
        glfwGetFramebufferSize(window, &w, &h);
        glViewport(0, 0, w, h);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }

    stopMonitoring();
    destroyYaraRules(yaraRules);
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();
    return 0;
}