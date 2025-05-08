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

static std::string status = "Idle";
std::vector<std::pair<std::string, std::string>> scanResults;
std::vector<std::string> logs;
static float scanProgress = 0.0f;
static float cpuData[100] = { 0.0f };
static int dataOffset = 0;
static auto lastCpuSample = std::chrono::steady_clock::now();

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

int main(int argc, char** argv) {
    std::filesystem::path exePath = std::filesystem::absolute(argv[0]);
    std::filesystem::path exeDir = exePath.parent_path();
    std::filesystem::path rulePath = exeDir / "rules" / "ByteAV_rules.yar";

    YR_RULES* yaraRules = compileYaraRules(rulePath.string());
    if (!yaraRules) {
        std::cerr << "[ERROR] Failed to compile YARA rules." << std::endl;
        return 1;
    }

    std::unordered_set<std::string> malwareHashes = loadSha256Hashes("sha256_only.csv");
    std::filesystem::create_directory("scandir");
    std::atomic<bool> stopMonitor{ false };
    std::thread monitorThread([&]() {
        startDirectoryMonitor("scandir", yaraRules, stopMonitor);
        });

    if (!glfwInit()) {
        std::cerr << "[ERROR] Failed to initialize GLFW" << std::endl;
        stopMonitor.store(true);
        monitorThread.join();
        destroyYaraRules(yaraRules);
        return 1;
    }

    GLFWwindow* window = glfwCreateWindow(1000, 700, "ByteAV Antivirus", NULL, NULL);
    if (!window) {
        std::cerr << "[ERROR] Failed to create window" << std::endl;
        glfwTerminate();
        stopMonitor.store(true);
        monitorThread.join();
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
    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        ImGui::Begin("ByteAV Scanner");
        ImGui::InputText("Scan Directory", dirPath, IM_ARRAYSIZE(dirPath));
        if (ImGui::Button("Start Scan")) {
            status = "Scanning...";
            scanResults.clear();
            logs.clear();
            scanProgress = 0.0f;

            std::thread scanThread([&]() {
                std::vector<std::pair<std::string, std::string>> normalFiles, maliciousFiles;
                std::filesystem::path root(dirPath);
                size_t total = std::distance(std::filesystem::recursive_directory_iterator(root), {});
                size_t count = 0;

                for (const auto& entry : std::filesystem::recursive_directory_iterator(root)) {
                    std::string filepath = entry.path().string();
                    std::string hash = computeHash(filepath);

                    if (yaraRules) {
                        yr_rules_scan_file(yaraRules, filepath.c_str(), 0, yaraCallback, &filepath, 0);
                    }

                    if (malwareHashes.count(hash) || yaraMatchedFiles.count(filepath)) {
                        maliciousFiles.emplace_back(filepath, hash);
                        logs.emplace_back("[MALICIOUS] " + filepath);
                    }
                    else {
                        normalFiles.emplace_back(filepath, hash);
                        logs.emplace_back("[CLEAN] " + filepath);
                    }
                    count++;
                    scanProgress = static_cast<float>(count) / total;
                }

                scanResults.insert(scanResults.end(), maliciousFiles.begin(), maliciousFiles.end());
                scanResults.insert(scanResults.end(), normalFiles.begin(), normalFiles.end());
                status = "Scan Complete.";
                scanProgress = 1.0f;
                });
            scanThread.detach();
        }

        ImGui::Text("Status: %s", status.c_str());
        ImGui::ProgressBar(scanProgress);
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

    stopMonitor.store(true);
    monitorThread.join();
    stopDirectoryMonitor();
    destroyYaraRules(yaraRules);
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();
    return 0;
}
