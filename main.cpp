// byteav_gui.cpp (Updated: scan progress bar, log window, slower CPU graph)
#include "imgui.h"
#include "backends/imgui_impl_glfw.h"
#include "backends/imgui_impl_opengl3.h"
#include <GLFW/glfw3.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <windows.h>
#include <psapi.h>
#include "ByteAV.h"

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

int main() {
    if (!glfwInit()) return -1;
    GLFWwindow* window = glfwCreateWindow(1000, 700, "ByteAV Antivirus", NULL, NULL);
    if (!window) return -1;
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    ImGui::StyleColorsDark();
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 5.0f;
    style.FrameRounding = 4.0f;
    style.GrabRounding = 4.0f;
    style.ScrollbarRounding = 4.0f;

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 130");

    static char dirPath[256] = "C:\\";
    static std::vector<std::pair<std::string, std::string>> scanResults;
    static std::string status = "Idle";
    std::vector<std::string> logs;
    float scanProgress = 0.0f;
    std::unordered_set<std::string> malwareHashes = loadSha256Hashes("sha256_only.csv");
    YR_RULES* yaraRules = compileYaraRules("rules/ByteAV_rules.yar");

    static float cpuData[100] = { 0.0f };
    static int dataOffset = 0;
    static auto lastCpuSample = std::chrono::steady_clock::now();

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        ImGui::Begin("ByteAV Antivirus Scanner", nullptr, ImGuiWindowFlags_MenuBar);

        if (ImGui::BeginMenuBar()) {
            ImGui::Text("ByteAV - Real-Time Antivirus");
            ImGui::EndMenuBar();
        }

        ImGui::InputText("Scan Directory", dirPath, IM_ARRAYSIZE(dirPath));
        if (ImGui::Button("Start Scan", ImVec2(120, 0))) {
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
        ImGui::ProgressBar(scanProgress, ImVec2(-1.0f, 0.0f));
        ImGui::Separator();
        ImGui::Text("Scan Results:");
        ImGui::BeginChild("Results", ImVec2(0, 200), true);
        for (const auto& result : scanResults) {
            bool isMalicious = malwareHashes.count(result.second) || yaraMatchedFiles.count(result.first);
            ImVec4 color = isMalicious ? ImVec4(1.0f, 0.3f, 0.3f, 1.0f) : ImVec4(0.3f, 1.0f, 0.3f, 1.0f);
            ImGui::PushStyleColor(ImGuiCol_Text, color);
            ImGui::TextWrapped("[%s] %s", isMalicious ? "Malicious" : "Clean", result.first.c_str());
            ImGui::PopStyleColor();
            if (isMalicious) {
                ImGui::SameLine();
                std::string delBtn = "Delete##" + result.first;
                std::string qBtn = "Quarantine##" + result.first;
                if (ImGui::Button(delBtn.c_str())) deleteFile(result.first);
                ImGui::SameLine();
                if (ImGui::Button(qBtn.c_str())) quarantineFile(result.first);
            }
        }
        ImGui::EndChild();

        ImGui::Separator();
        ImGui::Text("System Performance");
        MEMORYSTATUSEX mem = { sizeof(mem) };
        GlobalMemoryStatusEx(&mem);
        float memUsed = mem.dwMemoryLoad / 100.0f;
        ImGui::Text("RAM: %.1f%% used", mem.dwMemoryLoad * 1.0f);
        ImGui::ProgressBar(memUsed, ImVec2(-1.0f, 0.0f));

        if (std::chrono::steady_clock::now() - lastCpuSample > std::chrono::milliseconds(600)) {
            float cpu = GetCPUUsage();
            cpuData[dataOffset] = cpu;
            dataOffset = (dataOffset + 1) % IM_ARRAYSIZE(cpuData);
            lastCpuSample = std::chrono::steady_clock::now();
        }
        ImGui::PlotLines("CPU Usage (%)", cpuData, IM_ARRAYSIZE(cpuData), dataOffset, nullptr, 0.0f, 100.0f, ImVec2(0, 80));

        ImGui::Separator();
        ImGui::Text("Activity Log:");
        ImGui::BeginChild("LogWindow", ImVec2(0, 120), true);
        for (const auto& log : logs) {
            ImGui::TextUnformatted(log.c_str());
        }
        ImGui::EndChild();

        ImGui::End();

        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.1f, 0.1f, 0.1f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();
    return 0;
}
