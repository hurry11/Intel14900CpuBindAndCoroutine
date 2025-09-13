// coroutineCPP1.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <coroutine>
#include <windows.h>
#include <psapi.h>
#include <vector>
#include <intrin.h>
#include <thread>
#include <atomic>
#include <chrono>
#include <tlhelp32.h>
#include <string>
#include <pdh.h>
#include <unordered_map>
#include <pdhmsg.h> // 包含 PDH_MORE_DATA 的定义
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <cctype>

#pragma comment(lib, "Pdh.lib")

// 单个核心的占用比例，注意这里的比例是单核上限而非整体CPU上限
std::unordered_map<int, double> GetPerCoreCpuUsage()
{
    PDH_HQUERY query = nullptr;
    PDH_HCOUNTER counter = nullptr;
    std::unordered_map<int, double> coreUsages;

    // 初始化查询
    if (PdhOpenQuery(nullptr, 0, &query) != ERROR_SUCCESS) {
        std::cerr << "PdhOpenQuery failed: " << GetLastError() << std::endl;
        return coreUsages;
    }

    // 添加计数器
    if (PdhAddCounter(query, L"\\Processor(*)\\% Processor Time", 0, &counter) != ERROR_SUCCESS) {
        std::cerr << "PdhAddCounter failed: " << GetLastError() << std::endl;
        PdhCloseQuery(query);
        return coreUsages;
    }

    // 第一次采集数据（用于基准）
    if (PdhCollectQueryData(query) != ERROR_SUCCESS) {
        std::cerr << "PdhCollectQueryData (1) failed: " << GetLastError() << std::endl;
        PdhCloseQuery(query);
        return coreUsages;
    }

    Sleep(1000); // 间隔1秒

    // 第二次采集数据
    if (PdhCollectQueryData(query) != ERROR_SUCCESS) {
        std::cerr << "PdhCollectQueryData (2) failed: " << GetLastError() << std::endl;
        PdhCloseQuery(query);
        return coreUsages;
    }

    // 获取计数器数据
    DWORD bufferSize = 0;
    DWORD itemCount = 0;
    PDH_STATUS status = PdhGetFormattedCounterArray(
        counter, PDH_FMT_DOUBLE, &bufferSize, &itemCount, nullptr);
    if (status != PDH_MORE_DATA && status != ERROR_SUCCESS) {
        std::cerr << "PdhGetFormattedCounterArray (1) failed: " << status << std::endl;
        PdhCloseQuery(query);
        return coreUsages;
    }

    PDH_FMT_COUNTERVALUE_ITEM* items = reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM*>(new BYTE[bufferSize]);
    status = PdhGetFormattedCounterArray(
        counter, PDH_FMT_DOUBLE, &bufferSize, &itemCount, items);
    if (status != ERROR_SUCCESS) {
        std::cerr << "PdhGetFormattedCounterArray (2) failed: " << status << std::endl;
        delete[] items;
        PdhCloseQuery(query);
        return coreUsages;
    }

    // 解析核心使用率
    for (DWORD i = 0; i < itemCount; i++) {
        std::wstring name(items[i].szName);
        // 过滤 "_Total" 和非数字核心名称（如 "0,0"）
        if (name != L"_Total" && name.find(L',') == std::wstring::npos) {
            try {
                int coreId = std::stoi(name); // 将 "0" 转换为 0
                coreUsages.emplace(coreId, items[i].FmtValue.doubleValue);
            }
            catch (...) {
                // 忽略无效名称
            }
        }
    }

    delete[] items;
    PdhCloseQuery(query);
    return coreUsages;
}

// 获取当前进程的 EXE 路径
std::string GetCurrentExePath()
{
    char path[MAX_PATH];
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    return std::string(path);
}

// 获取相同 EXE 的进程数量（不包括当前进程）
int GetSameExeProcessCount()
{
    std::string currentExePath = GetCurrentExePath();
    int count = 0;

    // 创建进程快照
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return -1; // 快照创建失败
    }

    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    // 遍历进程
    if (Process32First(snapshot, &processEntry)) {
        do {
            // 打开进程句柄
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processEntry.th32ProcessID);
            if (hProcess) {
                char exePath[MAX_PATH];
                if (GetModuleFileNameExA(hProcess, nullptr, exePath, MAX_PATH)) {
                    // 对比 EXE 路径
                    if (std::string(exePath) == currentExePath) {
                        count++;
                    }
                }
                CloseHandle(hProcess);
            }
        } while (Process32Next(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return count - 1; // 排除当前进程
}

// 获取当前线程运行的CPU核心编号
int GetCurrentThreadCore()
{
    return GetCurrentProcessorNumber();
}

// 获取当前进程的CPU使用率（百分比）
double GetProcessCpuUsage()
{
    static ULARGE_INTEGER lastCPU = { 0 }, lastSysCPU = { 0 }, lastUserCPU = { 0 };
    static int numProcessors = 0;

    // 初始化处理器数量
    if (numProcessors == 0) {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        numProcessors = sysInfo.dwNumberOfProcessors;
        if (numProcessors == 0) {
            return -1.0; // 避免除零错误
        }
    }

    FILETIME ftime, fsys, fuser;
    ULARGE_INTEGER now, sys, user;

    // 获取当前系统时间
    GetSystemTimeAsFileTime(&ftime);
    now = { ftime.dwLowDateTime, ftime.dwHighDateTime };

    // 获取进程时间
    if (!GetProcessTimes(GetCurrentProcess(), &ftime, &ftime, &fsys, &fuser)) {
        return -1.0; // 系统调用失败
    }
    sys = { fsys.dwLowDateTime, fsys.dwHighDateTime };
    user = { fuser.dwLowDateTime, fuser.dwHighDateTime };

    // 第一次调用时初始化基准值
    if (lastCPU.QuadPart == 0) {
        lastCPU = now;
        lastSysCPU = sys;
        lastUserCPU = user;
        return 0.0; // 首次调用无历史数据
    }

    // 计算时间差
    ULONGLONG total = (sys.QuadPart - lastSysCPU.QuadPart) +
        (user.QuadPart - lastUserCPU.QuadPart);
    ULONGLONG time = now.QuadPart - lastCPU.QuadPart;

    // 更新基准值
    lastCPU = now;
    lastSysCPU = sys;
    lastUserCPU = user;

    // 避免除零错误
    if (time == 0) {
        return 0.0;
    }

    // 计算CPU使用率
    return (total * 100.0) / (time * numProcessors);
}

// 获取CPU物理核心和逻辑核心数量
void GetCpuCoreInfo(int& physicalCores, int& logicalCores)
{
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    logicalCores = sysInfo.dwNumberOfProcessors;

    DWORD bufferSize = 0;
    GetLogicalProcessorInformation(nullptr, &bufferSize);
    std::vector<SYSTEM_LOGICAL_PROCESSOR_INFORMATION> buffer(bufferSize / sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION));
    GetLogicalProcessorInformation(buffer.data(), &bufferSize);

    physicalCores = 0;
    for (const auto& info : buffer) {
        if (info.Relationship == RelationProcessorCore) {
            physicalCores++;
        }
    }
}

// 检测是否为Intel 14代CPU（改进版）
bool IsIntelI9_13thOr14thGen()
{
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 0);

    // 检查品牌字符串是否为 GenuineIntel
    if (memcmp(&cpuInfo[1], "Genu", 4) != 0 ||
        memcmp(&cpuInfo[3], "ineI", 4) != 0 ||
        memcmp(&cpuInfo[2], "ntel", 4) != 0) {
        return false;
    }

    // 获取 CPU 信息
    __cpuid(cpuInfo, 1);
    int family = (cpuInfo[0] >> 8) & 0xF;
    int model = (cpuInfo[0] >> 4) & 0xF;
    int extModel = (cpuInfo[0] >> 16) & 0xF;
    int combinedModel = (extModel << 4) | model;

    // 13/14 代 i9 型号范围
    // 13代 i9-13900K: family=6, combinedModel=0xB6 (182)
    // 14代 i9-14900K: family=6, combinedModel=0xB7 (183)
    if (family == 6 && (combinedModel == 0xB6 || combinedModel == 0xB7)) {
        return true;
    }
}

std::string GetTypeByApi(int coreId)
{
    DWORD bufferSize = 0;
    // 第一次调用获取缓冲区大小
    if (!GetLogicalProcessorInformationEx(RelationProcessorCore, nullptr, &bufferSize) &&
        GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        return "普通核心";
    }

    // 分配缓冲区
    auto buffer = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(malloc(bufferSize));
    if (!buffer)
        return "普通核心";

    std::string coreType = "普通核心";
    // 第二次调用获取数据
    if (GetLogicalProcessorInformationEx(RelationProcessorCore, buffer, &bufferSize)) {
        DWORD offset = 0;
        while (offset < bufferSize) {
            auto ptr = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(
                reinterpret_cast<BYTE*>(buffer) + offset);

            // 关键修正：P核的EfficiencyClass为非零值（通常为1），E核为0
            bool isPCore = (ptr->Processor.EfficiencyClass != 0); // 逻辑反转

            for (WORD group = 0; group < ptr->Processor.GroupCount; group++) {
                ULONG_PTR mask = ptr->Processor.GroupMask[group].Mask;
                for (int bit = 0; bit < 64; bit++) {
                    if (mask & (1ULL << bit)) {
                        int globalCoreId = bit + group * 64;
                        if (globalCoreId == coreId) {
                            coreType = isPCore ? "P核" : "E核";
                            break;
                        }
                    }
                }
            }
            offset += ptr->Size;
        }
    }
    free(buffer);
    return coreType;
}

std::vector<int> GetPCoresByApi()
{
    std::vector<int> pCores;
    DWORD bufferSize = 0;

    // 第一次调用获取缓冲区大小
    if (!GetLogicalProcessorInformationEx(RelationProcessorCore, nullptr, &bufferSize) &&
        GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        return pCores;
    }

    // 分配缓冲区
    auto buffer = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(
        malloc(bufferSize));
    if (!buffer)
        return pCores;

    // 第二次调用获取数据
    if (GetLogicalProcessorInformationEx(RelationProcessorCore, buffer, &bufferSize)) {
        DWORD offset = 0;
        while (offset < bufferSize) {
            auto ptr = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(
                reinterpret_cast<BYTE*>(buffer) + offset);

            // 修正：P核的EfficiencyClass为非零值（通常为1）
            if (ptr->Processor.EfficiencyClass == 1) { // 注意此处逻辑反转
                for (WORD group = 0; group < ptr->Processor.GroupCount; group++) {
                    ULONG_PTR mask = ptr->Processor.GroupMask[group].Mask;
                    for (int bit = 0; bit < 64; bit++) {
                        if (mask & (1ULL << bit)) {
                            int globalCoreId = bit + group * 64;
                            pCores.push_back(globalCoreId);
                        }
                    }
                }
            }
            offset += ptr->Size;
        }
    }
    free(buffer);
    return pCores;
}

// 绑定线程到指定核心
void BindThreadToCore(int coreId)
{
    DWORD_PTR affinityMask = 1ULL << coreId;
    SetThreadAffinityMask(GetCurrentThread(), affinityMask);
}

void BindThreadToCores(const std::vector<int>& coreIds)
{
    DWORD_PTR affinityMask = 0;
    for (int coreId : coreIds) {
        affinityMask |= (1ULL << coreId);
    }
    SetThreadAffinityMask(GetCurrentThread(), affinityMask);
}

// 协程返回类型
struct Coroutine
{
    struct promise_type
    {
        std::coroutine_handle<promise_type> handle;
        Coroutine get_return_object()
        {
            return Coroutine{ std::coroutine_handle<promise_type>::from_promise(*this) };
        }
        std::suspend_never initial_suspend() { return {}; }
        std::suspend_never final_suspend() noexcept { return {}; }
        void return_void() {}
        void unhandled_exception() {}
    };
    std::coroutine_handle<promise_type> handle;
    explicit Coroutine(std::coroutine_handle<promise_type> h) : handle(h) {}
};

// 计算斐波那契数列（迭代方式，避免递归栈溢出）
unsigned long long Fibonacci(int n)
{
    if (n <= 1)
        return n;
    unsigned long long a = 0, b = 1, c;
    for (int i = 2; i <= n; ++i) {
        c = a + b;
        a = b;
        b = c;
    }
    return b;
}

void BindThreadToFilteredCores(const std::vector<int>& pCores, const std::vector<int>& excludeCores) {
    std::vector<int> targetCores;
    for (int core : pCores) {
        // 检查当前核心是否需要排除
        if (std::find(excludeCores.begin(), excludeCores.end(), core) == excludeCores.end()) {
            targetCores.push_back(core);
            std::cout << "绑定的 P 核序号: " << core << "\n";
        }
    }

    // 绑定到筛选后的核心
    if (!targetCores.empty()) {
        BindThreadToCores(targetCores);
    }
    else {
        std::cout << "警告：没有可绑定的 P 核！\n";
    }
}

// 去除字符串两端的空格
std::string Trim(const std::string& str) {
    size_t start = str.find_first_not_of(" \t");
    if (start == std::string::npos) return "";
    size_t end = str.find_last_not_of(" \t");
    return str.substr(start, end - start + 1);
}

// 解析配置文件到 map
std::map<std::string, std::string> ReadIniToMap(const std::string& filePath) {
    std::map<std::string, std::string> configMap;
    std::ifstream file(filePath);
    if (!file.is_open()) {
        std::cerr << "无法打开配置文件: " << filePath << std::endl;
        return configMap;
    }

    std::string line;
    std::string currentSection;
    while (std::getline(file, line)) {
        line = Trim(line);
        if (line.empty() || line[0] == '#') continue; // 跳过空行和注释

        // 处理 section（如 [IOEXE_LOG]）
        if (line[0] == '[' && line.back() == ']') {
            currentSection = line.substr(1, line.size() - 2);
            continue;
        }

        // 解析键值对
        size_t eqPos = line.find('=');
        if (eqPos != std::string::npos) {
            std::string key = Trim(line.substr(0, eqPos));
            std::string value = Trim(line.substr(eqPos + 1));
            if (!currentSection.empty()) {
                key = currentSection + "." + key; // 组合 section 和 key
            }
            configMap[key] = value;
        }
    }
    file.close();
    return configMap;
}

// 读取 CPU 核心配置
bool ReadCpuCoreConfig(int& cpuCoreMode, std::vector<int>& unusedCores) {
    std::map<std::string, std::string> configMap = ReadIniToMap("CoreEx.ini");
    if (configMap.empty()) {
        std::cerr << "配置文件解析失败或为空" << std::endl;
        return false;
    }

    // 读取 CpuCoreMode
    auto it = configMap.find("CpuCoreMode");
    if (it != configMap.end()) {
        cpuCoreMode = std::stoi(it->second);
    }
    else {
        cpuCoreMode = 1; // 默认值
    }

    // 读取 UnUsedCore
    it = configMap.find("UnUsedCore");
    if (it != configMap.end()) {
        std::string unusedStr = it->second;
        std::istringstream iss(unusedStr);
        std::string token;
        while (std::getline(iss, token, ',')) {
            token = Trim(token);
            if (!token.empty()) {
                unusedCores.push_back(std::stoi(token));
            }
        }
    }

    return true;
}


// 协程函数
Coroutine myCoroutine(std::atomic<bool>& running)
{
    int physicalCores, logicalCores;
    GetCpuCoreInfo(physicalCores, logicalCores);
    bool isIntel14th = IsIntelI9_13thOr14thGen();

    std::cout << "CPU物理核心: " << physicalCores
        << " | 逻辑核心: " << logicalCores
        << " | 型号: " << (isIntel14th ? "Intel 14代" : "其他") << "\n";

    // 绑定到核心
    if (isIntel14th) {
        int cpuCoreMode = 1;
        std::vector<int> unusedCores;
        if (ReadCpuCoreConfig(cpuCoreMode, unusedCores)) {
            std::cout << "CpuCoreMode: " << cpuCoreMode << std::endl;
            std::cout << "UnUsedCore: ";
            for (int core : unusedCores) {
                std::cout << core << " ";
            }
            std::cout << std::endl;
        }
        if (1 == cpuCoreMode) {
            std::cout << "没有限制: " << "\n";
        }
        else if (2 == cpuCoreMode) {
            // 获取同名进程的数量（不包含当前进程）
            int sameProcessCount = GetSameExeProcessCount();
            std::cout << "同名进程个数: " << sameProcessCount << "\n";
            // 获取p核列表
            std::vector<int> pCores = GetPCoresByApi();
            std::cout << "p核个数: " << pCores.size() << "\n";
            if (!pCores.empty()) {
                int totalPCores = pCores.size(); // p核总数
                for (auto core : pCores) {
                    std::cout << "p核的序号:" << core << "\n";
                }
                // 计算应该绑定的p核id
                int targetIndex = totalPCores - sameProcessCount % (totalPCores / 2) * 2 - 1;
                if (targetIndex <= 0) {
                    targetIndex = totalPCores - 1;
                }

                // 获取所有核心的占用率
                std::unordered_map<int, double> mapAllCore = GetPerCoreCpuUsage();
                std::cout << "所有核心信息：" << mapAllCore.size() << "\n";
                for (auto& core : mapAllCore) {
                    std::cout << "核心: " << core.first << " 占用率: " << core.second << "%\n";
                }

                // 检查目标核心占用率，如果超过 50%，则向前遍历寻找空闲核心
                int originalTargetIndex = targetIndex; // 保存原始目标索引
                bool found = false;
                while (targetIndex >= 0) {
                    int targetCore = pCores.at(targetIndex);
                    double usage = mapAllCore.count(targetCore) ? mapAllCore[targetCore] : 0.0;

                    if (usage <= 50.0) {
                        found = true;
                        break;
                    }

                    // 每次减 2，确保跳过相邻核心
                    targetIndex -= 2;
                }

                // 如果未找到合适核心，回退到原始目标核心
                if (!found) {
                    targetIndex = originalTargetIndex;
                }

                // for test
                //targetIndex = 15;
                int targetCore = pCores.at(targetIndex);

                std::cout << "最终目标核心: " << targetCore << " (占用率: "
                    << (mapAllCore.count(targetCore) ? mapAllCore[targetCore] : 0.0) << "%)\n";

                BindThreadToCore(targetCore);
                std::cout << "线程已绑定到 P 核: " << targetCore << "\n";
            }
        }
        else if (3 == cpuCoreMode) {
            // 获取 p 核列表
            std::vector<int> pCores = GetPCoresByApi();
            std::cout << "p核个数: " << pCores.size() << "\n";

            if (!pCores.empty()) {
                // 计算前一半 P 核的范围
                int halfPCores = pCores.size() / 2;
                std::cout << "前一半 P 核数量: " << halfPCores << "\n";

                // 存储前一半 P 核的序号
                std::vector<int> targetCores;
                for (int i = 0; i < halfPCores; i++) {
                    targetCores.push_back(pCores[i]);
                    std::cout << "前一半 P 核的序号: " << pCores[i] << "\n";
                }

                // 绑定到所有前一半 P 核
                BindThreadToCores(targetCores);
            }
        }
        else if (4 == cpuCoreMode) {
            // 获取 p 核列表
            std::vector<int> pCores = GetPCoresByApi();
            std::cout << "p核个数: " << pCores.size() << "\n";

            if (!pCores.empty()) {
                // 计算后一半 P 核的范围
                int startIndex = pCores.size() / 2;
                std::cout << "后一半 P 核数量: " << (pCores.size() - startIndex) << "\n";

                // 存储后一半 P 核的序号
                std::vector<int> targetCores;
                for (int i = startIndex; i < pCores.size(); i++) {
                    targetCores.push_back(pCores[i]);
                    std::cout << "后一半 P 核的序号: " << pCores[i] << "\n";
                }
                // 绑定到所有后一半 P 核
                BindThreadToCores(targetCores);
            }
        }
        else if (5 == cpuCoreMode) {
            // 获取 p 核列表
            std::vector<int> pCores = GetPCoresByApi();
            std::cout << "p核个数: " << pCores.size() << "\n";
            BindThreadToFilteredCores(pCores, unusedCores);
        }
    }
    else {
        // 普通CPU：绑定到偏后的逻辑核心（后半部分）
        if (logicalCores > 1) {
            int targetCore = logicalCores / 2; // 从中间开始选择
            BindThreadToCore(targetCore);
            std::cout << "线程已绑定到普通核心: " << targetCore << "\n";
        }
    }

    while (running) {
        // CPU密集型计算（使用迭代方式计算斐波那契数列）
        auto start = std::chrono::high_resolution_clock::now();
        unsigned long long sum = 0;
        for (int i = 0; i < 5000000; ++i) {
            sum += Fibonacci(1000); // 计算斐波那契(1000)并累加结果
        }
        auto end = std::chrono::high_resolution_clock::now();

        // 输出CPU信息（确保sum被使用，防止优化）
        int core = GetCurrentThreadCore();
        double usage = GetProcessCpuUsage();
        std::string coreType = GetTypeByApi(core);

        std::cout << "核心ID: " << core
            << " | 类型: " << coreType
            << " | CPU使用率: " << usage << "%"
            << " | 计算耗时: "
            << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count()
            << "ms | 计算结果: " << (sum % 1000) << "\n"; // 防止优化

        co_await std::suspend_always{};
        Sleep(500); // 每0.5秒输出一次
    }
}

int main()
{
    std::cout << "Hello World!\n";
    std::atomic<bool> running(true);
    auto coro = myCoroutine(running); // 启动协程

    // 持续恢复协程
    while (running) {
        coro.handle.resume();
        std::this_thread::sleep_for(std::chrono::milliseconds(10)); // 更频繁地恢复协程
    }

    // 等待用户输入以退出程序
    std::cout << "按 Enter 键退出程序...\n";
    std::cin.get();
    running = false;
}