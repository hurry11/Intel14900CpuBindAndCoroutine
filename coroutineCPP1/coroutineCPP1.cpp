// coroutineCPP1.cpp : ���ļ����� "main" ����������ִ�н��ڴ˴���ʼ��������
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
#include <pdhmsg.h> // ���� PDH_MORE_DATA �Ķ���
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <cctype>

#pragma comment(lib, "Pdh.lib")

// �������ĵ�ռ�ñ�����ע������ı����ǵ������޶�������CPU����
std::unordered_map<int, double> GetPerCoreCpuUsage()
{
    PDH_HQUERY query = nullptr;
    PDH_HCOUNTER counter = nullptr;
    std::unordered_map<int, double> coreUsages;

    // ��ʼ����ѯ
    if (PdhOpenQuery(nullptr, 0, &query) != ERROR_SUCCESS) {
        std::cerr << "PdhOpenQuery failed: " << GetLastError() << std::endl;
        return coreUsages;
    }

    // ��Ӽ�����
    if (PdhAddCounter(query, L"\\Processor(*)\\% Processor Time", 0, &counter) != ERROR_SUCCESS) {
        std::cerr << "PdhAddCounter failed: " << GetLastError() << std::endl;
        PdhCloseQuery(query);
        return coreUsages;
    }

    // ��һ�βɼ����ݣ����ڻ�׼��
    if (PdhCollectQueryData(query) != ERROR_SUCCESS) {
        std::cerr << "PdhCollectQueryData (1) failed: " << GetLastError() << std::endl;
        PdhCloseQuery(query);
        return coreUsages;
    }

    Sleep(1000); // ���1��

    // �ڶ��βɼ�����
    if (PdhCollectQueryData(query) != ERROR_SUCCESS) {
        std::cerr << "PdhCollectQueryData (2) failed: " << GetLastError() << std::endl;
        PdhCloseQuery(query);
        return coreUsages;
    }

    // ��ȡ����������
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

    // ��������ʹ����
    for (DWORD i = 0; i < itemCount; i++) {
        std::wstring name(items[i].szName);
        // ���� "_Total" �ͷ����ֺ������ƣ��� "0,0"��
        if (name != L"_Total" && name.find(L',') == std::wstring::npos) {
            try {
                int coreId = std::stoi(name); // �� "0" ת��Ϊ 0
                coreUsages.emplace(coreId, items[i].FmtValue.doubleValue);
            }
            catch (...) {
                // ������Ч����
            }
        }
    }

    delete[] items;
    PdhCloseQuery(query);
    return coreUsages;
}

// ��ȡ��ǰ���̵� EXE ·��
std::string GetCurrentExePath()
{
    char path[MAX_PATH];
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    return std::string(path);
}

// ��ȡ��ͬ EXE �Ľ�����������������ǰ���̣�
int GetSameExeProcessCount()
{
    std::string currentExePath = GetCurrentExePath();
    int count = 0;

    // �������̿���
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return -1; // ���մ���ʧ��
    }

    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    // ��������
    if (Process32First(snapshot, &processEntry)) {
        do {
            // �򿪽��̾��
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processEntry.th32ProcessID);
            if (hProcess) {
                char exePath[MAX_PATH];
                if (GetModuleFileNameExA(hProcess, nullptr, exePath, MAX_PATH)) {
                    // �Ա� EXE ·��
                    if (std::string(exePath) == currentExePath) {
                        count++;
                    }
                }
                CloseHandle(hProcess);
            }
        } while (Process32Next(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return count - 1; // �ų���ǰ����
}

// ��ȡ��ǰ�߳����е�CPU���ı��
int GetCurrentThreadCore()
{
    return GetCurrentProcessorNumber();
}

// ��ȡ��ǰ���̵�CPUʹ���ʣ��ٷֱȣ�
double GetProcessCpuUsage()
{
    static ULARGE_INTEGER lastCPU = { 0 }, lastSysCPU = { 0 }, lastUserCPU = { 0 };
    static int numProcessors = 0;

    // ��ʼ������������
    if (numProcessors == 0) {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        numProcessors = sysInfo.dwNumberOfProcessors;
        if (numProcessors == 0) {
            return -1.0; // ����������
        }
    }

    FILETIME ftime, fsys, fuser;
    ULARGE_INTEGER now, sys, user;

    // ��ȡ��ǰϵͳʱ��
    GetSystemTimeAsFileTime(&ftime);
    now = { ftime.dwLowDateTime, ftime.dwHighDateTime };

    // ��ȡ����ʱ��
    if (!GetProcessTimes(GetCurrentProcess(), &ftime, &ftime, &fsys, &fuser)) {
        return -1.0; // ϵͳ����ʧ��
    }
    sys = { fsys.dwLowDateTime, fsys.dwHighDateTime };
    user = { fuser.dwLowDateTime, fuser.dwHighDateTime };

    // ��һ�ε���ʱ��ʼ����׼ֵ
    if (lastCPU.QuadPart == 0) {
        lastCPU = now;
        lastSysCPU = sys;
        lastUserCPU = user;
        return 0.0; // �״ε�������ʷ����
    }

    // ����ʱ���
    ULONGLONG total = (sys.QuadPart - lastSysCPU.QuadPart) +
        (user.QuadPart - lastUserCPU.QuadPart);
    ULONGLONG time = now.QuadPart - lastCPU.QuadPart;

    // ���»�׼ֵ
    lastCPU = now;
    lastSysCPU = sys;
    lastUserCPU = user;

    // ����������
    if (time == 0) {
        return 0.0;
    }

    // ����CPUʹ����
    return (total * 100.0) / (time * numProcessors);
}

// ��ȡCPU������ĺ��߼���������
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

// ����Ƿ�ΪIntel 14��CPU���Ľ��棩
bool IsIntelI9_13thOr14thGen()
{
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 0);

    // ���Ʒ���ַ����Ƿ�Ϊ GenuineIntel
    if (memcmp(&cpuInfo[1], "Genu", 4) != 0 ||
        memcmp(&cpuInfo[3], "ineI", 4) != 0 ||
        memcmp(&cpuInfo[2], "ntel", 4) != 0) {
        return false;
    }

    // ��ȡ CPU ��Ϣ
    __cpuid(cpuInfo, 1);
    int family = (cpuInfo[0] >> 8) & 0xF;
    int model = (cpuInfo[0] >> 4) & 0xF;
    int extModel = (cpuInfo[0] >> 16) & 0xF;
    int combinedModel = (extModel << 4) | model;

    // 13/14 �� i9 �ͺŷ�Χ
    // 13�� i9-13900K: family=6, combinedModel=0xB6 (182)
    // 14�� i9-14900K: family=6, combinedModel=0xB7 (183)
    if (family == 6 && (combinedModel == 0xB6 || combinedModel == 0xB7)) {
        return true;
    }
}

std::string GetTypeByApi(int coreId)
{
    DWORD bufferSize = 0;
    // ��һ�ε��û�ȡ��������С
    if (!GetLogicalProcessorInformationEx(RelationProcessorCore, nullptr, &bufferSize) &&
        GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        return "��ͨ����";
    }

    // ���仺����
    auto buffer = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(malloc(bufferSize));
    if (!buffer)
        return "��ͨ����";

    std::string coreType = "��ͨ����";
    // �ڶ��ε��û�ȡ����
    if (GetLogicalProcessorInformationEx(RelationProcessorCore, buffer, &bufferSize)) {
        DWORD offset = 0;
        while (offset < bufferSize) {
            auto ptr = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(
                reinterpret_cast<BYTE*>(buffer) + offset);

            // �ؼ�������P�˵�EfficiencyClassΪ����ֵ��ͨ��Ϊ1����E��Ϊ0
            bool isPCore = (ptr->Processor.EfficiencyClass != 0); // �߼���ת

            for (WORD group = 0; group < ptr->Processor.GroupCount; group++) {
                ULONG_PTR mask = ptr->Processor.GroupMask[group].Mask;
                for (int bit = 0; bit < 64; bit++) {
                    if (mask & (1ULL << bit)) {
                        int globalCoreId = bit + group * 64;
                        if (globalCoreId == coreId) {
                            coreType = isPCore ? "P��" : "E��";
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

    // ��һ�ε��û�ȡ��������С
    if (!GetLogicalProcessorInformationEx(RelationProcessorCore, nullptr, &bufferSize) &&
        GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        return pCores;
    }

    // ���仺����
    auto buffer = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(
        malloc(bufferSize));
    if (!buffer)
        return pCores;

    // �ڶ��ε��û�ȡ����
    if (GetLogicalProcessorInformationEx(RelationProcessorCore, buffer, &bufferSize)) {
        DWORD offset = 0;
        while (offset < bufferSize) {
            auto ptr = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(
                reinterpret_cast<BYTE*>(buffer) + offset);

            // ������P�˵�EfficiencyClassΪ����ֵ��ͨ��Ϊ1��
            if (ptr->Processor.EfficiencyClass == 1) { // ע��˴��߼���ת
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

// ���̵߳�ָ������
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

// Э�̷�������
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

// ����쳲��������У�������ʽ������ݹ�ջ�����
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
        // ��鵱ǰ�����Ƿ���Ҫ�ų�
        if (std::find(excludeCores.begin(), excludeCores.end(), core) == excludeCores.end()) {
            targetCores.push_back(core);
            std::cout << "�󶨵� P �����: " << core << "\n";
        }
    }

    // �󶨵�ɸѡ��ĺ���
    if (!targetCores.empty()) {
        BindThreadToCores(targetCores);
    }
    else {
        std::cout << "���棺û�пɰ󶨵� P �ˣ�\n";
    }
}

// ȥ���ַ������˵Ŀո�
std::string Trim(const std::string& str) {
    size_t start = str.find_first_not_of(" \t");
    if (start == std::string::npos) return "";
    size_t end = str.find_last_not_of(" \t");
    return str.substr(start, end - start + 1);
}

// ���������ļ��� map
std::map<std::string, std::string> ReadIniToMap(const std::string& filePath) {
    std::map<std::string, std::string> configMap;
    std::ifstream file(filePath);
    if (!file.is_open()) {
        std::cerr << "�޷��������ļ�: " << filePath << std::endl;
        return configMap;
    }

    std::string line;
    std::string currentSection;
    while (std::getline(file, line)) {
        line = Trim(line);
        if (line.empty() || line[0] == '#') continue; // �������к�ע��

        // ���� section���� [IOEXE_LOG]��
        if (line[0] == '[' && line.back() == ']') {
            currentSection = line.substr(1, line.size() - 2);
            continue;
        }

        // ������ֵ��
        size_t eqPos = line.find('=');
        if (eqPos != std::string::npos) {
            std::string key = Trim(line.substr(0, eqPos));
            std::string value = Trim(line.substr(eqPos + 1));
            if (!currentSection.empty()) {
                key = currentSection + "." + key; // ��� section �� key
            }
            configMap[key] = value;
        }
    }
    file.close();
    return configMap;
}

// ��ȡ CPU ��������
bool ReadCpuCoreConfig(int& cpuCoreMode, std::vector<int>& unusedCores) {
    std::map<std::string, std::string> configMap = ReadIniToMap("CoreEx.ini");
    if (configMap.empty()) {
        std::cerr << "�����ļ�����ʧ�ܻ�Ϊ��" << std::endl;
        return false;
    }

    // ��ȡ CpuCoreMode
    auto it = configMap.find("CpuCoreMode");
    if (it != configMap.end()) {
        cpuCoreMode = std::stoi(it->second);
    }
    else {
        cpuCoreMode = 1; // Ĭ��ֵ
    }

    // ��ȡ UnUsedCore
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


// Э�̺���
Coroutine myCoroutine(std::atomic<bool>& running)
{
    int physicalCores, logicalCores;
    GetCpuCoreInfo(physicalCores, logicalCores);
    bool isIntel14th = IsIntelI9_13thOr14thGen();

    std::cout << "CPU�������: " << physicalCores
        << " | �߼�����: " << logicalCores
        << " | �ͺ�: " << (isIntel14th ? "Intel 14��" : "����") << "\n";

    // �󶨵�����
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
            std::cout << "û������: " << "\n";
        }
        else if (2 == cpuCoreMode) {
            // ��ȡͬ�����̵���������������ǰ���̣�
            int sameProcessCount = GetSameExeProcessCount();
            std::cout << "ͬ�����̸���: " << sameProcessCount << "\n";
            // ��ȡp���б�
            std::vector<int> pCores = GetPCoresByApi();
            std::cout << "p�˸���: " << pCores.size() << "\n";
            if (!pCores.empty()) {
                int totalPCores = pCores.size(); // p������
                for (auto core : pCores) {
                    std::cout << "p�˵����:" << core << "\n";
                }
                // ����Ӧ�ð󶨵�p��id
                int targetIndex = totalPCores - sameProcessCount % (totalPCores / 2) * 2 - 1;
                if (targetIndex <= 0) {
                    targetIndex = totalPCores - 1;
                }

                // ��ȡ���к��ĵ�ռ����
                std::unordered_map<int, double> mapAllCore = GetPerCoreCpuUsage();
                std::cout << "���к�����Ϣ��" << mapAllCore.size() << "\n";
                for (auto& core : mapAllCore) {
                    std::cout << "����: " << core.first << " ռ����: " << core.second << "%\n";
                }

                // ���Ŀ�����ռ���ʣ�������� 50%������ǰ����Ѱ�ҿ��к���
                int originalTargetIndex = targetIndex; // ����ԭʼĿ������
                bool found = false;
                while (targetIndex >= 0) {
                    int targetCore = pCores.at(targetIndex);
                    double usage = mapAllCore.count(targetCore) ? mapAllCore[targetCore] : 0.0;

                    if (usage <= 50.0) {
                        found = true;
                        break;
                    }

                    // ÿ�μ� 2��ȷ���������ں���
                    targetIndex -= 2;
                }

                // ���δ�ҵ����ʺ��ģ����˵�ԭʼĿ�����
                if (!found) {
                    targetIndex = originalTargetIndex;
                }

                // for test
                //targetIndex = 15;
                int targetCore = pCores.at(targetIndex);

                std::cout << "����Ŀ�����: " << targetCore << " (ռ����: "
                    << (mapAllCore.count(targetCore) ? mapAllCore[targetCore] : 0.0) << "%)\n";

                BindThreadToCore(targetCore);
                std::cout << "�߳��Ѱ󶨵� P ��: " << targetCore << "\n";
            }
        }
        else if (3 == cpuCoreMode) {
            // ��ȡ p ���б�
            std::vector<int> pCores = GetPCoresByApi();
            std::cout << "p�˸���: " << pCores.size() << "\n";

            if (!pCores.empty()) {
                // ����ǰһ�� P �˵ķ�Χ
                int halfPCores = pCores.size() / 2;
                std::cout << "ǰһ�� P ������: " << halfPCores << "\n";

                // �洢ǰһ�� P �˵����
                std::vector<int> targetCores;
                for (int i = 0; i < halfPCores; i++) {
                    targetCores.push_back(pCores[i]);
                    std::cout << "ǰһ�� P �˵����: " << pCores[i] << "\n";
                }

                // �󶨵�����ǰһ�� P ��
                BindThreadToCores(targetCores);
            }
        }
        else if (4 == cpuCoreMode) {
            // ��ȡ p ���б�
            std::vector<int> pCores = GetPCoresByApi();
            std::cout << "p�˸���: " << pCores.size() << "\n";

            if (!pCores.empty()) {
                // �����һ�� P �˵ķ�Χ
                int startIndex = pCores.size() / 2;
                std::cout << "��һ�� P ������: " << (pCores.size() - startIndex) << "\n";

                // �洢��һ�� P �˵����
                std::vector<int> targetCores;
                for (int i = startIndex; i < pCores.size(); i++) {
                    targetCores.push_back(pCores[i]);
                    std::cout << "��һ�� P �˵����: " << pCores[i] << "\n";
                }
                // �󶨵����к�һ�� P ��
                BindThreadToCores(targetCores);
            }
        }
        else if (5 == cpuCoreMode) {
            // ��ȡ p ���б�
            std::vector<int> pCores = GetPCoresByApi();
            std::cout << "p�˸���: " << pCores.size() << "\n";
            BindThreadToFilteredCores(pCores, unusedCores);
        }
    }
    else {
        // ��ͨCPU���󶨵�ƫ����߼����ģ���벿�֣�
        if (logicalCores > 1) {
            int targetCore = logicalCores / 2; // ���м俪ʼѡ��
            BindThreadToCore(targetCore);
            std::cout << "�߳��Ѱ󶨵���ͨ����: " << targetCore << "\n";
        }
    }

    while (running) {
        // CPU�ܼ��ͼ��㣨ʹ�õ�����ʽ����쳲��������У�
        auto start = std::chrono::high_resolution_clock::now();
        unsigned long long sum = 0;
        for (int i = 0; i < 5000000; ++i) {
            sum += Fibonacci(1000); // ����쳲�����(1000)���ۼӽ��
        }
        auto end = std::chrono::high_resolution_clock::now();

        // ���CPU��Ϣ��ȷ��sum��ʹ�ã���ֹ�Ż���
        int core = GetCurrentThreadCore();
        double usage = GetProcessCpuUsage();
        std::string coreType = GetTypeByApi(core);

        std::cout << "����ID: " << core
            << " | ����: " << coreType
            << " | CPUʹ����: " << usage << "%"
            << " | �����ʱ: "
            << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count()
            << "ms | ������: " << (sum % 1000) << "\n"; // ��ֹ�Ż�

        co_await std::suspend_always{};
        Sleep(500); // ÿ0.5�����һ��
    }
}

int main()
{
    std::cout << "Hello World!\n";
    std::atomic<bool> running(true);
    auto coro = myCoroutine(running); // ����Э��

    // �����ָ�Э��
    while (running) {
        coro.handle.resume();
        std::this_thread::sleep_for(std::chrono::milliseconds(10)); // ��Ƶ���ػָ�Э��
    }

    // �ȴ��û��������˳�����
    std::cout << "�� Enter ���˳�����...\n";
    std::cin.get();
    running = false;
}