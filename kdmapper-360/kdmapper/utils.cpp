#include "utils.hpp"
#include <sstream>
#include <fstream>

std::wstring utils::GetFullTempPath() {
    wchar_t temp_directory[MAX_PATH + 1] = { 0 };
    const uint32_t get_temp_path_ret = GetTempPathW(sizeof(temp_directory) / 2, temp_directory);
    if (!get_temp_path_ret || get_temp_path_ret > MAX_PATH + 1) {
        Log("[ERROR] Failed to get temp path\n");
        return L"";
    }
    if (temp_directory[wcslen(temp_directory) - 1] == L'\\')
        temp_directory[wcslen(temp_directory) - 1] = 0x0;

    return std::wstring(temp_directory);
}

bool utils::ReadFileToMemory(const std::wstring& file_path, std::vector<uint8_t>* out_buffer) {
    std::ifstream file_ifstream(file_path, std::ios::binary);
    if (!file_ifstream) {
        Log("[ERROR] Failed to open file for reading\n");
        return false;
    }

    out_buffer->assign((std::istreambuf_iterator<char>(file_ifstream)), std::istreambuf_iterator<char>());
    file_ifstream.close();
    return true;
}

bool utils::CreateFileFromMemory(const std::wstring& desired_file_path, const char* address, size_t size) {
    // 先尝试删除现有文件（如果存在）
    DeleteFileW(desired_file_path.c_str());
    
    // 使用Windows API创建文件，更好地处理宽字符路径和权限
    HANDLE file_handle = CreateFileW(
        desired_file_path.c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (file_handle == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        printf("[ERROR] Failed to create file - Windows error: %lu\n", error);
        return false;
    }

    DWORD bytes_written = 0;
    BOOL write_result = WriteFile(
        file_handle,
        address,
        static_cast<DWORD>(size),
        &bytes_written,
        nullptr
    );

    if (!write_result || bytes_written != size) {
        DWORD error = GetLastError();
        printf("[ERROR] Failed to write to file - Windows error: %lu, bytes written: %lu/%zu\n",
            error, bytes_written, size);
        CloseHandle(file_handle);
        return false;
    }

    CloseHandle(file_handle);
    printf("[DEBUG] File created successfully: %zu bytes written\n", size);
    return true;
}

uint64_t utils::GetKernelModuleAddress(const std::string& module_name) {
    void* buffer = nullptr;
    DWORD buffer_size = 0;

    // 输出请求的模块名
    {
        std::ostringstream oss;
        oss << "[DEBUG] Looking for kernel module base address, module name: " << module_name << "\n";
        Log(oss.str().c_str());
    }

    NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemModuleInformation), buffer, buffer_size, &buffer_size);

    // 输出初始 status 和 buffer_size
    {
        std::ostringstream oss;
        oss << "[DEBUG] NtQuerySystemInformation initial return status: 0x" << std::hex << status << ", buffer_size: " << std::dec << buffer_size << "\n";
        Log(oss.str().c_str());
    }

    while (status == nt::STATUS_INFO_LENGTH_MISMATCH) {
        if (buffer) {
            VirtualFree(buffer, 0, MEM_RELEASE);
        }

        buffer = VirtualAlloc(nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemModuleInformation), buffer, buffer_size, &buffer_size);

        // 输出每次循环的 status 和 buffer_size
        {
            std::ostringstream oss;
            oss << "[DEBUG] NtQuerySystemInformation loop return status: 0x" << std::hex << status << ", buffer_size: " << std::dec << buffer_size << "\n";
            Log(oss.str().c_str());
        }
    }

    if (!NT_SUCCESS(status)) {
        std::ostringstream oss;
        oss << "[ERROR] NtQuerySystemInformation failed, status: 0x" << std::hex << status << "\n";
        Log(oss.str().c_str());
        if (buffer != nullptr)
            VirtualFree(buffer, 0, MEM_RELEASE);
        return 0;
    }

    const auto modules = static_cast<nt::PRTL_PROCESS_MODULES>(buffer);
    if (!modules) {
        Log("[ERROR] Failed to get module list, modules is NULL\n");
        if (buffer != nullptr)
            VirtualFree(buffer, 0, MEM_RELEASE);
        return 0;
    }

    for (auto i = 0u; i < modules->NumberOfModules; ++i) {
        const std::string current_module_name = std::string(reinterpret_cast<char*>(modules->Modules[i].FullPathName) + modules->Modules[i].OffsetToFileName);

        // 输出每个模块名
        {
            std::ostringstream oss;
            oss << "[DEBUG] Enumerated module: " << current_module_name << "\n";
            Log(oss.str().c_str());
        }

        if (!_stricmp(current_module_name.c_str(), module_name.c_str())) {
            const uint64_t result = reinterpret_cast<uint64_t>(modules->Modules[i].ImageBase);

            {
                std::ostringstream oss;
                oss << "[DEBUG] Found module " << current_module_name << ", base address: 0x" << std::hex << result << "\n";
                Log(oss.str().c_str());
            }

            VirtualFree(buffer, 0, MEM_RELEASE);
            return result;
        }
    }

    {
        std::ostringstream oss;
        oss << "[ERROR] Module not found: " << module_name << "\n";
        Log(oss.str().c_str());
    }
    
    VirtualFree(buffer, 0, MEM_RELEASE);
    return 0;
}