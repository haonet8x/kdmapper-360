#pragma once
#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <string>
#include <filesystem>
#include <atlstr.h>

// 定义 PHYSICAL_ADDRESS 如果未定义
#ifndef PHYSICAL_ADDRESS
typedef LARGE_INTEGER PHYSICAL_ADDRESS, *PPHYSICAL_ADDRESS;
#endif

#include "eneio64_driver_resource.hpp"
#include "service.hpp"
#include "utils.hpp"
#include <assert.h>

// 内存页大小定义
constexpr uint32_t PAGE_SIZE = 0x1000;  // 4KB page size

// 适配 eneio64.sys 驱动的接口
namespace eneio64_driver
{
	extern char driver_name[100]; //"eneio64.sys"
	constexpr uint32_t ioctl_map = 0x80102040; // IOCTL_WINIO_MAPPHYSTOLIN
	constexpr uint32_t ioctl_unmap = 0x80102044; // IOCTL_WINIO_UNMAPPHYSADDR
	constexpr DWORD eneio64_timestamp = 0x5284EAC3;
	extern ULONG64 ntoskrnlAddr;

	// 设备名和IOCTL常量定义 - 支持多种可能的设备名称
	constexpr wchar_t ENEIO64_DEVICE_NAME[] = L"\\\\.\\EneIo";        // 主要设备名
	constexpr wchar_t ENEIO64_DEVICE_NAME_ALT1[] = L"\\\\.\\ENEIO64";  // 备选设备名1
	constexpr wchar_t ENEIO64_DEVICE_NAME_ALT2[] = L"\\\\.\\GLCKIo";   // 备选设备名2
	constexpr wchar_t ENEIO64_DEVICE_NAME_ALT3[] = L"\\\\.\\eneio64";  // 备选设备名3
	constexpr uint32_t IOCTL_WINIO_MAPPHYSTOLIN = 0x80102040;
	constexpr uint32_t IOCTL_WINIO_UNMAPPHYSADDR = 0x80102044;
	
	// EneIo64 专用 IOCTL 定义
	#define ENEIO64_DEVICE_TYPE          (DWORD)0x8010
	#define ENEIO64_MAP_SECTION_FUNCID   (DWORD)0x810
	#define ENEIO64_UNMAP_SECTION_FUNCID (DWORD)0x811
	#define IOCTL_ENEIO64_MAP_USER_PHYSICAL_MEMORY      \
		CTL_CODE(ENEIO64_DEVICE_TYPE, ENEIO64_MAP_SECTION_FUNCID, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x80102040
	#define IOCTL_ENEIO64_UNMAP_USER_PHYSICAL_MEMORY    \
		CTL_CODE(ENEIO64_DEVICE_TYPE, ENEIO64_UNMAP_SECTION_FUNCID, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x80102044

	// EneIo64.sys 的物理内存信息结构（根据驱动分析）
	#pragma pack(push)
	#pragma pack(1)
	typedef struct _ENEIO64_PHYSICAL_MEMORY_INFO {
		LARGE_INTEGER Size;              // 映射大小
		PHYSICAL_ADDRESS PhysicalAddress; // 物理地址
		PVOID hSection;                  // 节句柄
		PVOID pMappedAddress;           // 映射的地址
		PVOID pObject;                  // 对象指针
	} ENEIO64_PHYSICAL_MEMORY_INFO, *PENEIO64_PHYSICAL_MEMORY_INFO;
	#pragma pack(pop)

	// 兼容旧版本的 INPUTBUF 结构（保留用于向后兼容）
	typedef struct _INPUTBUF
	{
		ULONG64 Size;
		ULONG64 val2;
		ULONG64 val3;
		ULONG64 MappingAddress;
		ULONG64 val5;
	} INPUTBUF, *PINPUTBUF;

	// 页表遍历相关常量和结构定义
	#define ENTRY_PRESENT_BIT       0x1
	#define ENTRY_PAGE_SIZE_BIT     0x80
	#define PHY_ADDRESS_MASK        0x000ffffffffff000ULL
	#define PHY_ADDRESS_MASK_1GB_PAGES  0x000fffffc0000000ULL
	#define PHY_ADDRESS_MASK_2MB_PAGES  0x000fffffffe00000ULL
	#define VADDR_ADDRESS_MASK_1GB_PAGES 0x3fffffffULL
	#define VADDR_ADDRESS_MASK_2MB_PAGES 0x1fffffULL
	#define VADDR_ADDRESS_MASK_4KB_PAGES 0xfffULL
	#define PAGE_SIZE               0x1000

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

	// KDU标准GDT和IDT结构定义
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
	} KGDTENTRY64, * PKGDTENTRY64;

	typedef union _KIDTENTRY64 {
		struct {
			USHORT OffsetLow;
			USHORT Selector;
			USHORT IstIndex : 3;
			USHORT Reserved0 : 5;
			USHORT Type : 5;
			USHORT Dpl : 2;
			USHORT Present : 1;
			USHORT OffsetMiddle;
			ULONG OffsetHigh;
			ULONG Reserved1;
		};
		ULONG64 Alignment;
	} KIDTENTRY64, * PKIDTENTRY64;

	typedef union _KGDT_BASE {
		struct {
			USHORT BaseLow;
			UCHAR BaseMiddle;
			UCHAR BaseHigh;
			ULONG BaseUpper;
		};
		ULONG64 Base;
	} KGDT_BASE, * PKGDT_BASE;

	typedef union _KGDT_LIMIT {
		struct {
			USHORT LimitLow;
			USHORT LimitHigh : 4;
			USHORT MustBeZero : 12;
		};
		ULONG Limit;
	} KGDT_LIMIT, * PKGDT_LIMIT;

	#define PSB_GDT32_MAX       3

	typedef struct _KDESCRIPTOR32 {
		USHORT Pad[3];
		USHORT Limit;
		ULONG Base;
	} KDESCRIPTOR32, * PKDESCRIPTOR32;

	// 描述符结构定义
	typedef struct _KDESCRIPTOR {
		USHORT Pad[3];
		USHORT Limit;
		PVOID Base;
	} KDESCRIPTOR, *PKDESCRIPTOR;

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
	} KSPECIAL_REGISTERS, * PKSPECIAL_REGISTERS;

	typedef struct _KPROCESSOR_STATE {
		KSPECIAL_REGISTERS SpecialRegisters;
		CONTEXT ContextFrame;
	} KPROCESSOR_STATE, * PKPROCESSOR_STATE;

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

	#ifndef FIELD_OFFSET
	#define FIELD_OFFSET(type, field)    ((LONG)(LONG_PTR)&(((type *)0)->field))
	#define UFIELD_OFFSET(type, field)    ((ULONG)(LONG_PTR)&(((type *)0)->field))
	#endif

	#ifndef RtlOffsetToPointer
	#define RtlOffsetToPointer(Base, Offset)  ((PCHAR)( ((PCHAR)(Base)) + ((ULONG_PTR)(Offset))  ))
	#endif

	// 虚拟地址转换函数类型定义
	typedef BOOL(WINAPI* ProvQueryPML4)(_In_ HANDLE DeviceHandle, _Out_ ULONG_PTR* Value);
	typedef BOOL(WINAPI* ProvReadPhysicalMemory)(_In_ HANDLE DeviceHandle, _In_ ULONG_PTR PhysicalAddress, _In_reads_bytes_(NumberOfBytes) PVOID Buffer, _In_ ULONG NumberOfBytes);

	// 基础函数声明
	std::wstring GetDriverNameW();
	std::wstring GetDriverPath();
	bool IsRunning();
	HANDLE Load(const std::wstring& custom_device = L"");
	void Unload(HANDLE device_handle);
	bool UnloadDriver();
	
	// 全局变量声明
	extern ULONG64 ntoskrnlAddr;
	extern char driver_name[100];
	extern bool translation_permanently_disabled;  // 地址转换永久禁用标志

	// 物理内存读写函数
	bool ReadPhysicalMemory(HANDLE device_handle, UINT64 address, void* buffer, DWORD size);
	bool WritePhysicalMemory(HANDLE device_handle, UINT64 address, void* buffer, DWORD size);
	
	// EneIo64 专用内存映射函数（使用正确的结构体）
	PVOID EneIo64MapMemory(HANDLE device_handle, ULONG_PTR physical_address, ULONG number_of_bytes, PVOID* object, PHANDLE section_handle);
	VOID EneIo64UnmapMemory(HANDLE device_handle, PVOID section_to_unmap, PVOID object, HANDLE section_handle);
	BOOL EneIo64ReadWritePhysicalMemory(HANDLE device_handle, ULONG_PTR physical_address, PVOID buffer, ULONG number_of_bytes, BOOLEAN do_write);
	BOOL EneIo64ReadPhysicalMemory(HANDLE device_handle, ULONG_PTR physical_address, PVOID buffer, ULONG number_of_bytes);
	BOOL EneIo64WritePhysicalMemory(HANDLE device_handle, ULONG_PTR physical_address, PVOID buffer, ULONG number_of_bytes);

	// KDU标准函数声明
	PVOID SuperMapMemory(HANDLE device_handle, ULONG_PTR PhysicalAddress, ULONG NumberOfBytes, DWORD MappingType);
	VOID SuperUnmapMemory(HANDLE device_handle, PVOID VirtualAddress, ULONG NumberOfBytes, DWORD MappingType);
	ULONG_PTR SuperGetPML4FromLowStub1M(ULONG_PTR pbLowStub1M);
	BOOL SuperQueryPML4Value(HANDLE device_handle, ULONG_PTR* value);
	BOOL PwVirtualToPhysical(HANDLE device_handle, ProvQueryPML4 QueryPML4Routine, ProvReadPhysicalMemory ReadPhysicalMemoryRoutine, ULONG_PTR VirtualAddress, ULONG_PTR* PhysicalAddress);

	// 兼容旧版本的内存映射函数
	UINT64 MapPhysicalMemory(HANDLE device_handle, UINT64 size);
	bool UnmapPhysicalMemory(HANDLE device_handle, UINT64 mapped_address, UINT64 size);

	// 兼容 kdmapper 的接口
	bool ReadMemory(HANDLE device_handle, uint64_t address, void* buffer, uint64_t size);
	bool WriteMemory(HANDLE device_handle, uint64_t address, void* buffer, uint64_t size);
	bool WritePhysicalMemoryDirect(HANDLE device_handle, uint64_t physical_address, void* buffer, uint64_t size);
	uint64_t AllocatePool(HANDLE device_handle, uint32_t pool_type, uint64_t size);
	bool FreePool(HANDLE device_handle, uint64_t address);
	uint64_t GetKernelModuleExport(HANDLE device_handle, uint64_t kernel_module_base, const std::string& function_name);
	bool CallKernelFunction(HANDLE device_handle, void* output, uint64_t kernel_function_address, uint64_t param1 = 0, uint64_t param2 = 0);

	// 虚拟到物理地址转换
	UINT64 VirtualToPhysical(HANDLE device_handle, UINT64 cr3, UINT64 virtualAddr);
	
	// 强制虚拟到物理地址转换（绕过永久禁用检查，专用于用户空间地址）
	UINT64 VirtualToPhysicalForced(HANDLE device_handle, UINT64 cr3, UINT64 virtualAddr);
	
	// 获取当前进程的 CR3 值
	uint64_t GetCurrentProcessCR3(HANDLE device_handle);
	
	// 获取 ntoskrnl 基地址
	uint64_t GetNtoskrnlBaseAddress(HANDLE device_handle);
	
	// 物理内存扫描查找内核模块
	uint64_t ScanPhysicalMemoryForKernel(HANDLE device_handle);
}