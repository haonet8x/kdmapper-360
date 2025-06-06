#include "kdmapper.hpp"
#include <Windows.h>
#include <iostream>

#include "utils.hpp"
#include "eneio64_driver.hpp"
#include "nt.hpp"
#include "portable_executable.hpp"

// 定义页面大小常量
#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

ULONG64 AllocIndependentPages(HANDLE device_handle, ULONG32 size)
{
	const auto base = eneio64_driver::MmAllocateIndependentPagesEx(device_handle, size);
	if (!base)
	{
		std::cout << "[-] Error allocating independent pages" << std::endl;
		return 0;
	}

	if (!eneio64_driver::MmSetPageProtection(device_handle, base, size, PAGE_EXECUTE_READWRITE))
	{
		std::cout << "[-] Failed to change page protections" << std::endl;
		eneio64_driver::MmFreeIndependentPages(device_handle, base, size);
		return 0;
	}

	return base;
}

// 分配连续物理内存MDL - 根据参考文档第455-510行实现
ULONG64 AllocContiguousMdlMemory(HANDLE eneio64_device_handle, uint64_t size, uint64_t* mdlPtr) {
	/*added by psec*/
	LARGE_INTEGER LowAddress, HighAddress, SkipAddress;
	LowAddress.QuadPart = 0;
	HighAddress.QuadPart = 0xffff'ffff'ffff'ffffULL;
	SkipAddress.QuadPart = 0;
	uint64_t pages = (size / PAGE_SIZE) + 1;
	auto mdl = eneio64_driver::MmAllocatePagesForMdlEx(
		eneio64_device_handle,
		LowAddress,
		HighAddress,
		SkipAddress,
		pages * (uint64_t)PAGE_SIZE,
		nt::MEMORY_CACHING_TYPE::MmNonCached,
		nt::MEMORY_ALLOCATE_FLAG::MM_ALLOCATE_REQUIRE_CONTIGUOUS_CHUNKS);
	if (!mdl) {
		Log(L"[-] Can't allocate pages for mdl" << std::endl);
		return { 0 };
	}

	uint32_t byteCount = 0;
	if (!eneio64_driver::ReadMemory(eneio64_device_handle, mdl + 0x028 /*_MDL : byteCount*/, &byteCount, sizeof(uint32_t))) {
		Log(L"[-] Can't read the _MDL : byteCount" << std::endl);
		return { 0 };
	}

	if (byteCount < size) {
		Log(L"[-] Couldn't allocate enough memory, cleaning up" << std::endl);
		eneio64_driver::MmFreePagesFromMdl(eneio64_device_handle, mdl);
		eneio64_driver::FreePool(eneio64_device_handle, mdl);
		return { 0 };
	}

	auto mappingStartAddress = eneio64_driver::MmMapLockedPagesSpecifyCache(eneio64_device_handle, mdl, nt::KernelMode, nt::MmCached, NULL, FALSE, nt::NormalPagePriority);
	if (!mappingStartAddress) {
		Log(L"[-] Can't set mdl pages cache, cleaning up." << std::endl);
		eneio64_driver::MmFreePagesFromMdl(eneio64_device_handle, mdl);
		eneio64_driver::FreePool(eneio64_device_handle, mdl);
		return { 0 };
	}

	const auto result = eneio64_driver::MmProtectMdlSystemAddress(eneio64_device_handle, mdl, PAGE_EXECUTE_READWRITE);
	if (!result) {
		Log(L"[-] Can't change protection for mdl pages, cleaning up" << std::endl);
		eneio64_driver::MmUnmapLockedPages(eneio64_device_handle, mappingStartAddress, mdl);
		eneio64_driver::MmFreePagesFromMdl(eneio64_device_handle, mdl);
		eneio64_driver::FreePool(eneio64_device_handle, mdl);
		return { 0 };
	}
	Log(L"[+] Allocated pages for mdl" << std::endl);

	if (mdlPtr)
		*mdlPtr = mdl;

	return mappingStartAddress;
}

void RelocateImageByDelta(portable_executable::vec_relocs relocs, const ULONG64 delta) {
	for (const auto& current_reloc : relocs) {
		for (auto i = 0u; i < current_reloc.count; ++i) {
			const uint16_t type = current_reloc.item[i] >> 12;
			const uint16_t offset = current_reloc.item[i] & 0xFFF;

			if (type == IMAGE_REL_BASED_DIR64)
				*reinterpret_cast<ULONG64*>(current_reloc.address + offset) += delta;
		}
	}
}

// Fix cookie by @Jerem584
bool FixSecurityCookie(void* local_image, ULONG64 kernel_image_base)
{
	auto headers = portable_executable::GetNtHeaders(local_image);
	if (!headers)
		return false;

	auto load_config_directory = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
	if (!load_config_directory)
	{
		Log(L"[+] Load config directory wasn't found, probably StackCookie not defined, fix cookie skipped" << std::endl);
		return true;
	}

	auto load_config_struct = (PIMAGE_LOAD_CONFIG_DIRECTORY)((uintptr_t)local_image + load_config_directory);
	auto stack_cookie = load_config_struct->SecurityCookie;
	if (!stack_cookie)
	{
		Log(L"[+] StackCookie not defined, fix cookie skipped" << std::endl);
		return true; // as I said, it is not an error and we should allow that behavior
	}

	stack_cookie = stack_cookie - (uintptr_t)kernel_image_base + (uintptr_t)local_image; //since our local image is already relocated the base returned will be kernel address

	if (*(uintptr_t*)(stack_cookie) != 0x2B992DDFA232) {
		Log(L"[-] StackCookie already fixed!? this probably wrong" << std::endl);
		return false;
	}

	Log(L"[+] Fixing stack cookie" << std::endl);

	auto new_cookie = 0x2B992DDFA232 ^ GetCurrentProcessId() ^ GetCurrentThreadId(); // here we don't really care about the value of stack cookie, it will still works and produce nice result
	if (new_cookie == 0x2B992DDFA232)
		new_cookie = 0x2B992DDFA233;

	*(uintptr_t*)(stack_cookie) = new_cookie; // the _security_cookie_complement will be init by the driver itself if they use crt
	return true;
}

bool ResolveImports(HANDLE iqvw64e_device_handle, portable_executable::vec_imports imports) {
	for (const auto& current_import : imports) {
		ULONG64 Module = utils::GetKernelModuleAddress(current_import.module_name);
		if (!Module) {
#if !defined(DISABLE_OUTPUT)
			std::cout << "[-] Dependency " << current_import.module_name << " wasn't found" << std::endl;
#endif
			return false;
		}

		for (auto& current_function_data : current_import.function_datas) {
			ULONG64 function_address = eneio64_driver::GetKernelModuleExport(iqvw64e_device_handle, Module, current_function_data.name);

			if (!function_address) {
				//Lets try with ntoskrnl
				if (Module != eneio64_driver::ntoskrnlAddr) {
					function_address = eneio64_driver::GetKernelModuleExport(iqvw64e_device_handle, eneio64_driver::ntoskrnlAddr, current_function_data.name);
					if (!function_address) {
#if !defined(DISABLE_OUTPUT)
						std::cout << "[-] Failed to resolve import " << current_function_data.name << " (" << current_import.module_name << ")" << std::endl;
#endif
						return false;
					}
				}
			}

			*current_function_data.address = function_address;
		}
	}

	return true;
}

ULONG64 kdmapper::MapDriver(HANDLE iqvw64e_device_handle, BYTE* data, ULONG64 param1, ULONG64 param2, bool free, bool destroyHeader, AllocationMode mode, bool PassAllocationAddressAsFirstParam, mapCallback callback, NTSTATUS* exitCode) {

	const PIMAGE_NT_HEADERS64 nt_headers = portable_executable::GetNtHeaders(data);

	if (!nt_headers) {
		Log(L"[-] Invalid format of PE image" << std::endl);
		return 0;
	}

	if (nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		Log(L"[-] Image is not 64 bit" << std::endl);
		return 0;
	}

	ULONG32 image_size = nt_headers->OptionalHeader.SizeOfImage;

	void* local_image_base = VirtualAlloc(nullptr, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!local_image_base)
		return 0;

	DWORD TotalVirtualHeaderSize = (IMAGE_FIRST_SECTION(nt_headers))->VirtualAddress;
	image_size = image_size - (destroyHeader ? TotalVirtualHeaderSize : 0);

	ULONG64 kernel_image_base = 0;
	uint64_t mdlptr = 0;
	if (mode == AllocationMode::AllocateIndependentPages) {
		kernel_image_base = AllocIndependentPages(iqvw64e_device_handle, image_size);
	}
	else { // 使用连续物理内存分配 - 根据参考文档第524-533行修改
		// 原始代码：kernel_image_base = eneio64_driver::AllocatePool(iqvw64e_device_handle, nt::POOL_TYPE::NonPagedPool, image_size);
		// 修改为使用连续物理内存，避免物理页面不连续导致的问题
		kernel_image_base = eneio64_driver::MmAllocateContiguousMemory(iqvw64e_device_handle, image_size);
		if (!kernel_image_base) {
			// 如果连续内存分配失败，尝试MDL方式
			Log(L"[!] MmAllocateContiguousMemory failed, trying MDL allocation" << std::endl);
			kernel_image_base = AllocContiguousMdlMemory(iqvw64e_device_handle, image_size, &mdlptr);
		}
	}

	if (!kernel_image_base) {
		Log(L"[-] Failed to allocate remote image in kernel" << std::endl);

		VirtualFree(local_image_base, 0, MEM_RELEASE);
		return 0;
	}

	do {
		Log(L"[+] Image base has been allocated at 0x" << reinterpret_cast<void*>(kernel_image_base) << std::endl);

		// Copy image headers

		memcpy(local_image_base, data, nt_headers->OptionalHeader.SizeOfHeaders);

		// Copy image sections

		const PIMAGE_SECTION_HEADER current_image_section = IMAGE_FIRST_SECTION(nt_headers);

		for (auto i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
			if ((current_image_section[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) > 0)
				continue;
			auto local_section = reinterpret_cast<void*>(reinterpret_cast<ULONG64>(local_image_base) + current_image_section[i].VirtualAddress);
			memcpy(local_section, reinterpret_cast<void*>(reinterpret_cast<ULONG64>(data) + current_image_section[i].PointerToRawData), current_image_section[i].SizeOfRawData);
		}

		ULONG64 realBase = kernel_image_base;
		if (destroyHeader) {
			kernel_image_base -= TotalVirtualHeaderSize;
			Log(L"[+] Skipped 0x" << std::hex << TotalVirtualHeaderSize << L" bytes of PE Header" << std::endl);
		}

		// Resolve relocs and imports

		RelocateImageByDelta(portable_executable::GetRelocs(local_image_base), kernel_image_base - nt_headers->OptionalHeader.ImageBase);

		if (!FixSecurityCookie(local_image_base, kernel_image_base ))
		{
			Log(L"[-] Failed to fix cookie" << std::endl);
			return 0;
		}

		if (!ResolveImports(iqvw64e_device_handle, portable_executable::GetImports(local_image_base))) {
			Log(L"[-] Failed to resolve imports" << std::endl);
			kernel_image_base = realBase;
			break;
		}

		// Write fixed image to kernel

		if (!eneio64_driver::WriteMemory(iqvw64e_device_handle, realBase, (PVOID)((uintptr_t)local_image_base + (destroyHeader ? TotalVirtualHeaderSize : 0)), image_size)) {
			Log(L"[-] Failed to write local image to remote image" << std::endl);
			kernel_image_base = realBase;
			break;
		}

		// Call driver entry point

		const ULONG64 address_of_entry_point = kernel_image_base + nt_headers->OptionalHeader.AddressOfEntryPoint;

		Log(L"[<] Calling DriverEntry 0x" << reinterpret_cast<void*>(address_of_entry_point) << std::endl);

		if (callback) {
			if (!callback(&param1, &param2, realBase, image_size)) {
				Log(L"[-] Callback returns false, failed!" << std::endl);
				kernel_image_base = realBase;
				break;
			}
		}

		NTSTATUS status = 0;
		if (!eneio64_driver::CallKernelFunction(iqvw64e_device_handle, &status, address_of_entry_point, (PassAllocationAddressAsFirstParam ? realBase : param1), param2)) {
			Log(L"[-] Failed to call driver entry" << std::endl);
			kernel_image_base = realBase;
			break;
		}

		if (exitCode)
			*exitCode = status;

		Log(L"[+] DriverEntry returned 0x" << std::hex << status << std::endl);

		// Free memory
		if (free) {
			Log(L"[+] Freeing memory" << std::endl);
			bool free_status = false;

			if (mode == AllocationMode::AllocateIndependentPages)
			{
				free_status = eneio64_driver::MmFreeIndependentPages(iqvw64e_device_handle, realBase, image_size);
			}
			else {
				// 如果使用了MDL分配，需要正确清理MDL
				if (mdlptr != 0) {
					Log(L"[+] Freeing MDL memory" << std::endl);
					eneio64_driver::MmUnmapLockedPages(iqvw64e_device_handle, realBase, mdlptr);
					eneio64_driver::MmFreePagesFromMdl(iqvw64e_device_handle, mdlptr);
					eneio64_driver::FreePool(iqvw64e_device_handle, mdlptr);
					free_status = true;
				}
				else {
					// 使用连续物理内存分配的情况，需要使用FreePool清理
					free_status = eneio64_driver::FreePool(iqvw64e_device_handle, realBase);
				}
			}

			if (free_status) {
				Log(L"[+] Memory has been released" << std::endl);
			}
			else {
				Log(L"[-] WARNING: Failed to free memory!" << std::endl);
			}
		}



		VirtualFree(local_image_base, 0, MEM_RELEASE);
		return realBase;

	} while (false);


	VirtualFree(local_image_base, 0, MEM_RELEASE);

	Log(L"[+] Freeing memory" << std::endl);
	bool free_status = false;

	if (mode == AllocationMode::AllocateIndependentPages)
	{
		free_status = eneio64_driver::MmFreeIndependentPages(iqvw64e_device_handle, kernel_image_base, image_size);
	}
	else {
		free_status = eneio64_driver::FreePool(iqvw64e_device_handle, kernel_image_base);
	}

	if (free_status) {
		Log(L"[+] Memory has been released" << std::endl);
	}
	else {
		Log(L"[-] WARNING: Failed to free memory!" << std::endl);
	}

	return 0;
}


