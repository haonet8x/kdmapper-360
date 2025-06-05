#include "kdmapper.hpp"

// 使用EneIo64驱动接口进行驱动映射

uint64_t kdmapper::MapDriver(HANDLE iqvw64e_device_handle, BYTE* data, ULONG64 param1, ULONG64 param2, bool free, bool destroyHeader, bool mdlMode, bool PassAllocationAddressAsFirstParam, mapCallback callback, NTSTATUS* exitCode) {
	// 忽略mdlMode参数 - 使用池分配
	UNREFERENCED_PARAMETER(mdlMode);

	const PIMAGE_NT_HEADERS64 nt_headers = portable_executable::GetNtHeaders(data);
	if (!nt_headers) {
		Log("[-] Invalid PE headers\n");
		return 0;
	}

	if (nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		Log("[-] Image is not 64 bit\n");
		return 0;
	}

	const uint32_t image_size = nt_headers->OptionalHeader.SizeOfImage;
	
	void* local_image_base = VirtualAlloc(nullptr, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!local_image_base) {
		Log("[-] Failed to allocate local image base\n");
		return 0;
	}

	DWORD TotalVirtualHeaderSize = (destroyHeader) ? nt_headers->OptionalHeader.SizeOfHeaders : 0;
	uint64_t RealBase = eneio64_driver::AllocatePool(iqvw64e_device_handle, 0, image_size);
	if (!RealBase) {
		Log("[-] Failed to allocate pool memory\n");
		VirtualFree(local_image_base, 0, MEM_RELEASE);
		return 0;
	}

	do {
		if (!memcpy(local_image_base, data, nt_headers->OptionalHeader.SizeOfHeaders)) {
			Log("[-] Failed to copy headers\n");
			break;
		}

		const PIMAGE_SECTION_HEADER current_image_section = IMAGE_FIRST_SECTION(nt_headers);
		for (auto i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
			if (!memcpy((void*)((uintptr_t)local_image_base + current_image_section[i].VirtualAddress), (void*)((uintptr_t)data + current_image_section[i].PointerToRawData), current_image_section[i].SizeOfRawData)) {
				Log("[-] Failed to copy section\n");
				goto CLEANUP_ALLOCATIONS;
			}
		}

		uint64_t realBase = RealBase;

		// Relocate image
		RelocateImageByDelta(portable_executable::GetRelocs(local_image_base), realBase - nt_headers->OptionalHeader.ImageBase);

		// Resolve imports
		if (!ResolveImports(iqvw64e_device_handle, portable_executable::GetImports(local_image_base))) {
			Log("[-] Failed to resolve imports\n");
			goto CLEANUP_ALLOCATIONS;
		}

		// Write image to kernel
		if (!eneio64_driver::WriteMemory(iqvw64e_device_handle, realBase + TotalVirtualHeaderSize, (PVOID)((uintptr_t)local_image_base + TotalVirtualHeaderSize), image_size - TotalVirtualHeaderSize)) {
			Log("[-] Failed to write image to kernel\n");
			goto CLEANUP_ALLOCATIONS;
		}

		char info_msg[256];
		sprintf_s(info_msg, "[+] Image base: 0x%llx\n", (unsigned long long)realBase);
		Log(info_msg);
		sprintf_s(info_msg, "[+] Entry point: 0x%llx\n", (unsigned long long)(realBase + nt_headers->OptionalHeader.AddressOfEntryPoint));
		Log(info_msg);

		VirtualFree(local_image_base, 0, MEM_RELEASE);

		if (callback) {
			NTSTATUS status = 0; // STATUS_SUCCESS

			if (PassAllocationAddressAsFirstParam) {
				status = callback(&realBase, &param1, param2, image_size, 0); // 使用池分配
			} else {
				status = callback(&param1, &param2, realBase, image_size, 0); // 使用池分配
			}

			if (exitCode) {
				*exitCode = status;
			}
		}

		if (free) {
			eneio64_driver::FreePool(iqvw64e_device_handle, RealBase);
		}

		return realBase;

	} while (false);

CLEANUP_ALLOCATIONS:
	eneio64_driver::FreePool(iqvw64e_device_handle, RealBase);
	VirtualFree(local_image_base, 0, MEM_RELEASE);
	return 0;
}

void kdmapper::RelocateImageByDelta(portable_executable::vec_relocs relocs, const uint64_t delta) {
	for (const auto& current_reloc : relocs) {
		for (auto i = 0u; i < current_reloc.count; ++i) {
			const uint16_t type = current_reloc.item[i] >> 12;
			const uint16_t offset = current_reloc.item[i] & 0xFFF;

			if (type == IMAGE_REL_BASED_DIR64)
				*(uint64_t*)((uintptr_t)current_reloc.address + offset) += delta;
		}
	}
}

bool kdmapper::ResolveImports(HANDLE iqvw64e_device_handle, portable_executable::vec_imports imports) {
	for (const auto& current_import : imports) {
		ULONG64 module_base = utils::GetKernelModuleAddress(current_import.module_name.c_str());
		if (!module_base) {
			std::cout << "[-] Failed to get " << current_import.module_name.data() << std::endl;
			return false;
		}

		for (const auto& current_function : current_import.function_datas) {
			auto function_rva = eneio64_driver::GetKernelModuleExport(iqvw64e_device_handle, module_base, current_function.name.c_str());
			if (!function_rva) {
				std::cout << "[-] Failed to get export " << current_function.name.data() << std::endl;
				return false;
			}

			*current_function.address = function_rva;
		}
	}

	return true;
}
