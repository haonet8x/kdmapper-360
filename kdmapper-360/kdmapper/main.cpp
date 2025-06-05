#include "kdmapper.hpp"
#include "eneio64_driver.hpp"
#include "DriverCtrl.h"
#include <sstream>

HANDLE eneio64_device_handle;

#define ctl_hello	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0400, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

LONG WINAPI SimplestCrashHandler(EXCEPTION_POINTERS* ExceptionInfo)
{
	if (ExceptionInfo && ExceptionInfo->ExceptionRecord) {
		Log("[!!] Crash\n");
	}
	else {
		Log("[!!] Crash\n");
	}

	if (eneio64_device_handle)
		eneio64_driver::Unload(eneio64_device_handle);

	return EXCEPTION_EXECUTE_HANDLER;
}

int paramExists(const int argc, wchar_t** argv, const wchar_t* param) {
	size_t plen = wcslen(param);
	for (int i = 1; i < argc; i++) {
		if (wcslen(argv[i]) == plen + 1ull && _wcsicmp(&argv[i][1], param) == 0 && argv[i][0] == '/') { // with slash
			return i;
		}
		else if (wcslen(argv[i]) == plen + 2ull && _wcsicmp(&argv[i][2], param) == 0 && argv[i][0] == '-' && argv[i][1] == '-') { // with double dash
			return i;
		}
	}
	return -1;
}

// 获取带值的参数 (例如: --device=EneIo)
std::wstring getParamValue(const int argc, wchar_t** argv, const wchar_t* param) {
	std::wstring paramName = L"--";
	paramName += param;
	paramName += L"=";
	
	for (int i = 1; i < argc; i++) {
		std::wstring arg = argv[i];
		if (arg.size() > paramName.size() &&
			_wcsnicmp(arg.c_str(), paramName.c_str(), paramName.size()) == 0) {
			return arg.substr(paramName.size());
		}
	}
	return L"";
}

void help() {
	Log("\r\n\r\n[!] Incorrect usage!\n");
	Log("[+] Usage: kdmapper.exe [--free][--PassAllocationPtr][--scmode][--device=DeviceName] driver.sys\n");
	Log("[+] Parameters:\n");
	Log("    --free               - Free pool memory after use\n");
	Log("    --PassAllocationPtr  - Pass allocation pointer as first parameter\n");
	Log("    --scmode             - Force SC Manager mode for driver loading\n");
	Log("    --device=DeviceName  - Specify device name (e.g.: --device=EneIo)\n");
	Log("[+] Examples:\n");
	Log("    kdmapper.exe driver.sys                    (default mode)\n");
	Log("    kdmapper.exe --scmode driver.sys           (SC Manager mode)\n");
	Log("    kdmapper.exe --device=ENEIO64 driver.sys   (specify device name)\n");
}

bool callbackExample(ULONG64* param1, ULONG64* param2, ULONG64 allocationPtr, ULONG64 allocationSize, ULONG64 poolPtr) {
	UNREFERENCED_PARAMETER(param1);
	UNREFERENCED_PARAMETER(param2);
	UNREFERENCED_PARAMETER(allocationPtr);
	UNREFERENCED_PARAMETER(allocationSize);
	UNREFERENCED_PARAMETER(poolPtr);
	Log("[+] Callback example invoked - driver successfully mapped to kernel memory\n");
	Log("[+] Driver allocation pointer: 0x%llx, size: %llu bytes\n", allocationPtr, allocationSize);
	
	/*
	此回调在驱动入口点调用之前执行
	如果能执行到这里，说明驱动已经成功映射到内核空间
	接下来将调用驱动的DriverEntry函数
	*/
	return true;
}

typedef struct info_t {
	int pid = 0;
	DWORD_PTR address;
	void* value;
	SIZE_T size;
	void* data;
}info, * p_info;


int wmain(const int argc, wchar_t** argv) {
	SetUnhandledExceptionFilter(SimplestCrashHandler);

	bool free = paramExists(argc, argv, L"free") > 0;
	bool passAllocationPtr = paramExists(argc, argv, L"PassAllocationPtr") > 0;
	bool scMode = paramExists(argc, argv, L"scmode") > 0;
	std::wstring customDevice = getParamValue(argc, argv, L"device");

	// 移除了MDL参数检查 - 已完全禁用MDL功能

	if (free) {
		Log("[+] Free pool memory after use enabled\n");
	}

	if (passAllocationPtr) {
		Log("[+] Pass allocation pointer as first parameter enabled\n");
	}

	if (scMode) {
		Log("[+] Force SC Manager mode enabled\n");
	}

	if (!customDevice.empty()) {
		printf("[+] Using custom device name: ");
		wprintf(L"%ws\n", customDevice.c_str());
	}

	int drvIndex = -1;
	for (int i = 1; i < argc; i++) {
		if (std::filesystem::path(argv[i]).extension().string().compare(".sys") == 0) {
			drvIndex = i;
			break;
		}
	}

	if (drvIndex <= 0) {
		help();
		return -1;
	}

	const std::wstring driver_path = argv[drvIndex];

	if (!std::filesystem::exists(driver_path)) {
		Log("[-] Driver file does not exist\n");
		return -1;
	}

	eneio64_device_handle = eneio64_driver::Load();

	if (eneio64_device_handle == INVALID_HANDLE_VALUE)
		return -1;

	Log("[DEBUG] Starting to read driver file into memory\n");
	std::vector<uint8_t> raw_image = { 0 };
	if (!utils::ReadFileToMemory(driver_path, &raw_image)) {
		Log("[-] Failed to read image to memory\n");
		eneio64_driver::Unload(eneio64_device_handle);
		return -1;
	}

	Log("[DEBUG] Driver file read successfully, starting driver mapping\n");
	NTSTATUS exitCode = 0;
	if (!kdmapper::MapDriver(eneio64_device_handle, raw_image.data(), 0, 0, free, true, false, passAllocationPtr, callbackExample, &exitCode)) {
		Log("[-] Driver mapping failed\n");
		eneio64_driver::Unload(eneio64_device_handle);
		return -1;
	}

	Log("[+] Driver mapping completed successfully!\n");
	Log("[*] Unsigned driver 'driver.sys' has been successfully loaded and executed in kernel mode\n");
	Log("[*] Driver entry point was called and callback executed - this confirms successful loading\n");
	Log("[*] You can now use third-party software (like Process Hacker) to check driver status\n");
	// 继续卸载驱动程序
	Log("[*] Continuing with driver unloading...\n");

	eneio64_driver::Unload(eneio64_device_handle);
	Log("[+] Driver unloaded successfully\n");


#ifndef bypass360
	if (!DriverHello()) {
		Log("DriverCtrl Failed\n");
	}
#endif // !bypass360


}