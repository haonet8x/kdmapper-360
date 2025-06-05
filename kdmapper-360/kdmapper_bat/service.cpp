#include "service.hpp"

bool service::RegisterAndStart(const std::wstring& driver_path) {
	const static DWORD ServiceTypeKernel = 1;
	const std::wstring driver_name = intel_driver::GetDriverNameW();
	const std::wstring servicesPath = L"SYSTEM\\CurrentControlSet\\Services\\" + driver_name;
	const std::wstring nPath = L"\\??\\" + driver_path;

	HKEY dservice;
	LSTATUS status = RegCreateKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &dservice); //Returns Ok if already exists
	if (status != ERROR_SUCCESS) {
		Log("[-] Can't create service key" << std::endl);
		return false;
	}
	
	status = RegSetKeyValueW(dservice, NULL, L"ImagePath", REG_EXPAND_SZ, nPath.c_str(), (DWORD)(nPath.size()*sizeof(wchar_t)));
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		Log("[-] Can't create 'ImagePath' registry value" << std::endl);
		return false;
	}
	
	status = RegSetKeyValueW(dservice, NULL, L"Type", REG_DWORD, &ServiceTypeKernel, sizeof(DWORD));
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		Log("[-] Can't create 'Type' registry value" << std::endl);
		return false;
	}
	
	RegCloseKey(dservice);

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL) {
		return false;
	}

	auto RtlAdjustPrivilege = (nt::RtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");
	auto NtLoadDriver = (nt::NtLoadDriver)GetProcAddress(ntdll, "NtLoadDriver");

	ULONG SE_LOAD_DRIVER_PRIVILEGE = 10UL;
	BOOLEAN SeLoadDriverWasEnabled;
	NTSTATUS Status = RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &SeLoadDriverWasEnabled);
	if (!NT_SUCCESS(Status)) {
		Log("Fatal error: failed to acquire SE_LOAD_DRIVER_PRIVILEGE. Make sure you are running as administrator." << std::endl);
		return false;
	}

	std::wstring wdriver_reg_path = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + driver_name;
	UNICODE_STRING serviceStr;
	RtlInitUnicodeString(&serviceStr, wdriver_reg_path.c_str());

	Status = NtLoadDriver(&serviceStr);
	Log("[+] NtLoadDriver Status 0x" << std::hex << Status << std::endl);
	
	//Never should occur since kdmapper checks for "IsRunning" driver before
	if (Status == 0xC000010E) {// STATUS_IMAGE_ALREADY_LOADED
		return true;
	}
	
	return NT_SUCCESS(Status);
}

bool service::StopAndRemove(const std::wstring& driver_name) {
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL)
		return false;

	std::wstring wdriver_reg_path = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + driver_name;
	UNICODE_STRING serviceStr;
	RtlInitUnicodeString(&serviceStr, wdriver_reg_path.c_str());

	HKEY driver_service;
	std::wstring servicesPath = L"SYSTEM\\CurrentControlSet\\Services\\" + driver_name;
	LSTATUS status = RegOpenKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &driver_service);
	if (status != ERROR_SUCCESS) {
		if (status == ERROR_FILE_NOT_FOUND) {
			return true;
		}
		return false;
	}
	RegCloseKey(driver_service);

	auto NtUnloadDriver = (nt::NtUnloadDriver)GetProcAddress(ntdll, "NtUnloadDriver");
	NTSTATUS st = NtUnloadDriver(&serviceStr);
	Log("[+] NtUnloadDriver Status 0x" << std::hex << st << std::endl);
	if (st != 0x0) {
		Log("[-] Driver Unload Failed!!" << std::endl);
	}
	

	status = RegDeleteKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
	if (status != ERROR_SUCCESS) {
		return false;
	}
	return true;
}

#pragma warning(disable:4996)

BOOL service::installDvr(const std::wstring& driver_path) {
	Log(L"Loading Drive Path= " << driver_path << std::endl);
	// 打开服务控制管理器数据库
	SC_HANDLE schSCManager = OpenSCManager(
		NULL,                   // 目标计算机的名称,NULL：连接本地计算机上的服务控制管理器
		NULL,                   // 服务控制管理器数据库的名称，NULL：打开 SERVICES_ACTIVE_DATABASE 数据库
		SC_MANAGER_ALL_ACCESS   // 所有权限
	);
	if (schSCManager == NULL)
		return FALSE;
	auto DRIVER_NAME = intel_driver::GetDriverNameW();
	//const std::wstring nPath = L"\\??\\" + driver_path;
	const std::wstring nPath = driver_path;

	// 创建服务对象，添加至服务控制管理器数据库
	SC_HANDLE schService = CreateServiceW(
		schSCManager,               // 服务控件管理器数据库的句柄
		DRIVER_NAME.c_str(),               // 要安装的服务的名称
		DRIVER_NAME.c_str(),               // 用户界面程序用来标识服务的显示名称
		SERVICE_ALL_ACCESS,         // 对服务的访问权限：所有全权限
		SERVICE_KERNEL_DRIVER,      // 服务类型：驱动服务
		SERVICE_DEMAND_START,       // 服务启动选项：进程调用 StartService 时启动
		SERVICE_ERROR_NORMAL,       // 如果无法启动：忽略错误继续运行
		nPath.c_str(),                // 驱动文件绝对路径，如果包含空格需要多加双引号
		NULL,                       // 服务所属的负载订购组：服务不属于某个组
		NULL,                       // 接收订购组唯一标记值：不接收
		NULL,                       // 服务加载顺序数组：服务没有依赖项
		NULL,                       // 运行服务的账户名：使用 LocalSystem 账户
		NULL                        // LocalSystem 账户密码
	);
	if (schService == NULL) {
		CloseServiceHandle(schSCManager);
		return FALSE;
	}

// 启动服务

	// 打开服务
	SC_HANDLE hs = OpenService(
		schSCManager,           // 服务控件管理器数据库的句柄
		DRIVER_NAME.c_str(),            // 要打开的服务名
		SERVICE_ALL_ACCESS      // 服务访问权限：所有权限
	);
	if (hs == NULL) {
		CloseServiceHandle(schSCManager);
		MessageBoxA(0, 0, "OpenServiceErr", 0);
		return FALSE;
	}
	if (!StartServiceW(hs, 0, 0)) {
		Log(L"StartServiceW Err %d" << GetLastError() << std::endl);
		CloseServiceHandle(hs);
		CloseServiceHandle(schSCManager);
		return FALSE;
	}

	CloseServiceHandle(schService);
	CloseServiceHandle(hs);
	CloseServiceHandle(schSCManager);
	return TRUE;
}

BOOL service::UninstallDvr(const std::wstring& driver_name){
	SC_HANDLE schSCManager = OpenSCManager(
		NULL,                   // 目标计算机的名称,NULL：连接本地计算机上的服务控制管理器
		NULL,                   // 服务控制管理器数据库的名称，NULL：打开 SERVICES_ACTIVE_DATABASE 数据库
		SC_MANAGER_ALL_ACCESS   // 所有权限
	);
	if (schSCManager == NULL) {
		MessageBoxA(0, "打开服务控制管理器数据库Err", 0, 0);
		return FALSE;
	}

	// 打开服务
	SC_HANDLE hs = OpenService(
		schSCManager,           // 服务控件管理器数据库的句柄
		driver_name.c_str(),            // 要打开的服务名
		SERVICE_ALL_ACCESS      // 服务访问权限：所有权限
	);
	if (hs == NULL) {
		MessageBoxA(0, "OpenServiceErr", 0, 0);
		CloseServiceHandle(schSCManager);
		return FALSE;
	}

	// 如果服务正在运行
	SERVICE_STATUS status;
	QueryServiceStatus(hs, &status);

	if (status.dwCurrentState != SERVICE_STOPPED &&
		status.dwCurrentState != SERVICE_STOP_PENDING
		) {
		// 发送关闭服务请求
		if (ControlService(
			hs,                         // 服务句柄
			SERVICE_CONTROL_STOP,       // 控制码：通知服务应该停止
			&status                     // 接收最新的服务状态信息
		) == 0) {
			CloseServiceHandle(hs);
			CloseServiceHandle(schSCManager);
			MessageBoxA(0, "ControlServiceErr", 0, 0);
			return FALSE;
		}

		// 判断超时
		INT timeOut = 0;
		while (status.dwCurrentState != SERVICE_STOPPED) {
			timeOut++;
			QueryServiceStatus(hs, &status);

			Sleep(50);
		}
		if (timeOut > 80) {
			CloseServiceHandle(hs);
			CloseServiceHandle(schSCManager);
			MessageBoxA(0, "KillDriverTimeout", 0, 0);
			return FALSE;
		}
	}




	// 删除服务
	if (DeleteService(hs) == 0) {
		CloseServiceHandle(hs);
		CloseServiceHandle(schSCManager);
		return FALSE;
	}

	CloseServiceHandle(hs);
	CloseServiceHandle(schSCManager);
	return TRUE;

}
