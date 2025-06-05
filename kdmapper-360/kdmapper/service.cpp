#include "service.hpp"
#include <sstream>
#include <chrono>

bool service::RegisterAndStart(const std::wstring& driver_path) {
	const static DWORD ServiceTypeKernel = 1;
	const std::wstring driver_name = eneio64_driver::GetDriverNameW();
	const std::wstring servicesPath = L"SYSTEM\\CurrentControlSet\\Services\\" + driver_name;
	const std::wstring nPath = L"\\??\\" + driver_path;

	HKEY dservice;
	LSTATUS status = RegCreateKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &dservice); //Returns Ok if already exists
	if (status != ERROR_SUCCESS) {
		Log("[-] Failed to create service key\n");
		return false;
	}
	
	status = RegSetKeyValueW(dservice, NULL, L"ImagePath", REG_EXPAND_SZ, nPath.c_str(), (DWORD)(nPath.size()*sizeof(wchar_t)));
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		Log("[-] Failed to create 'ImagePath' registry value\n");
		return false;
	}
	
	status = RegSetKeyValueW(dservice, NULL, L"Type", REG_DWORD, &ServiceTypeKernel, sizeof(DWORD));
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		Log("[-] Failed to create 'Type' registry value\n");
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
		Log("FATAL: Failed to acquire SE_LOAD_DRIVER_PRIVILEGE. Please run as administrator.\n");
		return false;
	}

	std::wstring wdriver_reg_path = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + driver_name;
	UNICODE_STRING serviceStr;
	RtlInitUnicodeString(&serviceStr, wdriver_reg_path.c_str());

	Status = NtLoadDriver(&serviceStr);
	// 加载驱动状态日志
	Log("[+] NtLoadDriver Status 0x");
	printf("%x\n", Status);
	
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
	Log("[+] NtUnloadDriver Status: ");
	// NtUnloadDriver 状态
	printf("0x%lx\n", (unsigned long)st);
	if (st != 0x0) {
		Log("[-] Driver unload failed!!\n");
	}
	

	status = RegDeleteKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
	if (status != ERROR_SUCCESS) {
		return false;
	}
	return true;
}

#pragma warning(disable:4996)

BOOL service::installDvr(const std::wstring& driver_path) {
	Log("[*] Loading driver via SC Manager, path: ");
	// 使用 SC Manager 加载驱动路径
	wprintf(L"%s\n", driver_path.c_str());
	// 打开服务控制管理器数据库
	SC_HANDLE schSCManager = OpenSCManager(
		NULL,                   // 目标计算机名称，NULL表示连接本地计算机系统的服务控制管理器
		NULL,                   // 服务控制管理器数据库名称，NULL表示 SERVICES_ACTIVE_DATABASE 数据库
		SC_MANAGER_ALL_ACCESS   // 访问权限
	);
	if (schSCManager == NULL)
		return FALSE;
	auto DRIVER_NAME = eneio64_driver::GetDriverNameW();
	//const std::wstring nPath = L"\\??\\" + driver_path;
	const std::wstring nPath = driver_path;

	// 先尝试删除可能存在的同名服务以避免错误183
	Log("[*] Checking for existing service...\n");
	SC_HANDLE existingService = OpenServiceW(schSCManager, DRIVER_NAME.c_str(), SERVICE_ALL_ACCESS);
	if (existingService != NULL) {
		Log("[*] Found existing service, checking status...\n");
		SERVICE_STATUS serviceStatus;
		if (QueryServiceStatus(existingService, &serviceStatus)) {
			if (serviceStatus.dwCurrentState == SERVICE_RUNNING) {
				Log("[*] Service is running, attempting to stop...\n");
				ControlService(existingService, SERVICE_CONTROL_STOP, &serviceStatus);
				// 等待服务停止
				for (int i = 0; i < 30; i++) {
					Sleep(100);
					if (QueryServiceStatus(existingService, &serviceStatus)) {
						if (serviceStatus.dwCurrentState == SERVICE_STOPPED) {
							Log("[+] Service stopped successfully\n");
							break;
						}
					}
				}
			}
		}
		
		// 尝试删除服务
		if (DeleteService(existingService)) {
			Log("[+] Existing service deleted successfully\n");
		} else {
			Log("[-] Failed to delete existing service, error: ");
			printf("%lu\n", GetLastError());
		}
		CloseServiceHandle(existingService);
		
		// 等待一段时间确保服务完全删除
		Sleep(500);
	}

	// 创建新的服务到服务控制管理器数据库
	printf("[DEBUG] Creating service with name: ");
	wprintf(L"%s\n", DRIVER_NAME.c_str());
	SC_HANDLE schService = CreateServiceW(
		schSCManager,               // ����ؼ����������ݿ�ľ��
		DRIVER_NAME.c_str(),               // Ҫ��װ�ķ��������
		DRIVER_NAME.c_str(),               // �û��������������ʶ�������ʾ����
		SERVICE_ALL_ACCESS,         // �Է���ķ���Ȩ�ޣ�����ȫȨ��
		SERVICE_KERNEL_DRIVER,      // �������ͣ���������
		SERVICE_DEMAND_START,       // ��������ѡ����̵��� StartService ʱ����
		SERVICE_ERROR_NORMAL,       // ����޷����������Դ����������
		nPath.c_str(),                // �����ļ�����·������������ո���Ҫ���˫����
		NULL,                       // ���������ĸ��ض����飺��������ĳ����
		NULL,                       // ���ն�����Ψһ���ֵ��������
		NULL,                       // �������˳�����飺����û��������
		NULL,                       // ���з�����˻�����ʹ�� LocalSystem �˻�
		NULL                        // LocalSystem �˻�����
	);
	if (schService == NULL) {
		DWORD createError = GetLastError();
		printf("[-] CreateServiceW failed, error: %lu\n", createError);
		if (createError == ERROR_SERVICE_EXISTS) {
			Log("[-] Service already exists\n");
		} else if (createError == ERROR_INVALID_PARAMETER) {
			Log("[-] Invalid parameter in CreateServiceW\n");
		} else if (createError == 1072) { // ERROR_SERVICE_MARKED_FOR_DELETE
			Log("[-] Service marked for deletion, waiting and retrying...\n");
			
			// 等待服务完全删除，然后重试
			Sleep(1000);
			
			// 使用原名称重新创建服务
			schService = CreateServiceW(
				schSCManager,
				DRIVER_NAME.c_str(),
				DRIVER_NAME.c_str(),
				SERVICE_ALL_ACCESS,
				SERVICE_KERNEL_DRIVER,
				SERVICE_DEMAND_START,
				SERVICE_ERROR_NORMAL,
				nPath.c_str(),
				NULL, NULL, NULL, NULL, NULL
			);
			
			if (schService == NULL) {
				DWORD retryError = GetLastError();
				printf("[-] Retry with original name failed, error: %lu\n", retryError);
				CloseServiceHandle(schSCManager);
				return FALSE;
			} else {
				Log("[+] Service created successfully after waiting\n");
			}
		}
		
		if (schService == NULL) {
			CloseServiceHandle(schSCManager);
			return FALSE;
		}
	} else {
		Log("[+] Service created successfully\n");
	}

// ��������

	// 获取当前使用的驱动名称（可能是唯一名称）
	std::wstring currentDriverName = eneio64_driver::GetDriverNameW();
	
	// 打开服务
	SC_HANDLE hs = OpenService(
		schSCManager,           // 服务控制管理器数据库句柄
		currentDriverName.c_str(),            // 要打开的服务名
		SERVICE_ALL_ACCESS      // 期望的访问权限：所有权限
	);
	if (hs == NULL) {
		CloseServiceHandle(schSCManager);
		MessageBoxA(0, 0, "OpenServiceErr", 0);
		return FALSE;
	}
	if (!StartServiceW(hs, 0, 0)) {
		DWORD error = GetLastError();
		if (error == ERROR_SERVICE_ALREADY_RUNNING) {
			Log("[*] Service is already running, continuing...\n");
		} else if (error == 183) { // ERROR_ALREADY_EXISTS
			Log("[*] Service already exists/running, continuing...\n");
		} else {
			// 启动服务错误日志
			Log("StartServiceW Error ");
			printf("%lu\n", error);
			if (error == ERROR_SERVICE_REQUEST_TIMEOUT) {
				Log("[-] Service start timeout\n");
			} else if (error == ERROR_SERVICE_DISABLED) {
				Log("[-] Service is disabled\n");
			} else if (error == ERROR_PATH_NOT_FOUND) {
				Log("[-] Driver file path not found\n");
			}
			CloseServiceHandle(hs);
			CloseServiceHandle(schSCManager);
			return FALSE;
		}
	} else {
		Log("[+] Service started successfully\n");
	}

	CloseServiceHandle(schService);
	CloseServiceHandle(hs);
	CloseServiceHandle(schSCManager);
	return TRUE;
}

BOOL service::UninstallDvr(const std::wstring& driver_name){
	SC_HANDLE schSCManager = OpenSCManager(
		NULL,                   // Ŀ������������,NULL�����ӱ��ؼ�����ϵķ�����ƹ�����
		NULL,                   // ������ƹ��������ݿ�����ƣ�NULL���� SERVICES_ACTIVE_DATABASE ���ݿ�
		SC_MANAGER_ALL_ACCESS   // ����Ȩ��
	);
	if (schSCManager == NULL) {
		MessageBoxA(0, "�򿪷�����ƹ��������ݿ�Err", 0, 0);
		return FALSE;
	}

	// �򿪷���
	SC_HANDLE hs = OpenService(
		schSCManager,           // ����ؼ����������ݿ�ľ��
		driver_name.c_str(),            // Ҫ�򿪵ķ�����
		SERVICE_ALL_ACCESS      // �������Ȩ�ޣ�����Ȩ��
	);
	if (hs == NULL) {
		MessageBoxA(0, "OpenServiceErr", 0, 0);
		CloseServiceHandle(schSCManager);
		return FALSE;
	}

	// ���������������
	SERVICE_STATUS status;
	QueryServiceStatus(hs, &status);

	if (status.dwCurrentState != SERVICE_STOPPED &&
		status.dwCurrentState != SERVICE_STOP_PENDING
		) {
		// ���͹رշ�������
		if (ControlService(
			hs,                         // ������
			SERVICE_CONTROL_STOP,       // �����룺֪ͨ����Ӧ��ֹͣ
			&status                     // �������µķ���״̬��Ϣ
		) == 0) {
			CloseServiceHandle(hs);
			CloseServiceHandle(schSCManager);
			MessageBoxA(0, "ControlServiceErr", 0, 0);
			return FALSE;
		}

		// �жϳ�ʱ
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




	// ɾ������
	if (DeleteService(hs) == 0) {
		CloseServiceHandle(hs);
		CloseServiceHandle(schSCManager);
		return FALSE;
	}

	CloseServiceHandle(hs);
	CloseServiceHandle(schSCManager);
	return TRUE;

}
