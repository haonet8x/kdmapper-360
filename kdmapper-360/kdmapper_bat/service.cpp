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
	// �򿪷�����ƹ��������ݿ�
	SC_HANDLE schSCManager = OpenSCManager(
		NULL,                   // Ŀ������������,NULL�����ӱ��ؼ�����ϵķ�����ƹ�����
		NULL,                   // ������ƹ��������ݿ�����ƣ�NULL���� SERVICES_ACTIVE_DATABASE ���ݿ�
		SC_MANAGER_ALL_ACCESS   // ����Ȩ��
	);
	if (schSCManager == NULL)
		return FALSE;
	auto DRIVER_NAME = intel_driver::GetDriverNameW();
	//const std::wstring nPath = L"\\??\\" + driver_path;
	const std::wstring nPath = driver_path;

	// ����������������������ƹ��������ݿ�
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
		CloseServiceHandle(schSCManager);
		return FALSE;
	}

// ��������

	// �򿪷���
	SC_HANDLE hs = OpenService(
		schSCManager,           // ����ؼ����������ݿ�ľ��
		DRIVER_NAME.c_str(),            // Ҫ�򿪵ķ�����
		SERVICE_ALL_ACCESS      // �������Ȩ�ޣ�����Ȩ��
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
