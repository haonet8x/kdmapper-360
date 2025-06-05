#include "DriverCtrl.h"
#include <Windows.h>

#include <iostream>

#define Log(content) std::wcout << content


typedef struct info_t {
    int pid = 0;
    DWORD_PTR address;
    void* value;
    SIZE_T size;
    void* data;
}info, * p_info;

bool DriverHello() {
    auto hDriver = CreateFileW(L"\\\\.\\u8CI", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hDriver == INVALID_HANDLE_VALUE)
    {
        Log("Invalid DriverHandle\n");
        return false;
    }

    info_t Input_Output_Data1 = { 0 };
    unsigned long int Readed_Bytes_Amount1;
    //DeviceIoControl(hDriver, ctl_clear, &Input_Output_Data1, sizeof Input_Output_Data1, &Input_Output_Data1, sizeof Input_Output_Data1, &Readed_Bytes_Amount1, nullptr);
    DeviceIoControl(hDriver, ctl_hello, &Input_Output_Data1, sizeof Input_Output_Data1, &Input_Output_Data1, sizeof Input_Output_Data1, &Readed_Bytes_Amount1, nullptr);

    CloseHandle(hDriver);
    return true;
}

