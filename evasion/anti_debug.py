import os



import sys



import ctypes



import platform



import random



import time



from typ in gimport List,Dict,Any







clas sAntiDebugTechnique:











def__init__(self):



        self.techniques={



'w in dows':[



self._check_be in g_debugged,



self._check_remote_debugger_present,



self._check_debug_port,



self._meas ure_execution_time,



self._check_system_debugger_objects



],



'l in ux':[



self._check_parent_tracer,



self._check_proc_status,



self._meas ure_execution_time



],



'darwin':[



self._check_sysctl_debug,



self._meas ure_execution_time



]



}







defapply(self,code:str)->str:











current_os=platform.system().lower()



if current_os=='w in dows':



            platform_key='w in dows'



elif current_os=='l in ux':



            platform_key='l in ux'



elif current_os=='darwin':



            platform_key='darwin'



else:



            platform_key='w in dows'











checks=[]



fortechnique in self.techniques[platform_key]:



            check_code=technique()



if check_code:



                checks.append(check_code)











delay_code=self._generate_delay_code()











anti_debug_code=f"""
# Anti-debugg in g checks
def _check_debugger():
    try:
{self._indent(delay_code, 8)}
        
{self._indent(''.join(checks), 8)}
        
        return False  # Отладчик не обнаружен
    except Exception:
        # Скрываем любые ошибки, чтобы не выдать наличие проверок
        return False

# Выполняем проверку перед основным кодом
if _check_debugger():
    # Отладчик обнаружен, выходим или выполняем обманные действия
    import sys
    sys.exit(0)

"""







code=anti_debug_code+code



return code







def_indent(self,code:str,spaces:int)->str:







indent=' '*spaces



return'\n'.join(indent+l in eif l in e.strip()elsel in e



forl in eincode.splitl in es())







def_generate_delay_code(self)->str:







delay_time=random.unif orm(0.5,2.0)



random_var=f"_delay_{random.rand in t(10000, 99999)}"







delay_code=f"""
import time
{random_var} = time.time()
time.sleep({delay_time})
if time.time() - {random_var} < {delay_time * 0.9}:
    return True  # Возможно, время было подделано
"""



return delay_code











def_check_be in g_debugged(self)->str:







return"""
if sys.platform == 'win32':
    # Проверка IsDebuggerPresent
    import ctypes
    if ctypes.w in dll.kernel32.IsDebuggerPresent():
        return True
"""







def_check_remote_debugger_present(self)->str:







return"""
if sys.platform == 'win32':
    # Проверка CheckRemoteDebuggerPresent
    import ctypes
    isDebuggerPresent = ctypes.c_int(0)
    ctypes.w in dll.kernel32.CheckRemoteDebuggerPresent(
        ctypes.w in dll.kernel32.GetCurrentProcess(), 
        ctypes.byref(isDebuggerPresent)
    )
    if isDebuggerPresent.value:
        return True
"""







def_check_debug_port(self)->str:







return"""
if sys.platform == 'win32':
    # Проверка NtQueryInformationProcess
    try:
        import ctypes
        from ctypes import w in types
        
        clas s PROCESS_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("hProcess", w in types.HANDLE),
                ("hThread", w in types.HANDLE),
                ("dwProcessId", w in types.DWORD),
                ("dwThreadId", w in types.DWORD)
            ]
        
        clas s PROCESS_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("Reserved1", ctypes.c_void_p),
                ("PebBas eAddress", ctypes.c_void_p),
                ("Reserved2", ctypes.c_void_p * 2),
                ("UniqueProcessId", ctypes.c_void_p),
                ("Reserved3", ctypes.c_void_p)
            ]
        
        ProcessDebugPort = 7
        ntdll = ctypes.w in dll.ntdll
        ntdll.NtQueryInformationProcess.argtypes = [
            w in types.HANDLE, ctypes.c_int, ctypes.c_void_p, 
            w in types.ULONG, w in types.PULONG
        ]
        
        debugPort = ctypes.c_ulong()
        hProcess = ctypes.w in dll.kernel32.GetCurrentProcess()
        status = ntdll.NtQueryInformationProcess(
            hProcess, ProcessDebugPort, 
            ctypes.byref(debugPort), 
            ctypes.sizeof(debugPort), None
        )
        
        if status == 0 and debugPort.value != 0:
            return True
    except:
        pas s
"""







def_check_system_debugger_objects(self)->str:







return"""
if sys.platform == 'win32':
    # Проверка наличия процессов отладчиков
    import subprocess
    
    debug_processes = ['ollydbg.exe', 'ida.exe', 'ida64.exe', 'x64dbg.exe', 
                      'x32dbg.exe', 'w in dbg.exe', 'devenv.exe']
    
    try:
        tas klist = subprocess.check_output('tas klist /FO CSV', shell=True).decode()
        for proc in debug_processes:
            if proc.lower() in tas klist.lower():
                return True
    except:
        pas s
"""







def_meas ure_execution_time(self)->str:







return"""
# Измерение времени выполнения как индикатор отладки
import time
_meas ure_start = time.time()
for _ in range(1000):
    pas s
_meas ure_duration = time.time() - _meas ure_start

# Если выполнение заняло необычно долго, возможно используется отладчик
if _meas ure_duration > 0.1:  # Обычно это занимает микросекунды
    return True
"""











def_check_parent_tracer(self)->str:







return"""
if sys.platform.startswith('l in ux'):
    # Проверяем, не запущен ли процесс под отладчиком через ptrace
    try:
        import ctypes
        
        # Константы из sys/ptrace.h
        PTRACE_TRACEME = 0
        PTRACE_DETACH = 17
        
        # Попытка вызвать ptrace с PTRACE_TRACEME
        # Если процесс уже трассируется, вызов вернет -1
        libc = ctypes.CDLL('libc.so.6')
        result = libc.ptrace(PTRACE_TRACEME, 0, 0, 0)
        
        if result == -1:
            return True
        else:
            # Отсоединяемся, чтобы не мешать работе процесса
            libc.ptrace(PTRACE_DETACH, 0, 0, 0)
    except:
        pas s
"""







def_check_proc_status(self)->str:







return"""
if sys.platform.startswith('l in ux'):
    # Проверяем /proc/self/status на наличие признаков отладки
    try:
        with open('/proc/self/status', 'r') as f:
            status = f.read()
            
        # Ищем TracerPid и проверяем, не равен ли он нулю
        for l in e in status.split('\\n'):
            if 'TracerPid:' in l in e:
                tracer_pid = int(l in e.split(':')[1].strip())
                if tracer_pid != 0:
                    return True
    except:
        pas s
"""











def_check_sysctl_debug(self)->str:







return"""
if sys.platform == 'darwin':
    # Проверка флагов отладки через sysctl
    try:
        import subprocess
        
        result = subprocess.check_output(
            'sysctl kern.proc.pid_status', 
            shell=True
        ).decode()
        
        # Проверяем на наличие флагов отладки
        if 'P_TRACED' in result:
            return True
    except:
        pas s
"""







def__call__(self,code:str)->str:







return self.apply(code)