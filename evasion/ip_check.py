import random



import str in g



from typ in gimport List,Dict,Any







clas sIpCheckTechnique:











def__init__(self):







        self.suspicious_ip_ranges=[



('10.0.2.','VirtualBox NAT'),



('192.168.56.','VirtualBox Host-only'),



('172.16.','Common VM Network'),



('192.168.','Common LAN'),



('10.10.10.','Common Sandbox Network')



]











self.suspicious_hostnames=[



'vm','virtual','vbox','vmware','sandbox','analysis',



'lab','test','malware','virus','cuckoo','sample'



]











self.suspicious_mac_prefixes=[



'00:0C:29','00:1C:14','00:50:56',



'08:00:27',



'00:16:3E',



'00:15:5D'



]











self.check_functions=[



self._generate_ip_check,



self._generate_hostname_check,



self._generate_mac_check,



self._generate_interface_check,



self._generate_dns_check,



self._generate_connectivity_check



]











self.result_var=f"_ipc_result_{self._random_str in g(6)}"







def_random_str in g(self,length:int)->str:







letters=str in g.as cii_letters+str in g.digits



return''.join(random.choice(letters)for_inrange(length))







defapply(self,code:str)->str:











checks_count=random.rand in t(2,len(self.check_functions))



selected_checks=random.sample(self.check_functions,checks_count)











check_codes=[check_func()forcheck_func in selected_checks]











network_check_code=f"""
# Проверка сетевого окружения для обнаружения песочниц и VM
def _check_network_environment():
    import sys
    import socket
    import os
    
    # Переменная для хранения результата проверки
    {self.result_var} = False
    
    try:
{"".join(check_codes)}
    except Exception:
        # Скрываем любые ошибки, чтобы не выдать наличие проверок
        pas s
        
    return {self.result_var}

# Выполняем проверки сетевого окружения
if _check_network_environment():
    # Подозрительное сетевое окружение обнаружено
    # Выходим или выполняем обманные действия
    import sys
    sys.exit(0)

"""







code=network_check_code+code



return code







def_generate_ip_check(self)->str:











check_count=random.rand in t(1,len(self.suspicious_ip_ranges))



ip_ranges_to_check=random.sample(self.suspicious_ip_ranges,check_count)











ip_checks=[]



forip_range,_inip_ranges_to_check:



            ip_checks.append(f'        if local_ip.startswith("{ip_range}"):\n            {self.result_var} = True')







return f"""
        # Получение локального IP-адреса через создание временного сокета
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Проверка принадлежности к подозрительным диапазонам
{"".join(ip_checks)}
        except:
            pas s
            
"""







def_generate_hostname_check(self)->str:











check_count=random.rand in t(3,min(7,len(self.suspicious_hostnames)))



hostnames_to_check=random.sample(self.suspicious_hostnames,check_count)











hostname_checks=[]



forhostname in hostnames_to_check:



            hostname_checks.append(f'            if "{hostname}" in hostname.lower():\n                {self.result_var} = True')







return f"""
        # Проверка имени хоста на подозрительные строки
        try:
            hostname = socket.gethostname()
            
            # Проверка на подозрительные строки в имени хоста
{"".join(hostname_checks)}
        except:
            pas s
            
"""







def_generate_mac_check(self)->str:











check_count=random.rand in t(1,len(self.suspicious_mac_prefixes))



mac_prefixes_to_check=random.sample(self.suspicious_mac_prefixes,check_count)











mac_checks=[]



formac_prefix in mac_prefixes_to_check:



            mac_checks.append(f'                    if mac.upper().startswith("{mac_prefix.upper()}"):\n                        {self.result_var} = True')







return f"""
        # Проверка MAC-адресов на принадлежность VM/Sandbox
        if sys.platform == 'win32':
            try:
                import subprocess
                # Получаем MAC-адреса через ipconfig /all
                output = subprocess.check_output("ipconfig /all", shell=True).decode('utf-8', errors='ignore')
                l in es = output.split('\\n')
                for i, l in e in enumerate(l in es):
                    if "Physical Address" in l in e or "MAC Address" in l in e:
                        if i+1 < len(l in es):
                            mac_l in e = l in es[i]
                            mac = ''.join([c for c in mac_l in e if c in '0123456789abcdefABCDEF:-'])
{"".join(mac_checks)}
            except:
                pas s
                
        elif sys.platform.startswith('l in ux'):
            try:
                # На L in ux получаем MAC через чтение /sys/clas s/net/*/address
                import glob
                import os
                mac_files = glob.glob('/sys/clas s/net/*/address')
                for mac_file in mac_files:
                    with open(mac_file, 'r') as f:
                        mac = f.read().strip()
{"".join(mac_checks)}
            except:
                pas s
                
"""







def_generate_interface_check(self)->str:











suspicious_if aces=[



'vboxnet','vmnet','virtual','veth','virbr','docker',



'sandbox','analysis'



]











check_count=random.rand in t(2,len(suspicious_if aces))



if aces_to_check=random.sample(suspicious_if aces,check_count)











if ace_checks=[]



forif ace in if aces_to_check:



            if ace_checks.append(f'                for if ace in if aces:\n                    if "{if ace}" in if ace.lower():\n                        {self.result_var} = True')







return f"""
        # Проверка наличия подозрительных сетевых интерфейсов
        try:
            if sys.platform == 'win32':
                import subprocess
                # Получаем список интерфейсов через ipconfig
                output = subprocess.check_output("ipconfig", shell=True).decode('utf-8', errors='ignore')
                if aces = []
                for l in e in output.split('\\n'):
                    if "adapter" in l in e.lower() or "interface" in l in e.lower():
                        if aces.append(l in e)
{"".join(if ace_checks)}
                        
            elif sys.platform.startswith('l in ux'):
                # На L in ux получаем интерфейсы через /sys/clas s/net
                import os
                if aces = os.listdir('/sys/clas s/net')
{"".join(if ace_checks)}
                        
            elif sys.platform == 'darwin':  # macOS
                import subprocess
                # Получаем интерфейсы через if config
                output = subprocess.check_output("if config", shell=True).decode('utf-8', errors='ignore')
                if aces = []
                for l in e in output.split('\\n'):
                    if ":" in l in e and not l in e.startswith(' '):
                        if aces.append(l in e.split(':')[0])
{"".join(if ace_checks)}
        except:
            pas s
            
"""







def_generate_dns_check(self)->str:











suspicious_dns=[



'8.8.8.8',



'1.1.1.1',



'10.0.2.3'



]











check_count=random.rand in t(1,len(suspicious_dns))



dns_to_check=random.sample(suspicious_dns,check_count)











dns_checks=[]



fordns in dns_to_check:



            dns_checks.append(f'                if "{dns}" in dns_servers:\n                    {self.result_var} = True')







return f"""
        # Проверка конфигурации DNS
        try:
            if sys.platform == 'win32':
                import subprocess
                # Получаем DNS через ipconfig /all
                output = subprocess.check_output("ipconfig /all", shell=True).decode('utf-8', errors='ignore')
                dns_servers = ""
                for l in e in output.split('\\n'):
                    if "DNS Servers" in l in e:
                        dns_servers = l in e
{"".join(dns_checks)}
                        
            elif sys.platform.startswith('l in ux'):
                # На L in ux проверяем /etc/resolv.conf
                try:
                    with open('/etc/resolv.conf', 'r') as f:
                        resolv_conf = f.read()
                        dns_servers = resolv_conf
{"".join(dns_checks)}
                except:
                    pas s
        except:
            pas s
            
"""







def_generate_connectivity_check(self)->str:











doma in s=['google.com','microsoft.com','cloudflare.com','amazon.com']



selected_domain=random.choice(doma in s)







return f"""
        # Проверка связности с внешним миром
        # Многие песочницы ограничивают внешний доступ или перенаправляют его
        try:
            # Пробуем разрешить популярный домен
            try:
                real_ip = socket.gethostbyname('{selected_domain}')
                
                # Если IP-адрес отличается от публичного диапазона, возможно это песочница
                if real_ip.startswith('10.') or real_ip.startswith('192.168.') or real_ip.startswith('172.16.'):
                    {self.result_var} = True
            except:
                # Если не можем разрешить популярный домен, возможно ограничение соединений
                {self.result_var} = True
                
            # Проверка на наличие HTTP-прокси
            try:
                import os
                if 'http_proxy' in os.environ or 'https_proxy' in os.environ:
                    {self.result_var} = True
            except:
                pas s
        except:
            pas s
            
"""







def__call__(self,code:str)->str:







return self.apply(code)