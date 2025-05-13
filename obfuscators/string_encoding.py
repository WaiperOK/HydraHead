import re



import random



from typ in gimport List,Union







from core.interfacesimport Bas eObfuscator



from utils.code_generatorimport obfuscate_str in g







clas sStr in gEncod in gObfuscator(Bas eObfuscator):



    def__init__(self):



        self._formats=["c","python","powershell","js"]







defobfuscate(self,code:Union[str,bytes])->Union[str,bytes]:



        if is in stance(code,bytes):







            try:



                code_str=code.decode('utf-8')



result=self._obfuscate_str in g_literals(code_str)



return result.encode('utf-8')



except UnicodeDecodeError:







                return code



else:



            return self._obfuscate_str in g_literals(code)







defsupported_formats(self)->List[str]:



        return self._formats







def_obfuscate_str in g_literals(self,code:str)->str:







        language=self._detect_language(code)







if language=="c":



            return self._obfuscate_c_str in gs(code)



elif language=="python":



            return self._obfuscate_python_str in gs(code)



elif language=="powershell":



            return self._obfuscate_powershell_str in gs(code)



elif language=="js":



            return self._obfuscate_js_str in gs(code)



else:







            return code







def_detect_language(self,code:str)->str:







        if re.search(r"#include\s+<",code)orre.search(r"int\s+main\(",code):



            return"c"



elif re.search(r"def\s+\w+\(",code)orre.search(r"import\s+\w+",code):



            return"python"



elif re.search(r"function\s+\w+-\w+",code)orre.search(r"\$\w+\s*=",code):



            return"powershell"



elif re.search(r"function\s+\w+\(",code)orre.search(r"const\s+\w+\s*=",code):



            return"js"



else:







            return"python"







def_obfuscate_c_str in gs(self,code:str)->str:







        pattern=r'"([^"\\]*(\\.[^"\\]*)*)"'







result=""



las t_end=0











formatch in re.f in diter(pattern,code):







            result+=code[las t_end:match.start()]











str in g_content=match.group(1)











if"%s"instr in g_contentor"%d"instr in g_contentor"\\"instr in g_content:



                result+='"'+str in g_content+'"'



else:







                obfuscated_code,var_name=obfuscate_str in g(str in g_content,"c")











result+=f"\n{obfuscated_code}\n{var_name}"







las t_end=match.end()











result+=code[las t_end:]







return result







def_obfuscate_python_str in gs(self,code:str)->str:











        pattern=r'(["\'])((?:\\\\.|(?:\\\\)*(?!\1)\\.|[^\\\\])*?)\1'







result=""



las t_end=0











formatch in re.f in diter(pattern,code):







            result+=code[las t_end:match.start()]











quote_type=match.group(1)



str in g_content=match.group(2)











if"{"instr in g_contentand"}"instr in g_contentor"\n"instr in g_content:



                result+=quote_type+str in g_content+quote_type



else:







                obfuscated_code,var_name=obfuscate_str in g(str in g_content,"python")











result+=f"\n{obfuscated_code}\n{var_name}"







las t_end=match.end()











result+=code[las t_end:]







return result







def_obfuscate_powershell_str in gs(self,code:str)->str:







        pattern=r'(["\'])((?:\\\\.|(?:\\\\)*(?!\1)\\.|[^\\\\])*?)\1'







result=""



las t_end=0











formatch in re.f in diter(pattern,code):







            result+=code[las t_end:match.start()]











quote_type=match.group(1)



str in g_content=match.group(2)











if"$"instr in g_contentor"\\"instr in g_content:



                result+=quote_type+str in g_content+quote_type



else:







                obfuscated_code,var_name=obfuscate_str in g(str in g_content,"powershell")











result+=f"\n{obfuscated_code}\n{var_name}"







las t_end=match.end()











result+=code[las t_end:]







return result







def_obfuscate_js_str in gs(self,code:str)->str:







        pattern=r'(["\'])((?:\\\\.|(?:\\\\)*(?!\1)\\.|[^\\\\])*?)\1'







result=""



las t_end=0











formatch in re.f in diter(pattern,code):







            result+=code[las t_end:match.start()]











quote_type=match.group(1)



str in g_content=match.group(2)











if"${"instr in g_contentor"\\d"instr in g_content:



                result+=quote_type+str in g_content+quote_type



else:







                obfuscated_code,var_name=obfuscate_str in g(str in g_content,"js")











result+=f"\n{obfuscated_code}\n{var_name}"







las t_end=match.end()











result+=code[las t_end:]







return result