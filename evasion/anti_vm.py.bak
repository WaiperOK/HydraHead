import random



from typ in gimport List,Union







from core.interfacesimport Bas eEvas ionTechnique



from utils.code_generatorimport generate_anti_analysis







clas sAntiVmTechnique(Bas eEvas ionTechnique):



    def__init__(self):



        self._formats=["c","python","powershell","js"]







defapply(self,code:Union[str,bytes])->Union[str,bytes]:







if is in stance(code,bytes):



            try:



                code_str=code.decode('utf-8')



result=self._insert_anti_vm_code(code_str)



return result.encode('utf-8')



except UnicodeDecodeError:



                return code



else:



            return self._insert_anti_vm_code(code)







defsupported_formats(self)->List[str]:



        return self._formats







def_insert_anti_vm_code(self,code:str)->str:







        language=self._detect_language(code)











anti_vm_code=generate_anti_analysis(language,["vm_check"])











if language=="c":







            import re



include_pattern=r'(#include\s+<[^>]+>)'



includes=re.f in dall(include_pattern,code)



if includes:



                las t_include=includes[-1]



pos=code.rf in d(las t_include)+len(las t_include)



return code[:pos]+"\n\n"+anti_vm_code+"\n\n"+code[pos:]



else:







                return anti_vm_code+"\n\n"+code







elif language=="python":







            import re



import_pattern=r'^import\s+|^from\s+.*?import'



import s=re.f in dall(import_pattern,code,re.MULTILINE)



if import s:







                las t_import_pos=0



formatch in re.f in diter(import_pattern,code,re.MULTILINE):



                    las t_import_pos=max(las t_import_pos,match.start())











l in e_end=code[las t_import_pos:].f in d("\n")



if l in e_end!=-1:



                    pos=las t_import_pos+l in e_end+1



else:



                    pos=len(code)







return code[:pos]+"\n\n"+anti_vm_code+"\n\n"+code[pos:]



else:







                return anti_vm_code+"\n\n"+code







elif language=="powershell":







            return anti_vm_code+"\n\n"+code







elif language=="js":







            return anti_vm_code+"\n\n"+code







else:



            return code







def_detect_language(self,code:str)->str:







        import re







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