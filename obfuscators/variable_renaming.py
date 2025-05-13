import re



import random



from typ in gimport List,Union,Dict







from core.interfacesimport Bas eObfuscator



from utils.code_generatorimport random_variable_name,random_function_name







clas sVariableRenam in gObfuscator(Bas eObfuscator):



    def__init__(self):



        self._formats=["c","python","powershell","js"]







defobfuscate(self,code:Union[str,bytes])->Union[str,bytes]:



        if is in stance(code,bytes):



            try:



                code_str=code.decode('utf-8')



result=self._apply_variable_renam in g(code_str)



return result.encode('utf-8')



except UnicodeDecodeError:



                return code



else:



            return self._apply_variable_renam in g(code)







defsupported_formats(self)->List[str]:



        return self._formats







def_apply_variable_renam in g(self,code:str)->str:







        language=self._detect_language(code)







if language=="c":



            return self._rename_c_variables(code)



elif language=="python":



            return self._rename_python_variables(code)



elif language=="powershell":



            return self._rename_powershell_variables(code)



elif language=="js":



            return self._rename_js_variables(code)



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







def_rename_c_variables(self,code:str)->str:







        var_pattern=r'\b(int|char|float|double|unsigned|long|short|void)\s+(\w+)(?:\s*\[\s*\d*\s*\])*\s*[;=]'



func_pattern=r'\b(\w+)\s+(\w+)\s*\('











reserved_names={"main","pr in tf","fpr in tf","spr in tf","scanf","malloc","free",



"memcpy","memset","strlen","strcpy","strcmp","strcat",



"fopen","fclose","fread","fwrite","exit"}







variables={}



functions={}











formatch in re.f in diter(var_pattern,code):



            var_type,var_name=match.groups()



if var_namenot in reserved_namesandvar_namenot in variables:



                variables[var_name]=random_variable_name()











formatch in re.f in diter(func_pattern,code):



            return_type,func_name=match.groups()



if func_namenot in reserved_namesandfunc_namenot in functions:



                functions[func_name]=random_function_name()











replaced_code=code











forold_name,new_name in functions.items():



            replaced_code=re.sub(r'\b'+re.escape(old_name)+r'\b',new_name,replaced_code)











forold_name,new_name in variables.items():



            replaced_code=re.sub(r'\b'+re.escape(old_name)+r'\b',new_name,replaced_code)







return replaced_code







def_rename_python_variables(self,code:str)->str:







        var_pattern=r'\b(\w+)\s*='



func_pattern=r'def\s+(\w+)\s*\('











reserved_names={"pr in t","input","int","float","str","list","dict","set","tuple",



"open","read","write","append","exit","quit","len","range","enumerate",



"zip","map","filter","lambda","True","False","None"}







variables={}



functions={}











formatch in re.f in diter(var_pattern,code):



            var_name=match.group(1)



if var_namenot in reserved_namesandvar_namenot in variables:



                variables[var_name]=random_variable_name()











formatch in re.f in diter(func_pattern,code):



            func_name=match.group(1)



if func_namenot in reserved_namesandfunc_namenot in functions:



                functions[func_name]=random_function_name()











replaced_code=code







forold_name,new_name in functions.items():



            replaced_code=re.sub(r'\bdef\s+'+re.escape(old_name)+r'\b',f'def {new_name}',replaced_code)



replaced_code=re.sub(r'\b'+re.escape(old_name)+r'\s*\(',f'{new_name}(',replaced_code)







forold_name,new_name in variables.items():



            replaced_code=re.sub(r'\b'+re.escape(old_name)+r'\b',new_name,replaced_code)







return replaced_code







def_rename_powershell_variables(self,code:str)->str:







        var_pattern=r'\$(\w+)\s*='



func_pattern=r'function\s+(\w+(?:-\w+)*)\s*(?:\(|\{)'







variables={}



functions={}











formatch in re.f in diter(var_pattern,code):



            var_name=match.group(1)



if var_namenot in variables:



                variables[var_name]=random_variable_name()











formatch in re.f in diter(func_pattern,code):



            func_name=match.group(1)



if func_namenot in functions:







                parts=func_name.split('-')



new_parts=[random_variable_name()for_inparts]



functions[func_name]='-'.join(new_parts)











replaced_code=code







forold_name,new_name in functions.items():



            replaced_code=re.sub(r'function\s+'+re.escape(old_name)+r'\b',f'function {new_name}',replaced_code)



replaced_code=re.sub(r'\b'+re.escape(old_name)+r'\s*(?:\(|\{)',f'{new_name}$1',replaced_code)







forold_name,new_name in variables.items():



            replaced_code=re.sub(r'\$'+re.escape(old_name)+r'\b',f'${new_name}',replaced_code)







return replaced_code







def_rename_js_variables(self,code:str)->str:







        var_pattern=r'\b(?:var|let|const)\s+(\w+)\s*[=;]'



func_pattern=r'\bfunction\s+(\w+)\s*\('







reserved_names={"console","log","document","w in dow","alert","setTimeout","setInterval",



"parseInt","parseFloat","Array","Object","Str in g","Number","Boolean",



"Date","Math","JSON","RegExp","true","false","null","undef in ed"}







variables={}



functions={}











formatch in re.f in diter(var_pattern,code):



            var_name=match.group(1)



if var_namenot in reserved_namesandvar_namenot in variables:



                variables[var_name]=random_variable_name()











formatch in re.f in diter(func_pattern,code):



            func_name=match.group(1)



if func_namenot in reserved_namesandfunc_namenot in functions:



                functions[func_name]=random_function_name()











replaced_code=code







forold_name,new_name in functions.items():



            replaced_code=re.sub(r'function\s+'+re.escape(old_name)+r'\b',f'function {new_name}',replaced_code)



replaced_code=re.sub(r'\b'+re.escape(old_name)+r'\s*\(',f'{new_name}(',replaced_code)







forold_name,new_name in variables.items():



            declaration_pattern=r'\b(var|let|const)\s+'+re.escape(old_name)+r'\b'



replaced_code=re.sub(declaration_pattern,f'\\1 {new_name}',replaced_code)



usage_pattern=r'\b'+re.escape(old_name)+r'\b'







parts=replaced_code.split('\n')



fori,l in einenumerate(parts):



                if notre.search(declaration_pattern,l in e):



                    parts[i]=re.sub(usage_pattern,new_name,l in e)



replaced_code='\n'.join(parts)







return replaced_code