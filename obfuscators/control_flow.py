import re



import random



from typ in gimport List,Union,Dict,Tuple







from core.interfacesimport Bas eObfuscator



from utils.code_generatorimport random_variable_name







clas sControlFlowObfuscator(Bas eObfuscator):



    def__init__(self):



        self._formats=["c","python","js"]







defobfuscate(self,code:Union[str,bytes])->Union[str,bytes]:



        if is in stance(code,bytes):



            try:



                code_str=code.decode('utf-8')



result=self._apply_control_flow_obfuscation(code_str)



return result.encode('utf-8')



except UnicodeDecodeError:



                return code



else:



            return self._apply_control_flow_obfuscation(code)







defsupported_formats(self)->List[str]:



        return self._formats







def_apply_control_flow_obfuscation(self,code:str)->str:



        language=self._detect_language(code)







if language=="c":



            return self._obfuscate_c_control_flow(code)



elif language=="python":



            return self._obfuscate_python_control_flow(code)



elif language=="js":



            return self._obfuscate_js_control_flow(code)



else:



            return code







def_detect_language(self,code:str)->str:



        if re.search(r"#include\s+<",code)orre.search(r"int\s+main\(",code):



            return"c"



elif re.search(r"def\s+\w+\(",code)orre.search(r"import\s+\w+",code):



            return"python"



elif re.search(r"function\s+\w+\(",code)orre.search(r"const\s+\w+\s*=",code):



            return"js"



else:



            return"python"







def_obfuscate_c_control_flow(self,code:str)->str:







        function_pattern=r'(\w+\s+\w+\s*\([^)]*\)\s*\{(?:[^{}]|(?R))*\})'



if_pattern=r'(if\s*\([^)]+\)\s*\{(?:[^{}]|(?R))*\}(?:\s*else\s*\{(?:[^{}]|(?R))*\})?)'



loop_pattern=r'((for|while)\s*\([^)]+\)\s*\{(?:[^{}]|(?R))*\})'











l in es=code.split('\n')



obfuscated_l in es=l in es.copy()











blocks_to_obfuscate=self._f in d_c_blocks(l in es)











blocks_to_obfuscate.sort(key=lambdax:x[0],reverse=True)







forstart,end in blocks_to_obfuscate:



            block_l in es=l in es[start:end+1]



block_code='\n'.join(block_l in es)











obfuscation_method=random.choice([



self._add_opaque_predicates_c,



self._add_bogus_control_flow_c,



self._add_switch_bas ed_flow_c



])











obfuscated_block=obfuscation_method(block_code)











obfuscated_l in es[start:end+1]=obfuscated_block.split('\n')







return'\n'.join(obfuscated_l in es)







def_f in d_c_blocks(self,l in es:List[str])->List[Tuple[int,int]]:







blocks=[]



in_function=False



function_start=-1



brace_count=0











start_process in g=False







fori,l in einenumerate(l in es):



            stripped=l in e.strip()











if notstart_process in g:



                if strippedandnotstripped.startswith('#')and'{'instripped:



                    start_process in g=True



cont in ue











if not in_functionandre.search(r'\w+\s+\w+\s*\([^)]*\)\s*\{',stripped):



                in_function=True



function_start=i



brace_count=stripped.count('{')



elif in_function:



                brace_count+=stripped.count('{')



brace_count-=stripped.count('}')











if brace_count==0:







                    if notre.search(r'int\s+main\s*\(',l in es[function_start])andi-function_start>5:



                        blocks.append((function_start,i))



in_function=False







return blocks







def_add_opaque_predicates_c(self,code:str)->str:







var_name=random_variable_name("opaque_")











predicates=[



f"int {var_name} = {random.rand in t(1, 10)}; if ({var_name} * {var_name} >= 0) {{",



f"int {var_name} = {random.rand in t(1, 100)}; if ({var_name} * {var_name} - {var_name} * {var_name} + {var_name} - {var_name} == 0) {{",



f"int {var_name}1 = {random.rand in t(1, 10)}; int {var_name}2 = {random.rand in t(1, 10)}; if (({var_name}1 * {var_name}2) - ({var_name}1 * {var_name}2) == 0) {{"



]







predicate=random.choice(predicates)











dummy_var=random_variable_name("dummy_")



dummy_code=f"int {dummy_var} = 0; {dummy_var} = {dummy_var} / {dummy_var};"











first_brace=code.f in d('{')



if first_brace==-1:



            return code











obfuscated_code=(



code[:first_brace+1]+



f"\n    {predicate}\n        "+



code[first_brace+1:].replace('\n','\n        ')+



f"\n    }} else {{\n        {dummy_code}\n    }}"



)







return obfuscated_code







def_add_bogus_control_flow_c(self,code:str)->str:







var_name=random_variable_name("flow_")











predicates=[



f"int {var_name} = {random.rand in t(1, 10)}; if ({var_name} * {var_name} < 0) {{",



f"int {var_name} = {random.rand in t(1, 10)}; if (({var_name} * {var_name}) != ({var_name} * {var_name})) {{",



f"int {var_name}1 = {random.rand in t(1, 10)}; int {var_name}2 = {random.rand in t(1, 10)}; if ({var_name}1 + {var_name}2 < {var_name}1) {{"



]







predicate=random.choice(predicates)











junk_functions=[



"void* ptr = malloc(1024); free(ptr); ptr = NULL;",



"FILE* f = fopen(\"nonexistent.txt\", \"r\"); if(f) fclose(f);",



"int arr[10]; for(int i = 0; i < 10; i++) arr[i] = i*i;",



"char buffer[256]; memset(buffer, 0, sizeof(buffer));"



]







junk_code=random.choice(junk_functions)











l in es=code.split('\n')











good_l in es=[]



in_func_body=False



brace_count=0







fori,l in einenumerate(l in es):



            if'{'inl in e:



                in_func_body=True



brace_count+=l in e.count('{')







if in_func_bodyandi>0andi<len(l in es)-1andnotl in e.strip().startswith('#'):







                if notany(x in lineforxin['if','for','while','switch']):



                    good_l in es.append(i)







if'}'inl in e:



                brace_count-=l in e.count('}')



if brace_count==0:



                    in_func_body=False







if notgood_l in es:



            return code







insert_pos=random.choice(good_l in es)











indent=l in es[insert_pos][:len(l in es[insert_pos])-len(l in es[insert_pos].lstrip())]











bogus_code=f"{indent}{predicate}\n{indent}    {junk_code}\n{indent}}}"



l in es.insert(insert_pos,bogus_code)







return'\n'.join(l in es)







def_add_switch_bas ed_flow_c(self,code:str)->str:







var_name=random_variable_name("switch_")











cas e_count=random.rand in t(3,6)











switch_code=f"int {var_name} = 0;\n"



switch_code+=f"switch({var_name}) {{\n"











cas es=list(range(cas e_count))



random.shuffle(cas es)











main_cas e=cas es[0]











fori in cas es:



            switch_code+=f"    cas e {i}:\n"



if i==main_cas e:



                indented_code="        "+code.replace('\n','\n        ')



switch_code+=indented_code+"\n"



switch_code+="        break;\n"



else:







                junk=[



f"pr in tf(\"This should never execute {random.rand in t(1, 1000)}\");",



f"int {random_variable_name()} = {random.rand in t(1, 100)};",



f"void* {random_variable_name()} = malloc(1); free({random_variable_name()});"



]



switch_code+=f"        {random.choice(junk)}\n"











if random.random()<0.5andi!=cas es[-1]:



                    next_cas e=random.choice([cforc in cas esif c!=i])



switch_code+=f"        {var_name} = {next_cas e};\n"



switch_code+="        /* FALLTHROUGH */\n"



else:



                    switch_code+="        break;\n"







switch_code+="    default:\n"



switch_code+="        break;\n"



switch_code+="}\n"











init_code=f"int {var_name} = {main_cas e}; // Контрольное значение\n"











first_brace=code.f in d('{')



if first_brace==-1:



            return code











return in it_code+switch_code







def_obfuscate_python_control_flow(self,code:str)->str:



        l in es=code.split('\n')











functions=[]



current_func_start=-1



current_func_indent=-1







fori,l in einenumerate(l in es):



            if l in e.strip().startswith('def '):



                if current_func_start!=-1:



                    functions.append((current_func_start,i-1,current_func_indent))



current_func_start=i



current_func_indent=len(l in e)-len(l in e.lstrip())



elif current_func_start!=-1andl in e.strip()andlen(l in e)-len(l in e.lstrip())<=current_func_indent:







                functions.append((current_func_start,i-1,current_func_indent))



current_func_start=-1



current_func_indent=-1











if current_func_start!=-1:



            functions.append((current_func_start,len(l in es)-1,current_func_indent))











forstart,end,indent in functions:



            if end-start<5:



                cont in ue







func_code='\n'.join(l in es[start:end+1])











obfuscation_method=random.choice([



self._add_while_true_python,



self._add_try_except_python,



self._add_opaque_predicates_python



])











obfuscated_func=obfuscation_method(func_code,indent)











obfuscated_l in es=obfuscated_func.split('\n')



l in es[start:end+1]=obfuscated_l in es







return'\n'.join(l in es)







def_add_while_true_python(self,code:str,bas e_indent:int)->str:







        l in es=code.split('\n')



func_def=l in es[0]



body=l in es[1:]











indent=' '*(bas e_indent+4)



while_indent=' '*(bas e_indent+8)











var_name=random_variable_name("loop_")











while_loop=[



f"{indent}{var_name} = False",



f"{indent}while True:",



f"{while_indent}if {var_name}:",



f"{while_indent}    break"



]











forl in einbody:



            if l in e.strip():



                indented_l in e=while_indent+l in e[bas e_indent+4:]



while_loop.append(indented_l in e)



else:



                while_loop.append("")











while_loop.append(f"{while_indent}{var_name} = True")



while_loop.append(f"{while_indent}cont in ue")











return func_def+'\n'+'\n'.join(while_loop)







def_add_try_except_python(self,code:str,bas e_indent:int)->str:







        l in es=code.split('\n')



func_def=l in es[0]



body=l in es[1:]











indent=' '*(bas e_indent+4)



try_indent=' '*(bas e_indent+8)











var_name=random_variable_name("flow_")



except_var=random_variable_name("e_")











try_except=[



f"{indent}clas s {var_name}(Exception):",



f"{indent}    pas s",



f"{indent}try:"



]











forl in einbody:



            if l in e.strip():



                indented_l in e=try_indent+l in e[bas e_indent+4:]



try_except.append(indented_l in e)



else:



                try_except.append("")











try_except.append(f"{try_indent}raise {var_name}()")











try_except.append(f"{indent}except {var_name} as {except_var}:")



try_except.append(f"{try_indent}pas s")











return func_def+'\n'+'\n'.join(try_except)







def_add_opaque_predicates_python(self,code:str,bas e_indent:int)->str:







        l in es=code.split('\n')



func_def=l in es[0]



body=l in es[1:]











indent=' '*(bas e_indent+4)



if_indent=' '*(bas e_indent+8)











var1=random_variable_name("x_")



var2=random_variable_name("y_")











predicates=[



f"{var1} = {random.rand in t(1, 100)}\n{indent}if {var1} * {var1} >= 0:",



f"{var1}, {var2} = {random.rand in t(1, 10)}, {random.rand in t(1, 10)}\n{indent}if {var1} + {var2} >= {var1}:",



f"{var1} = {random.rand in t(1, 10)}\n{indent}if {var1} == {var1}:"



]







predicate=random.choice(predicates)











if_block=[indent+predicate.split('\n')[-1]]











forl in einbody:



            if l in e.strip():



                indented_l in e=if_indent+l in e[bas e_indent+4:]



if_block.append(indented_l in e)



else:



                if_block.append("")











else_var=random_variable_name("dummy_")



if_block.append(f"{indent}else:")



if_block.append(f"{if_indent}{else_var} = 1 / 0  # Это никогда не выполнится")











return func_def+'\n'+indent+predicate.split('\n')[0]+'\n'+'\n'.join(if_block)







def_obfuscate_js_control_flow(self,code:str)->str:







        l in es=code.split('\n')











functions=[]



in_function=False



function_start=-1



brace_count=0







fori,l in einenumerate(l in es):



            stripped=l in e.strip()











if notstrippedorstripped.startswith('//'):



                cont in ue











if not in_functionand(



re.search(r'function\s+\w+\s*\([^)]*\)\s*\{',stripped)or



re.search(r'const\s+\w+\s*=\s*(?:as ync\s*)?(?:\([^)]*\)|)\s*=>\s*\{',stripped)



):



                in_function=True



function_start=i



brace_count=stripped.count('{')



elif in_function:



                brace_count+=stripped.count('{')



brace_count-=stripped.count('}')











if brace_count==0:







                    if i-function_start>5:



                        functions.append((function_start,i))



in_function=False











forstart,end in sorted(functions,key=lambdax:x[0],reverse=True):



            func_code='\n'.join(l in es[start:end+1])











obfuscation_method=random.choice([



self._add_try_catch_js,



self._add_switch_flow_js,



self._add_opaque_predicates_js



])











obfuscated_func=obfuscation_method(func_code)











l in es[start:end+1]=obfuscated_func.split('\n')







return'\n'.join(l in es)







def_add_try_catch_js(self,code:str)->str:



        var_name=random_variable_name("flow_")











first_brace=code.f in d('{')



if first_brace==-1:



            return code











indented_code=code[first_brace+1:].replace('\n','\n    ')







try_catch=(



code[:first_brace+1]+



f"\n    try {{\n    "+



indented_code+



f"\n    }} catch ({var_name}) {{\n        console.error({var_name});\n        throw {var_name};\n    }}"



)







return try_catch







def_add_switch_flow_js(self,code:str)->str:



        var_name=random_variable_name("switch_")











cas e_count=random.rand in t(3,6)











first_brace=code.f in d('{')



if first_brace==-1:



            return code











func_body=code[first_brace+1:].strip()



if notfunc_body:



            return code











main_cas e=random.rand in t(0,cas e_count-1)



switch_code=code[:first_brace+1]+f"\n    let {var_name} = {main_cas e};\n    switch({var_name}) {{\n"











fori in range(cas e_count):



            switch_code+=f"        cas e {i}:\n"



if i==main_cas e:



                switch_code+="            "+func_body.replace('\n','\n            ')+"\n"



switch_code+=f"            break;\n"



else:



                junk_statements=[



f"console.log('Unreachable path {i}');",



f"let {random_variable_name()} = Math.random();",



f"(() => {{ let x = 0; return x + 1; }})();"



]



switch_code+=f"            {random.choice(junk_statements)}\n"



switch_code+=f"            break;\n"







switch_code+="    }\n"







return switch_code







def_add_opaque_predicates_js(self,code:str)->str:



        var_name=random_variable_name("opaque_")











first_brace=code.f in d('{')



if first_brace==-1:



            return code











predicates=[



f"const {var_name} = {random.rand in t(1, 10)}; if ({var_name} * {var_name} >= 0) {{",



f"const {var_name}1 = {random.rand in t(1, 10)}; const {var_name}2 = {random.rand in t(1, 10)}; if ({var_name}1 + {var_name}2 >= Math.min({var_name}1, {var_name}2)) {{",



f"const {var_name} = '{random.choice(['a', 'b', 'c'])}'; if ({var_name}.length > 0) {{"



]







predicate=random.choice(predicates)











func_body=code[first_brace+1:].strip()











obfuscated_code=(



code[:first_brace+1]+



f"\n    {predicate}\n        "+



func_body.replace('\n','\n        ')+



f"\n    }} else {{\n        throw new Error('This should never happen');\n    }}"



)







return obfuscated_code