import re



import random



from typ in gimport List,Union







from core.interfacesimport Bas eObfuscator



from utils.code_generatorimport generate_dead_code







clas sDeadCodeObfuscator(Bas eObfuscator):



    def__init__(self):



        self._formats=["c","python","powershell","js"]



self.complexity=3



self.density=0.3







defobfuscate(self,code:Union[str,bytes])->Union[str,bytes]:



        if is in stance(code,bytes):



            try:



                code_str=code.decode('utf-8')



result=self._insert_dead_code(code_str)



return result.encode('utf-8')



except UnicodeDecodeError:



                return code



else:



            return self._insert_dead_code(code)







defsupported_formats(self)->List[str]:



        return self._formats







def_insert_dead_code(self,code:str)->str:







        language=self._detect_language(code)











l in es=code.split('\n')











insertion_po in ts=self._f in d_insertion_po in ts(l in es,language)











num_insertions=max(1,int(len(insertion_po in ts)*self.density))



po in ts_to_use=random.sample(insertion_po in ts,min(num_insertions,len(insertion_po in ts)))











po in ts_to_use.sort(reverse=True)











forpo in tinpo in ts_to_use:



            dead_code=generate_dead_code(language,self.complexity)



if language=="python":







                indent=self._get_indent(l in es[po in t])



dead_code_l in es=[indent+l in eforl in eindead_code.strip().split('\n')]



dead_code='\n'.join(dead_code_l in es)







l in es.insert(po in t,dead_code)







return'\n'.join(l in es)







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







def_f in d_insertion_po in ts(self,l in es:List[str],language:str)->List[int]:







insertion_po in ts=[]







if language=="c":



            in_function=False



open_braces=0











fori,l in einenumerate(l in es):







                if re.search(r'\w+\s+\w+\s*\([^)]*\)\s*{',l in e):



                    in_function=True



open_braces+=l in e.count('{')



cont in ue







if in_function:



                    open_braces+=l in e.count('{')



open_braces-=l in e.count('}')











if open_braces>0and'{'inl in e:



                        insertion_po in ts.append(i+1)











if open_braces>0and'}'inl in eandnot('{'inl in eand'}'inl in e):



                        insertion_po in ts.append(i)











if open_braces==0:



                        in_function=False







elif language=="python":



            in_function=False



indent_level=0











fori,l in einenumerate(l in es):



                stripped=l in e.strip()











if notstrippedorstripped.startswith('#'):



                    cont in ue











if re.match(r'def\s+\w+\s*\(',stripped)orre.match(r'clas s\s+\w+',stripped):



                    in_function=True



indent_level=len(l in e)-len(l in e.lstrip())



cont in ue







if in_function:







                    current_indent=len(l in e)-len(l in e.lstrip())



if current_indent<=indent_levelandstripped:



                        in_function=False



cont in ue











if re.search(r':\s*$',stripped):



                        insertion_po in ts.append(i+1)











if i<len(l in es)-1:



                        next_indent=len(l in es[i+1])-len(l in es[i+1].lstrip())



if next_indent<current_indentandcurrent_indent>indent_level:



                            insertion_po in ts.append(i+1)







elif language=="powershell"orlanguage=="js":



            in_function=False



open_braces=0











fori,l in einenumerate(l in es):



                stripped=l in e.strip()











if notstrippedorstripped.startswith('#')orstripped.startswith('//'):



                    cont in ue











if'function'instripped:



                    in_function=True







if in_function:



                    open_braces+=stripped.count('{')



open_braces-=stripped.count('}')











if open_braces>0and'{'instripped:



                        insertion_po in ts.append(i+1)











if open_braces>0and'}'instrippedandnot('{'instrippedand'}'instripped):



                        insertion_po in ts.append(i)











if open_braces==0:



                        in_function=False







return in sertion_po in ts







def_get_indent(self,l in e:str)->str:







return l in e[:len(l in e)-len(l in e.lstrip())]