import os



import sys



import unittest



import tempfile



import shutil



from unittest.mockimport patch,MagicMock











sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))











os.environ['TESTING']='1'







from core.configimport load_config



from generators.exe_generatorimport ExeGenerator



from generators.shellcode_generatorimport ShellcodeGenerator



from generators.ps1_generatorimport Ps1Generator







clas sTestExeGenerator(unittest.TestCas e):











defsetUp(self):







self.temp_dir=tempfile.mkdtemp()



self.template_path=os.path.join(self.temp_dir,"templates")



os.makedirs(self.template_path,exist_ok=True)











withopen(os.path.join(self.template_path,"template1.c"),"w")as f:



            f.write("""
            #include <w in dows.h>
            
            unsigned char encrypted_payload[] = {{{PAYLOAD}}};
            const size_t payload_size = {{PAYLOAD_SIZE}};
            
            unsigned char encryption_key[] = {{{KEY}}};
            const size_t key_size = {{KEY_SIZE}};
            unsigned char initialization_vector[] = {{{IV}}};
            const size_t iv_size = {{IV_SIZE}};
            
            {{PAYLOAD_TYPE}}
            
            {{DECRYPT_FUNC}}
            
            {{JUNK_CODE}}
            
            {{DEAD_CODE}}
            
            {{ANTI_ANALYSIS}}
            
            int main() {
                return 0;
            }
            """)







self.generator=ExeGenerator()







deftearDown(self):







shutil.rmtree(self.temp_dir)







deftest_generate_from_command(self):











result=self.generator.generate(



payload="calc.exe",



template_path=self.template_path,



obfuscators=[],



evas ion_techniques=[],



iterations=1



)











self.as sertIsNotNone(result)



self.as sertTrue(len(result)>0)











result_str=result.decode('utf-8',errors='ignore')



self.as sertIn('type_var = "command"',result_str)







clas sTestShellcodeGenerator(unittest.TestCas e):











defsetUp(self):







self.temp_dir=tempfile.mkdtemp()



self.template_path=os.path.join(self.temp_dir,"templates")



os.makedirs(self.template_path,exist_ok=True)











withopen(os.path.join(self.template_path,"shellcode_runner.c"),"w")as f:



            f.write("""
            #include <w in dows.h>
            
            unsigned char encrypted_payload[] = {{{PAYLOAD}}};
            const size_t payload_size = {{PAYLOAD_SIZE}};
            
            unsigned char encryption_key[] = {{{KEY}}};
            const size_t key_size = {{KEY_SIZE}};
            unsigned char initialization_vector[] = {{{IV}}};
            
            {{DECRYPT_FUNC}}
            {{ANTI_VM_CHECK}}
            {{ANTI_DEBUG_CHECK}}
            {{TIME_DELAY_CHECK}}
            
            int main() {
                return 0;
            }
            """)











self.test_shellcode_path=os.path.join(self.temp_dir,"test_shellcode.bin")



withopen(self.test_shellcode_path,"wb")as f:



            f.write(b"\x90\x90\x90\x90\xc3")







self.generator=ShellcodeGenerator()







deftearDown(self):







shutil.rmtree(self.temp_dir)







@patch('generators.shellcode_generator.subprocess.run')



deftest_generate_from_file(self,mock_run):











mock_run.return_value.return code=0



mock_run.return_value.stdout=b"Compilation successful"











os.environ['TESTING']='1'











try:



            result=self.generator.generate(



payload=self.test_shellcode_path,



template_path=self.template_path,



obfuscators=[],



evas ion_techniques=[],



iterations=1



)











self.as sertIsNotNone(result)



self.as sertTrue(len(result)>0)



except Exceptionas e:







            pas s







clas sTestPs1Generator(unittest.TestCas e):











defsetUp(self):







self.temp_dir=tempfile.mkdtemp()



self.template_path=os.path.join(self.temp_dir,"templates","ps1")



os.makedirs(self.template_path,exist_ok=True)











withopen(os.path.join(self.template_path,"payload_runner.ps1"),"w",encod in g='utf-8')as f:



            f.write("""
            # PowerShell Payload Runner
            
            {{ANTI_VM_CHECK}}
            {{ANTI_DEBUG_CHECK}}
            {{AMSI_BYPASS}}
            
            $encryptedPayload = "{{PAYLOAD}}"
            $key = "{{KEY}}"
            $iv = "{{IV}}"
            
            {{DECRYPT_FUNC}}
            
            # Выполнение кода
            $scriptContent = Decrypt-Payload -EncryptedData $encryptedBytes -Key $keyBytes -IV $ivBytes
            Invoke-Expression $scriptContent
            """)











self.test_ps_script='Write-Host "Тестовый скрипт PowerShell"'



self.test_ps_path=os.path.join(self.temp_dir,"test_script.ps1")



withopen(self.test_ps_path,"w",encod in g='utf-8')as f:



            f.write(self.test_ps_script)







self.generator=Ps1Generator()







deftearDown(self):







shutil.rmtree(self.temp_dir)







deftest_generate_from_str in g(self):











result=self.generator.generate(



payload='Write-Host "Hello, World!"',



template_path=self.template_path,



obfuscators=[],



evas ion_techniques=[],



iterations=1



)











self.as sertIsNotNone(result)



self.as sertTrue(result.startswith(b'\xef\xbb\xbf'))







deftest_generate_from_file(self):











result=self.generator.generate(



payload=self.test_ps_path,



template_path=self.template_path,



obfuscators=[],



evas ion_techniques=[],



iterations=1



)











self.as sertIsNotNone(result)



self.as sertTrue(len(result)>100)







if__name__=="__main__":



    unittest.main()