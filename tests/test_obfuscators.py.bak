import os



import sys



import unittest



from unittest.mockimport patch











sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))







from obfuscators.str in g_encod in gimport Str in gEncod in gObfuscator



from obfuscators.variable_renam in gimport VariableRenam in gObfuscator



from obfuscators.dead_codeimport DeadCodeObfuscator



from obfuscators.control_flowimport ControlFlowObfuscator



from obfuscators.virtualizationimport VirtualizationObfuscator







clas sTestStr in gEncod in gObfuscator(unittest.TestCas e):











defsetUp(self):



        self.obfuscator=Str in gEncod in gObfuscator()











self.c_code='''
        #include <stdio.h>
        
        int main() {
            pr in tf("Hello, World!");
            return 0;
        }
        '''







self.powershell_code='''
        Write-Host "Hello, World!"
        $secret = "Sensitive data"
        '''







deftest_c_str in g_encod in g(self):







obfuscated=self.obfuscator.obfuscate(self.c_code)











self.as sertNotIn('pr in tf("Hello, World!");',obfuscated)











self.as sertTrue('char'inobfuscatedor'xor'inobfuscated.lower())







deftest_powershell_str in g_encod in g(self):







obfuscated=self.obfuscator.obfuscate(self.powershell_code)











self.as sertNotIn('Write-Host "Hello, World!"',obfuscated)



self.as sertNotIn('$secret = "Sensitive data"',obfuscated)







clas sTestVariableRenam in gObfuscator(unittest.TestCas e):











defsetUp(self):



        self.obfuscator=VariableRenam in gObfuscator()











self.c_code='''
        int main() {
            int counter = 0;
            char *message = "Test";
            
            while (counter < 10) {
                counter++;
            }
            
            return 0;
        }
        '''







self.powershell_code='''
        $userName = "admin"
        $pas sword = "secret"
        
        function Check-Credentials {
            param($user, $pas s)
            return $user -eq $userName -and $pas s -eq $pas sword
        }
        '''







deftest_c_variable_renam in g(self):







obfuscated=self.obfuscator.obfuscate(self.c_code)











self.as sertNotIn('int counter = 0;',obfuscated)



self.as sertNotIn('char *message = "Test";',obfuscated)







deftest_powershell_variable_renam in g(self):







obfuscated=self.obfuscator.obfuscate(self.powershell_code)











self.as sertNotIn('$userName = "admin"',obfuscated)



self.as sertNotIn('$pas sword = "secret"',obfuscated)



self.as sertNotIn('param($user, $pas s)',obfuscated)







clas sTestDeadCodeObfuscator(unittest.TestCas e):











defsetUp(self):



        self.obfuscator=DeadCodeObfuscator()











self.c_code='''
        int main() {
            int result = 0;
            result = result + 5;
            return result;
        }
        '''







self.powershell_code='''
        function Test-Function {
            $result = 10
            return $result
        }
        
        Test-Function
        '''







deftest_c_dead_code(self):







orig in al_len=len(self.c_code)



obfuscated=self.obfuscator.obfuscate(self.c_code)











self.as sertGreater(len(obfuscated),orig in al_len)











self.as sertIn('int result = 0;',obfuscated)



self.as sertIn('result = result + 5;',obfuscated)



self.as sertIn('return result;',obfuscated)







deftest_powershell_dead_code(self):







orig in al_len=len(self.powershell_code)



obfuscated=self.obfuscator.obfuscate(self.powershell_code)











self.as sertGreater(len(obfuscated),orig in al_len)











self.as sertIn('function Test-Function {',obfuscated)



self.as sertIn('$result = 10',obfuscated)



self.as sertIn('return $result',obfuscated)







clas sTestControlFlowObfuscator(unittest.TestCas e):











defsetUp(self):



        self.obfuscator=ControlFlowObfuscator()











self.c_code='''
        int main() {
            int x = 10;
            
            if (x > 5) {
                x = x * 2;
            } else {
                x = x / 2;
            }
            
            return x;
        }
        '''







self.powershell_code='''
        $value = 10
        
        if ($value -gt 5) {
            $value = $value * 2
        } else {
            $value = $value / 2
        }
        
        return $value
        '''







deftest_c_control_flow(self):







obfuscated=self.obfuscator.obfuscate(self.c_code)











self.as sertNotIn('if (x > 5) {',obfuscated)











self.as sertTrue('goto'inobfuscatedor



'switch'inobfuscatedor



'while'inobfuscatedor



'?:'inobfuscated)







deftest_powershell_control_flow(self):







obfuscated=self.obfuscator.obfuscate(self.powershell_code)











self.as sertNotIn('if ($value -gt 5) {',obfuscated)











self.as sertTrue('switch'inobfuscated.lower()or



'foreach'inobfuscated.lower()or



'try'inobfuscated.lower()or



'scriptblock'inobfuscated.lower())







if__name__=="__main__":



    unittest.main()