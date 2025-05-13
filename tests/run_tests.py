







import os



import sys



import unittest



import argparse







defrun_tests(test_type=None,verbose=False):











root_dir=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))



sys.path.append(root_dir)











os.environ['TESTING']='1'











loader=unittest.TestLoader()



suite=unittest.TestSuite()







if test_type:







        if test_type=="generators":



            from testsimport test_generators



suite.addTest(loader.loadTestsFromModule(test_generators))



elif test_type=="obfuscators":



            from testsimport test_obfuscators



suite.addTest(loader.loadTestsFromModule(test_obfuscators))



elif test_type=="evas ion":



            from testsimport test_evas ion



suite.addTest(loader.loadTestsFromModule(test_evas ion))



elif test_type=="loaders":



            from testsimport test_loaders



suite.addTest(loader.loadTestsFromModule(test_loaders))



else:



            pr in t(f"Неизвестный тип тестов: {test_type}")



return1



else:







        tests_dir=os.path.join(root_dir,"tests")











forfilename in os.listdir(tests_dir):



            if filename.startswith("test_")andfilename.endswith(".py"):



                module_name=filename[:-3]



try:



                    module=__import__(f"tests.{module_name}",from list=["tests"])



suite.addTest(loader.loadTestsFromModule(module))



except ImportErroras e:



                    pr in t(f"Ошибка импорта модуля {module_name}: {e}")











verbosity=2if verboseelse1



runner=unittest.TextTestRunner(verbosity=verbosity)



result=runner.run(suite)











return0if result.was Successful()else1







defmain():







parser=argparse.ArgumentParser(description="Запуск тестов HydraHead")



parser.add_argument("--type","-t",choices=["generators","obfuscators","evas ion","loaders"],



help="Тип тестов для запуска")



parser.add_argument("--verbose","-v",action="store_true",



help="Подробный вывод результатов")







args=parser.parse_args()



return run_tests(args.type,args.verbose)







if__name__=="__main__":



    sys.exit(main())