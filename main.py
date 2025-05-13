import os
import sys
import argparse
from rich.console import Console
from rich.panel import Panel

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.manager import PayloadManager
from core.config import load_config

console = Console()

def banner():
    banner_text = """
    ╦ ╦╦ ╦╔╦╗╦═╗╔═╗╔═╗  ╦ ╦╔═╗╔═╗╔╦╗
    ╠═╣╚╦╝ ║║╠╦╝╠═╣╚═╗  ╠═╣║╣ ╠═╣ ║║
    ╩ ╩ ╩ ═╩╝╩╚═╩ ╩╚═╝  ╩ ╩╚═╝╩ ╩═╩╝
    Полиморфная система генерации и доставки нагрузки
    """
    console.print(Panel(banner_text, border_style="red"))

def parse_arguments():
    parser = argparse.ArgumentParser(description="Hydra's Head - Полиморфная система генерации нагрузки")

    subparsers = parser.add_subparsers(dest="command", help="Команды")

    # Команда генерации
    generate_parser = subparsers.add_parser("generate", help="Сгенерировать нагрузку")
    generate_parser.add_argument("--type", "-t", choices=["exe", "dll", "shellcode", "macro", "ps1", "py", "js"],
                               required=True, help="Тип нагрузки")
    generate_parser.add_argument("--payload", "-p", required=True, help="Полезная нагрузка (команда или путь к файлу)")
    generate_parser.add_argument("--output", "-o", required=True, help="Путь к выходному файлу")
    generate_parser.add_argument("--obfuscation", choices=["low", "medium", "high", "max"],
                               default="medium", help="Уровень обфускации")
    generate_parser.add_argument("--evasion", action="store_true", help="Включить техники обхода обнаружения")
    generate_parser.add_argument("--iterations", "-i", type=int, default=1,
                               help="Количество итераций полиморфизма")

    # Команда работы с шаблонами
    template_parser = subparsers.add_parser("template", help="Управление шаблонами")
    template_parser.add_argument("--list", action="store_true", help="Список доступных шаблонов")
    template_parser.add_argument("--add", help="Добавить новый шаблон из файла")

    return parser.parse_args()

def main():
    banner()
    args = parse_arguments()

    if not args.command:
        console.print("[bold red]Ошибка:[/bold red] Необходимо указать команду.")
        return 1

    try:
        config = load_config()
        manager = PayloadManager(config)

        if args.command == "generate":
            console.print(f"[bold green]Генерация полезной нагрузки типа:[/bold green] {args.type}")
            output_file = manager.generate(
                payload_type=args.type,
                payload=args.payload,
                output_path=args.output,
                obfuscation_level=args.obfuscation,
                use_evasion=args.evasion,
                iterations=args.iterations
            )
            console.print(f"[bold green]Успешно сгенерирован файл:[/bold green] {output_file}")

        elif args.command == "template":
            if args.list:
                templates = manager.list_templates()
                if templates:
                    console.print("[bold green]Доступные шаблоны:[/bold green]")
                    for template in templates:
                        console.print(f" - {template}")
                else:
                    console.print("[yellow]Шаблоны не найдены[/yellow]")
            
            elif args.add:
                manager.add_template(args.add)
                console.print(f"[bold green]Шаблон успешно добавлен:[/bold green] {args.add}")

        return 0

    except Exception as e:
        console.print(f"[bold red]Ошибка:[/bold red] {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())