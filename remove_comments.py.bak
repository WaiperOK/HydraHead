import os
import re
import glob
import tokenize
import io
from pathlib import Path

def remove_comments_from_file(file_path):
    print(f"Обработка файла: {file_path}")
    
    with open(file_path, 'r', encoding='utf-8') as file:
        try:
            content = file.read()
        except UnicodeDecodeError:
            print(f"Ошибка чтения файла: {file_path}")
            return
    
    # Обработка токенов для более аккуратного удаления комментариев
    tokens = []
    try:
        # Преобразуем содержимое файла в поток токенов
        readline = io.StringIO(content).readline
        token_generator = tokenize.generate_tokens(readline)
        
        # Фильтруем токены, убирая комментарии и строки документации
        for toktype, tokval, _, _, _ in token_generator:
            # Игнорируем комментарии
            if toktype == tokenize.COMMENT:
                continue
            # Проверяем, является ли строка документацией (обычно это СТРОКА сразу после определения функции или класса)
            if toktype == tokenize.STRING and tokval.startswith(('"""', "'''")):
                # Проверяем, может ли это быть строкой документации
                if tokens and tokens[-1][0] in (tokenize.INDENT, tokenize.NEWLINE):
                    continue
            
            tokens.append((toktype, tokval))
    except tokenize.TokenError:
        # В случае ошибки анализа токенов используем более простой подход с регулярными выражениями
        print(f"Ошибка токенизации файла {file_path}, использую метод с регулярными выражениями")
        # Удаление строк документации
        content = re.sub(r'"""[\s\S]*?"""', '', content)
        content = re.sub(r"'''[\s\S]*?'''", '', content)
        
        # Удаление однострочных комментариев
        result = []
        for line in content.split('\n'):
            line = re.sub(r'#.*$', '', line)
            # Сохраняем пробелы и структуру
            result.append(line)
        
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write('\n'.join(result))
        return
    
    # Восстанавливаем исходный код без комментариев
    result = []
    line = []
    
    for toktype, tokval in tokens:
        if toktype == tokenize.NEWLINE:
            line.append(tokval)
            result.append(''.join(line))
            line = []
        elif toktype == tokenize.NL:
            line.append(tokval)
            if line:
                result.append(''.join(line))
                line = []
        else:
            line.append(tokval)
    
    if line:
        result.append(''.join(line))
    
    # Удаляем последнюю пустую строку
    while result and not result[-1].strip():
        result.pop()
    
    # Убедимся, что мы не удалили пробелы между идентификаторами и операторами
    code_result = []
    for line in result:
        # Проверяем наличие склеенных идентификаторов (например "importos" -> "import os")
        line = re.sub(r'(import|from)([A-Za-z])', r'\1 \2', line)
        # Другие исправления синтаксиса
        line = re.sub(r'as([A-Za-z])', r'as \1', line)
        line = re.sub(r'except([A-Za-z])', r'except \1', line)
        line = re.sub(r'if([A-Za-z])', r'if \1', line)
        line = re.sub(r'([A-Za-z])in([A-Za-z])', r'\1 in \2', line)
        line = re.sub(r'notin', r'not in', line)
        line = re.sub(r'return([A-Za-z])', r'return \1', line)
        code_result.append(line)
    
    # Сохраняем файл без комментариев
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write('\n'.join(code_result))
    
    # Проверяем, что файл синтаксически корректен
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            compile(f.read(), file_path, 'exec')
    except SyntaxError as e:
        print(f"ВНИМАНИЕ: Возникла синтаксическая ошибка в файле {file_path}: {str(e)}")
        # Здесь можно добавить более серьезные исправления синтаксиса при необходимости

def process_all_files():
    python_files = glob.glob('**/*.py', recursive=True)
    
    # Исключаем текущий скрипт и папку .venv
    filtered_files = [f for f in python_files if not f.startswith('.venv') and f != 'remove_comments.py']
    
    print(f"Найдено {len(filtered_files)} файлов для обработки")
    
    for file_path in filtered_files:
        remove_comments_from_file(file_path)
    
    print("Все комментарии успешно удалены!")

if __name__ == "__main__":
    process_all_files() 