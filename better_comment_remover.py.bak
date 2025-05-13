import os
import re
import glob
import shutil
import tokenize
import io
from pathlib import Path

def ensure_spaces(text):
    """Восстанавливает необходимые пробелы в коде после удаления комментариев."""
    # Пробелы между ключевыми словами и идентификаторами
    text = re.sub(r'\b(import|from|as|except|if|elif|else|def|class|return|raise|while|for|in|not|is|and|or|try|with|yield|assert|del|global|nonlocal|lambda|with)\b([a-zA-Z0-9_])', r'\1 \2', text)
    
    # Пробелы вокруг операторов сравнения и присваивания
    text = re.sub(r'([a-zA-Z0-9_])(==|!=|>=|<=|>|<|=|\+=|-=|\*=|/=|%=|\^=|\|=|&=|>>|<<)([a-zA-Z0-9_])', r'\1 \2 \3', text)
    
    # Пробелы вокруг математических операторов
    text = re.sub(r'([a-zA-Z0-9_])(\+|-|\*|/|%|\^|\||\&|\*)([a-zA-Z0-9_])', r'\1 \2 \3', text)
    
    # Исправление разделенных сущностей
    text = re.sub(r'([a-zA-Z0-9_])\s*\.\s*([a-zA-Z0-9_])', r'\1.\2', text)
    
    # Исправление notin -> not in
    text = re.sub(r'\bnotin\b', r'not in', text)
    
    # Вставка пробелов в составные операторы
    text = re.sub(r'\b(not)(in)\b', r'not in', text)
    text = re.sub(r'\b(is)(not)\b', r'is not', text)
    
    return text

def clean_docstrings(content):
    """Удаляет строки документации (docstrings) из кода."""
    # Паттерн для поиска многострочных строк документации (docstrings)
    pattern = r'((["\'])\2\2[\s\S]*?\2\2\2)|((["\'])[\s\S]*?\4)'
    
    # Функция для определения, является ли строка документацией
    def is_docstring(match):
        before_match = content[:match.start()].strip()
        if not before_match:
            return True  # Docstring в начале модуля
        
        # Проверяем, находится ли docstring сразу после определения функции/класса/метода
        lines = before_match.split('\n')
        last_line = lines[-1].strip()
        
        if last_line.endswith(':') or last_line.endswith('(') or last_line.endswith(')'):
            return True  # Docstring для функции/класса
            
        # Если находится после присваивания, скорее всего, это обычная строка
        if '=' in last_line:
            return False
            
        return False
        
    # Ищем все строки и удаляем только те, что являются документацией
    result = content
    for match in re.finditer(pattern, content):
        if is_docstring(match):
            result = result.replace(match.group(0), "", 1)
    
    return result

def remove_comments(file_path, backup=True):
    """Удаляет комментарии из файла, сохраняя его синтаксическую корректность."""
    print(f"Обработка файла: {file_path}")
    
    # Создание резервной копии файла
    if backup:
        backup_path = f"{file_path}.bak"
        shutil.copy2(file_path, backup_path)
    
    try:
        # Чтение содержимого файла
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
    except UnicodeDecodeError:
        print(f"Ошибка: не удается прочитать файл {file_path} - неверная кодировка")
        return False
        
    # Первый проход: удаление строк документации
    content = clean_docstrings(content)
    
    # Второй проход: удаление комментариев
    lines = []
    prev_token_type = None
    prev_token_string = ""
    
    try:
        # Используем токенизатор Python для корректного выделения комментариев
        readline = io.StringIO(content).readline
        tokens = list(tokenize.generate_tokens(readline))
        
        for token in tokens:
            token_type = token[0]
            token_string = token[1]
            
            # Пропускаем комментарии
            if token_type == tokenize.COMMENT:
                continue
                
            # Пропускаем строки документации (если они не были удалены ранее)
            if token_type == tokenize.STRING and token_string.startswith(('"""', "'''")) and (
                prev_token_type in (tokenize.INDENT, tokenize.NEWLINE, None) or 
                prev_token_string.endswith((':'))
            ):
                continue
                
            lines.append(token_string)
            prev_token_type = token_type
            prev_token_string = token_string
    except (tokenize.TokenError, IndentationError):
        # В случае ошибки токенизации используем более простой подход
        print(f"Предупреждение: не удалось токенизировать {file_path}, использую альтернативный метод")
        # Удаление однострочных комментариев
        lines = []
        for line in content.split('\n'):
            # Удаляем комментарии в конце строки
            line = re.sub(r'#.*$', '', line)
            lines.append(line)
    
    # Объединяем строки в текст
    cleaned_content = ''.join(lines)
    
    # Проверяем на наличие ошибок синтаксиса
    cleaned_content = ensure_spaces(cleaned_content)
    
    # Записываем обратно в файл
    try:
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(cleaned_content)
        
        # Проверяем синтаксис
        try:
            compile(cleaned_content, file_path, 'exec')
            return True
        except SyntaxError as e:
            print(f"Ошибка: синтаксическая ошибка в {file_path} после удаления комментариев - {str(e)}")
            
            # Восстанавливаем из резервной копии при ошибке
            if backup:
                shutil.copy2(backup_path, file_path)
                print(f"Файл {file_path} восстановлен из резервной копии")
            return False
    except Exception as e:
        print(f"Ошибка при записи файла {file_path}: {str(e)}")
        return False

def process_directory(directory="."):
    """Обрабатывает все Python файлы в указанной директории."""
    python_files = glob.glob(f"{directory}/**/*.py", recursive=True)
    
    # Исключаем текущий скрипт и файлы в папке .venv
    python_files = [f for f in python_files 
                   if not f.startswith('.venv/') 
                   and not f == 'better_comment_remover.py'
                   and not f == 'remove_comments.py']
    
    print(f"Найдено {len(python_files)} Python файлов для обработки")
    
    success_count = 0
    for file_path in python_files:
        if remove_comments(file_path):
            success_count += 1
    
    print(f"Обработка завершена. Успешно обработано {success_count} из {len(python_files)} файлов.")
    
    # Удаление резервных копий
    if input("Удалить резервные копии файлов? (y/n): ").lower() == 'y':
        backup_files = glob.glob("**/*.py.bak", recursive=True)
        for backup in backup_files:
            os.remove(backup)
        print(f"Удалено {len(backup_files)} резервных копий")

if __name__ == "__main__":
    process_directory() 