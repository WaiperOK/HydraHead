import os
import yaml
from typing import Dict, Any

CONFIG_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config.yaml')

def load_config(config_path: str = CONFIG_FILE) -> Dict[str, Any]:
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Файл конфигурации не найден: {config_path}")

    with open(config_path, 'r', encoding='utf-8') as f:
        try:
            config = yaml.safe_load(f)
            return config
        except yaml.YAMLError as e:
            raise ValueError(f"Ошибка при чтении конфигурации: {str(e)}")

def get_obfuscation_config(config: Dict[str, Any], level: str) -> Dict[str, bool]:
    if level not in config['obfuscation']['levels']:
        raise ValueError(f"Неизвестный уровень обфускации: {level}")

    return config['obfuscation']['levels'][level]

def get_evasion_techniques(config: Dict[str, Any]) -> list:
    return config['evasion']['techniques']

def get_template_path(config: Dict[str, Any], payload_type: str) -> str:
    if payload_type not in config['payloads']['templates']:
        raise ValueError(f"Неизвестный тип нагрузки: {payload_type}")

    template_path = config['payloads']['templates'][payload_type]
    full_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), template_path)

    if not os.path.exists(full_path):
        raise FileNotFoundError(f"Директория шаблонов не найдена: {full_path}")

    return full_path