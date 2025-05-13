import os
import uuid
import importlib
from typing import Dict, Any, List, Optional

from core.config import get_obfuscation_config, get_evasion_techniques, get_template_path

class PayloadManager:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.output_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            config['paths']['output']
        )

        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def generate(self,
                payload_type: str,
                payload: str,
                output_path: str,
                obfuscation_level: str = "medium",
                use_evasion: bool = False,
                iterations: int = 1) -> str:

        obfuscation_config = get_obfuscation_config(self.config, obfuscation_level)

        generator = self._load_generator(payload_type)

        obfuscators = self._load_obfuscators(obfuscation_config)

        evasion_techniques = self._load_evasion_techniques() if use_evasion else []

        template_path = get_template_path(self.config, payload_type)

        result = generator.generate(
            payload=payload,
            template_path=template_path,
            obfuscators=obfuscators,
            evasion_techniques=evasion_techniques,
            iterations=iterations
        )

        output_path = os.path.join(self.output_dir, output_path)

        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        with open(output_path, 'wb') as f:
            f.write(result)

        return output_path

    def _load_generator(self, payload_type: str):
        try:
            module = importlib.import_module(f'generators.{payload_type}_generator')
            generator_class = getattr(module, f'{payload_type.capitalize()}Generator')
            return generator_class()
        except (ImportError, AttributeError) as e:
            raise ImportError(f"Не удалось загрузить генератор для типа {payload_type}: {str(e)}")

    def _load_obfuscators(self, obfuscation_config: Dict[str, bool]) -> List:
        obfuscators = []

        for technique, enabled in obfuscation_config.items():
            if enabled:
                try:
                    module = importlib.import_module(f'obfuscators.{technique}')
                    obfuscator_class = getattr(module, f'{technique.title().replace("_", "")}Obfuscator')
                    obfuscators.append(obfuscator_class())
                except (ImportError, AttributeError) as e:
                    print(f"Предупреждение: Не удалось загрузить обфускатор {technique}: {str(e)}")

        return obfuscators

    def _load_evasion_techniques(self) -> List:
        techniques = []
        available_techniques = get_evasion_techniques(self.config)

        for technique in available_techniques:
            try:
                module = importlib.import_module(f'evasion.{technique}')
                technique_class = getattr(module, f'{technique.title().replace("_", "")}Technique')
                techniques.append(technique_class())
            except (ImportError, AttributeError) as e:
                print(f"Предупреждение: Не удалось загрузить технику обхода {technique}: {str(e)}")

        return techniques

    def list_templates(self) -> List[str]:
        templates_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            self.config['paths']['templates']
        )

        if not os.path.exists(templates_dir):
            return []

        return [d for d in os.listdir(templates_dir)
                if os.path.isdir(os.path.join(templates_dir, d))]

    def add_template(self, template_path: str) -> None:
        if not os.path.exists(template_path):
            raise FileNotFoundError(f"Шаблон не найден: {template_path}")

        template_name = os.path.basename(template_path)
        target_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            self.config['paths']['templates'],
            template_name
        )

        if not os.path.exists(os.path.dirname(target_dir)):
            os.makedirs(os.path.dirname(target_dir))

        import shutil
        shutil.copytree(template_path, target_dir, dirs_exist_ok=True)