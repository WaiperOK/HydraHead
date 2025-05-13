from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Union, ByteString, Tuple, Set, Callable

class BaseGenerator(ABC):
    
    @abstractmethod
    def generate(self,
                payload: str,
                template_path: str,
                obfuscators: List = None,
                evasion_techniques: List = None,
                iterations: int = 1,
                encryption_key: bytes = None,
                multi_stage: bool = False,
                polymorphic: bool = False) -> bytes:
        pass
    
    @abstractmethod
    def get_supported_payloads(self) -> List[str]:
        pass
    
    @abstractmethod
    def get_supported_templates(self) -> List[str]:
        pass

class BaseObfuscator(ABC):
    
    @abstractmethod
    def obfuscate(self, code: str,
                level: str = "medium",
                iterations: int = 1,
                markers: Dict[str, str] = None) -> str:
        pass
    
    @abstractmethod
    def supported_formats(self) -> List[str]:
        pass
    
    @abstractmethod
    def get_complexity(self) -> int:
        pass
    
    @abstractmethod
    def is_compatible_with(self, other_obfuscator: 'BaseObfuscator') -> bool:
        pass

class BaseEvasionTechnique(ABC):
    
    @abstractmethod
    def apply(self, code: str,
            target_environments: List[str] = None,
            bypass_level: str = "medium",
            customize_params: Dict[str, Any] = None) -> str:
        pass
    
    @abstractmethod
    def supported_formats(self) -> List[str]:
        pass
    
    @abstractmethod
    def get_evasion_targets(self) -> List[str]:
        pass
    
    @abstractmethod
    def is_compatible_with(self, other_technique: 'BaseEvasionTechnique') -> bool:
        pass
    
    @abstractmethod
    def get_detection_probability(self) -> float:
        pass

class BaseLoader(ABC):
    
    @abstractmethod
    def load(self, payload: bytes,
            target_process: str = None,
            encryption_key: bytes = None,
            memory_protection: str = "RWX",
            stealthy_allocation: bool = False,
            hide_threads: bool = False,
            anti_memory_scan: bool = False,
            **kwargs) -> bool:
        pass
    
    @abstractmethod
    def supported_platforms(self) -> List[str]:
        pass
    
    @abstractmethod
    def get_technique_details(self) -> Dict[str, Any]:
        pass
    
    @abstractmethod
    def supports_multi_stage(self) -> bool:
        pass
    
    @abstractmethod
    def get_evasion_capabilities(self) -> Set[str]:
        pass

class ChainTechnique(ABC):
    
    @abstractmethod
    def add_technique(self, technique: Any, position: int = -1) -> None:
        pass
    
    @abstractmethod
    def execute_chain(self, payload: bytes, target: str = None, **kwargs) -> bool:
        pass
    
    @abstractmethod
    def get_chain(self) -> List[Dict[str, Any]]:
        pass
    
    @abstractmethod
    def clear_chain(self) -> None:
        pass