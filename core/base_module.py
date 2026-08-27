import abc
import logging
from typing import Dict, Any, Optional

class BaseOSINTModule(abc.ABC):
    """
    Abstract Base Class untuk seluruh modul di dalam PATRICT-OSINT.
    Semua modul di folder modules/ wajib meng-inherit class ini.
    """
    
    name: str = "BaseModule"
    module_id: str = "base_module"
    description: str = "Base OSINT Module Description"
    version: str = "1.0.0"
    author: str = "PATRICT Core Team"
    enabled: bool = True
    priority: int = 10  # Modul dengan prioritas lebih rendah dieksekusi lebih awal
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, async_client: Optional[Any] = None):
        self.config = config or {}
        self.async_client = async_client
        self.logger = logging.getLogger(f"PATRICT.{self.module_id}")
        
    @abc.abstractmethod
    async def run(self, target: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Method utama yang akan dieksekusi oleh orchestrator.
        
        :param target: Nomor telepon atau target input string
        :param context: Context data dari modul-modul yang sudah dieksekusi sebelumnya
        :return: Dict berisi hasil temuan modul
        """
        pass
    
    def success_response(self, data: Any, message: str = "Success") -> Dict[str, Any]:
        return {
            "status": "success",
            "module": self.name,
            "module_id": self.module_id,
            "message": message,
            "data": data
        }
        
    def error_response(self, error: str, data: Any = None) -> Dict[str, Any]:
        return {
            "status": "error",
            "module": self.name,
            "module_id": self.module_id,
            "error": str(error),
            "data": data or {}
        }
