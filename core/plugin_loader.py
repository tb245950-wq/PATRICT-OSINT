import os
import sys
import inspect
import importlib
import importlib.util
from typing import List, Dict, Any, Type, Optional
from core.base_module import BaseOSINTModule

class PluginLoader:
    """
    Dynamic Plugin / Module Discovery Engine.
    Secara otomatis memindai folder modules/, me-load class yang meng-inherit
    BaseOSINTModule, dan meng-instansiasi modul yang diaktifkan di konfigurasi.
    """
    
    def __init__(self, modules_dir: str = "modules", config: Any = None, async_client: Any = None):
        self.modules_dir = modules_dir
        self.config = config
        self.async_client = async_client
        self.loaded_modules: List[BaseOSINTModule] = []
        
    def discover_and_load(self, target_type: Optional[str] = None) -> List[BaseOSINTModule]:
        self.loaded_modules = []
        
        target_dir = self.modules_dir
        if not os.path.isabs(target_dir) and not os.path.exists(target_dir):
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            candidate = os.path.join(base_dir, target_dir)
            if os.path.exists(candidate):
                target_dir = candidate

        if not os.path.exists(target_dir):
            print(f"[!] Warning: Direktori modul '{target_dir}' tidak ditemukan.")
            return []
            
        abs_modules_dir = os.path.abspath(target_dir)
        if abs_modules_dir not in sys.path:
            sys.path.insert(0, abs_modules_dir)
            
        for file in sorted(os.listdir(abs_modules_dir)):
            if file.endswith(".py") and not file.startswith("__"):
                module_name = file[:-3]
                file_path = os.path.join(abs_modules_dir, file)
                
                try:
                    spec = importlib.util.spec_from_file_location(f"modules.{module_name}", file_path)
                    if spec and spec.loader:
                        py_module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(py_module)
                        
                        # Cari class turunan BaseOSINTModule di dalam file
                        for _, cls in inspect.getmembers(py_module, inspect.isclass):
                            if issubclass(cls, BaseOSINTModule) and cls is not BaseOSINTModule:
                                mod_type = getattr(cls, 'target_type', 'phone')
                                if target_type and target_type != 'all' and mod_type not in (target_type, 'all', 'any'):
                                    continue
                                    
                                module_instance = cls(config=self.config, async_client=self.async_client)
                                
                                # Periksa apakah modul diaktifkan di config
                                is_enabled = True
                                if self.config:
                                    is_enabled = self.config.is_module_enabled(module_instance.module_id)
                                    
                                if is_enabled:
                                    self.loaded_modules.append(module_instance)
                                    print(f"  [+] Loaded Module: {module_instance.name} (v{module_instance.version})")
                                else:
                                    print(f"  [-] Disabled Module: {module_instance.name} (via config)")
                except Exception as e:
                    print(f"  [!] Error loading module {file}: {e}")
                    
        # Urutkan berdasarkan prioritas (angka lebih kecil = prioritas lebih tinggi)
        self.loaded_modules.sort(key=lambda m: getattr(m, 'priority', 10))
        return self.loaded_modules
