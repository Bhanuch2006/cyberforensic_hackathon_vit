"""
File management utilities
"""
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional
import json


class FileManager:
    """Manages input/output file tracking"""
    
    def __init__(self, output_dir: str = "output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.file_registry: Dict[str, str] = {}
    
    def generate_timestamp(self) -> str:
        """Generate timestamp string"""
        return datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def get_output_path(self, filename_template: str) -> Path:
        """
        Get output file path with timestamp
        
        Args:
            filename_template: e.g., "forensiq_results_{timestamp}.csv"
        """
        timestamp = self.generate_timestamp()
        filename = filename_template.format(timestamp=timestamp)
        return self.output_dir / filename
    
    def register_file(self, key: str, filepath: str):
        """Register a file for future reference"""
        self.file_registry[key] = filepath
    
    def get_file(self, key: str) -> Optional[str]:
        """Get registered file path"""
        return self.file_registry.get(key)
    
    def get_latest_file(self, pattern: str) -> Optional[Path]:
        """
        Get most recent file matching pattern
        
        Args:
            pattern: e.g., "forensiq_results_*.csv"
        """
        files = sorted(self.output_dir.glob(pattern), reverse=True)
        return files[0] if files else None
    
    def save_metadata(self, data: dict, filename: str):
        """Save metadata as JSON"""
        filepath = self.output_dir / filename
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        return str(filepath)


file_manager = FileManager()
