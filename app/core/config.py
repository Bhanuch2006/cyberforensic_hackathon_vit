"""
Configuration management for ForensIQ API
"""
from pydantic_settings import BaseSettings
from pathlib import Path
from typing import List


class Settings(BaseSettings):
    """Application settings"""
    
    # API Configuration
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    debug: bool = True
    
    # Paths
    data_path: str = "data/UNSW_prepared.csv"
    output_dir: str = "output"
    model_dir: str = "output/models"
    autoencoder_path: str = "output/models/autoencoder.pth"
    iforest_path: str = "output/models/iforest.pkl"
    scaler_path: str = "output/models/scaler.pkl"
    
    # Model parameters
    batch_size: int = 2048
    ml_features: str = "dur,sbytes,dbytes,sttl,dttl,sloss,dloss"
    
    # Ensemble weights
    weight_ae: float = 0.40
    weight_iforest: float = 0.15
    weight_hbos: float = 0.12
    weight_statistical: float = 0.10
    weight_copod: float = 0.10
    weight_ecod: float = 0.08
    weight_ngram: float = 0.05
    
    # Correlation parameters
    time_window_seconds: int = 300
    baseline_window_hours: int = 24
    context_window_seconds: int = 600
    ngram_size: int = 3
    min_chain_size: int = 3
    rarity_threshold: float = 0.95
    
    class Config:
        env_file = ".env"
        case_sensitive = False
    
    @property
    def ml_features_list(self) -> List[str]:
        """Convert comma-separated string to list"""
        return [f.strip() for f in self.ml_features.split(',')]
    
    @property
    def weights_dict(self) -> dict:
        """Get ensemble weights as dictionary"""
        return {
            "ae": self.weight_ae,
            "iforest": self.weight_iforest,
            "hbos": self.weight_hbos,
            "statistical": self.weight_statistical,
            "copod": self.weight_copod,
            "ecod": self.weight_ecod,
            "ngram": self.weight_ngram
        }


settings = Settings()
