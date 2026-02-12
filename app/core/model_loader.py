"""
Model loading utilities
"""
import torch
import pickle
import torch.nn as nn
from pathlib import Path
from typing import Optional
from app.core.config import settings


class RobustAutoencoder(nn.Module):
    """Autoencoder architecture (same as notebook)"""
    def __init__(self, input_dim):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 32),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(32, 16),
            nn.ReLU(),
            nn.Linear(16, 8)
        )
        self.decoder = nn.Sequential(
            nn.Linear(8, 16),
            nn.ReLU(),
            nn.Linear(16, 32),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(32, input_dim)
        )
    
    def forward(self, x):
        z = self.encoder(x)
        x_recon = self.decoder(z)
        return x_recon


class ModelLoader:
    """Loads and caches pre-trained models"""
    
    def __init__(self):
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.autoencoder: Optional[RobustAutoencoder] = None
        self.iforest = None
        self.scaler = None
        self.hbos = None
        self.copod = None
        self.ecod = None
    
    def load_autoencoder(self, input_dim: int):
        """Load pre-trained autoencoder"""
        if self.autoencoder is None:
            model_path = Path(settings.autoencoder_path)
            if not model_path.exists():
                raise FileNotFoundError(f"Autoencoder model not found at {model_path}")
            
            self.autoencoder = RobustAutoencoder(input_dim).to(self.device)
            self.autoencoder.load_state_dict(torch.load(model_path, map_location=self.device))
            self.autoencoder.eval()
        
        return self.autoencoder
    
    def load_iforest(self):
        """Load pre-trained Isolation Forest"""
        if self.iforest is None:
            model_path = Path(settings.iforest_path)
            if not model_path.exists():
                raise FileNotFoundError(f"IsolationForest model not found at {model_path}")
            
            with open(model_path, 'rb') as f:
                self.iforest = pickle.load(f)
        
        return self.iforest
    
    def load_scaler(self):
        """Load pre-trained scaler"""
        if self.scaler is None:
            scaler_path = Path(settings.scaler_path)
            if not scaler_path.exists():
                raise FileNotFoundError(f"Scaler not found at {scaler_path}")
            
            with open(scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)
        
        return self.scaler
    
    def get_device(self):
        """Get PyTorch device"""
        return self.device


# Global model loader instance
model_loader = ModelLoader()
