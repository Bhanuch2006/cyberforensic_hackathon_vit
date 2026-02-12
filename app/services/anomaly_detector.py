"""
Anomaly Detection Service - Module 1
Inference-only (no training)
"""
import pandas as pd
import numpy as np
import torch
from sklearn.ensemble import IsolationForest
from collections import Counter
from scipy import stats
from pathlib import Path
from datetime import datetime
import json
from typing import Dict, Tuple

from app.core.config import settings
from app.core.model_loader import model_loader
from app.core.file_manager import file_manager


# PyOD fallback implementations
class SimpleECOD:
    def __init__(self):
        self.decision_scores_ = None
    
    def fit(self, X):
        n_samples, n_features = X.shape
        scores_per_feature = np.zeros((n_samples, n_features))
        
        for i in range(n_features):
            sorted_indices = np.argsort(X[:, i])
            ranks = np.empty_like(sorted_indices)
            ranks[sorted_indices] = np.arange(n_samples)
            left_prob = ranks / n_samples
            right_prob = 1 - left_prob
            tail_prob = np.minimum(left_prob, right_prob)
            scores_per_feature[:, i] = tail_prob
        
        log_probs = np.log(scores_per_feature + 1e-10)
        self.decision_scores_ = -np.sum(log_probs, axis=1)
        return self


class SimpleHBOS:
    def __init__(self, n_bins=10):
        self.n_bins = n_bins
        self.decision_scores_ = None
    
    def fit(self, X):
        n_samples, n_features = X.shape
        scores_per_feature = np.zeros((n_samples, n_features))
        
        for i in range(n_features):
            hist, bin_edges = np.histogram(X[:, i], bins=self.n_bins, density=True)
            bin_indices = np.digitize(X[:, i], bin_edges[:-1]) - 1
            bin_indices = np.clip(bin_indices, 0, len(hist) - 1)
            densities = hist[bin_indices]
            scores_per_feature[:, i] = -np.log(densities + 1e-10)
        
        self.decision_scores_ = np.sum(scores_per_feature, axis=1)
        return self


class SimpleCOPOD:
    def __init__(self):
        self.decision_scores_ = None
    
    def fit(self, X):
        n_samples, n_features = X.shape
        copula_data = np.zeros_like(X)
        
        for i in range(n_features):
            copula_data[:, i] = stats.rankdata(X[:, i]) / n_samples
        
        left_tail = copula_data
        right_tail = 1 - copula_data
        tail_probs = np.minimum(left_tail, right_tail)
        log_probs = np.log(tail_probs + 1e-10)
        self.decision_scores_ = -np.sum(log_probs, axis=1)
        return self


# Try PyOD, fallback to manual
try:
    from pyod.models.ecod import ECOD
    from pyod.models.hbos import HBOS
    from pyod.models.copod import COPOD
except ImportError:
    ECOD = SimpleECOD
    HBOS = SimpleHBOS
    COPOD = SimpleCOPOD


class AnomalyDetectionService:
    """Anomaly detection using pre-trained ensemble models"""
    
    def __init__(self):
        self.weights = settings.weights_dict
        self.ml_features = settings.ml_features_list
        self.device = model_loader.get_device()
    
    def normalize_score(self, scores: np.ndarray) -> np.ndarray:
        """Min-Max normalization"""
        min_s, max_s = scores.min(), scores.max()
        return (scores - min_s) / (max_s - min_s) if max_s > min_s else scores
    
    async def detect_anomalies(self, input_file: str, threshold: float = None) -> Dict:
        """
        Run anomaly detection on input data (INFERENCE ONLY)
        
        Args:
            input_file: Path to input CSV
            threshold: Custom threshold (if None, use default 0.5)
        
        Returns:
            Dictionary with output files and statistics
        """
        print(f"\n{'='*70}")
        print("🔍 ForensIQ - Anomaly Detection (Inference Mode)")
        print(f"{'='*70}")
        
        # Load data
        print(f"\n📂 Loading data from: {input_file}")
        df = pd.read_csv(input_file, encoding='utf-8', low_memory=False)
        print(f"✅ Loaded {len(df):,} events")
        
        # Prepare features
        print(f"\n🔧 Preparing features...")
        available_features = [f for f in self.ml_features if f in df.columns]
        print(f"   Using {len(available_features)} features: {available_features}")
        
        X = df[available_features].fillna(0).replace([np.inf, -np.inf], 0).values
        
        # Load scaler and transform
        scaler = model_loader.load_scaler()
        X_scaled = scaler.transform(X)
        print(f"✅ Features ready: {X_scaled.shape}")
        
        # Run all detection components
        print(f"\n{'='*70}")
        print("🔧 Running Detection Components (Inference)")
        print(f"{'='*70}")
        
        component_scores = {}
        
        # 1. Autoencoder
        print("\n1️⃣ Autoencoder (inference)...")
        ae_model = model_loader.load_autoencoder(X_scaled.shape[1])
        with torch.no_grad():
            X_tensor = torch.FloatTensor(X_scaled).to(self.device)
            X_recon = ae_model(X_tensor).cpu().numpy()
            ae_errors = np.mean((X_scaled - X_recon) ** 2, axis=1)
        component_scores['ae'] = ae_errors
        print("   ✅ Done")
        
        # 2. Isolation Forest
        print("2️⃣ Isolation Forest (inference)...")
        iforest = model_loader.load_iforest()
        component_scores['iforest'] = -iforest.score_samples(X_scaled)
        print("   ✅ Done")
        
        # 3. HBOS (fast, can retrain on-the-fly)
        print("3️⃣ HBOS...")
        hbos = HBOS() if hasattr(HBOS, '__module__') else HBOS(n_bins=10)
        hbos.fit(X_scaled)
        component_scores['hbos'] = hbos.decision_scores_
        print("   ✅ Done")
        
        # 4. Statistical baseline
        print("4️⃣ Statistical baseline...")
        if 'proto' in df.columns:
            stat_scores = np.zeros(len(X_scaled))
            for proto in df['proto'].unique():
                proto_mask = df['proto'] == proto
                proto_data = X_scaled[proto_mask]
                if len(proto_data) > 10:
                    mean = proto_data.mean(axis=0)
                    std = proto_data.std(axis=0) + 1e-6
                    z_scores = np.abs((proto_data - mean) / std)
                    stat_scores[proto_mask] = z_scores.max(axis=1)
        else:
            mean = X_scaled.mean(axis=0)
            std = X_scaled.std(axis=0) + 1e-6
            z_scores = np.abs((X_scaled - mean) / std)
            stat_scores = z_scores.max(axis=1)
        component_scores['statistical'] = stat_scores
        print("   ✅ Done")
        
        # 5. COPOD
        print("5️⃣ COPOD...")
        copod = COPOD()
        copod.fit(X_scaled)
        component_scores['copod'] = copod.decision_scores_
        print("   ✅ Done")
        
        # 6. ECOD
        print("6️⃣ ECOD...")
        ecod = ECOD()
        ecod.fit(X_scaled)
        component_scores['ecod'] = ecod.decision_scores_
        print("   ✅ Done")
        
        # 7. N-gram sequences
        print("7️⃣ N-gram sequences...")
        ngram_scores = self._compute_ngram_scores(df)
        component_scores['ngram'] = ngram_scores
        print("   ✅ Done")
        
        # Ensemble scoring
        print(f"\n{'='*70}")
        print("🔀 Creating Ensemble")
        print(f"{'='*70}")
        
        normalized_scores = {
            name: self.normalize_score(scores)
            for name, scores in component_scores.items()
        }
        
        ensemble_score = sum(
            self.weights[name] * normalized_scores[name]
            for name in self.weights.keys()
        )
        
        # Apply threshold
        if threshold is None:
            threshold = 0.5  # Default threshold
        
        y_pred = (ensemble_score >= threshold).astype(int)
        
        print(f"\n✅ Threshold: {threshold:.4f}")
        print(f"   Anomalies detected: {y_pred.sum():,} ({y_pred.sum()/len(y_pred)*100:.2f}%)")
        
        # Save results
        return await self._save_results(df, ensemble_score, y_pred, normalized_scores, threshold)
    
    def _compute_ngram_scores(self, df: pd.DataFrame) -> np.ndarray:
        """Compute N-gram rarity scores"""
        if not all(col in df.columns for col in ['proto', 'state', 'spkts', 'srcip']):
            return np.zeros(len(df))
        
        pkt_bins = pd.cut(df['spkts'], bins=[0, 10, 100, 1000, np.inf],
                          labels=['tiny', 'small', 'med', 'large']).astype(str)
        signatures = df['proto'].astype(str) + "|" + df['state'].astype(str) + "|" + pkt_bins
        
        ngram_scores = np.zeros(len(df))
        for src_ip in df['srcip'].unique():
            ip_mask = df['srcip'] == src_ip
            ip_indices = np.where(ip_mask)[0]
            ip_sigs = signatures[ip_mask].tolist()
            
            if len(ip_sigs) > 1:
                bigrams = [f"{ip_sigs[i]}→{ip_sigs[i+1]}" for i in range(len(ip_sigs)-1)]
                global_freq = Counter(bigrams)
                total = sum(global_freq.values())
                
                for i, bigram in enumerate(bigrams):
                    if i < len(ip_indices):
                        freq = global_freq[bigram]
                        rarity = -np.log(freq / total) if total > 0 else 0
                        ngram_scores[ip_indices[i]] = rarity
        
        return ngram_scores
    
    async def _save_results(self, df: pd.DataFrame, ensemble_score: np.ndarray,
                           y_pred: np.ndarray, normalized_scores: Dict,
                           threshold: float) -> Dict:
        """Save detection results to files"""
        print(f"\n{'='*70}")
        print("💾 Saving Results")
        print(f"{'='*70}")
        
        timestamp = file_manager.generate_timestamp()
        
        # Full results
        results_df = df.copy()
        results_df['anomaly_score'] = ensemble_score
        results_df['is_anomaly'] = y_pred
        
        # Add component scores
        for name, scores in normalized_scores.items():
            results_df[f'score_{name}'] = scores
        
        # Save full results
        results_file = file_manager.get_output_path(f"forensiq_results_{timestamp}.csv")
        results_df.to_csv(results_file, index=False)
        print(f"✅ Full results: {results_file.name}")
        
        # Save anomalies only
        anomaly_df = results_df[results_df['is_anomaly'] == 1][[
            'srcip', 'dstip', 'sport', 'dsport', 'proto', 'state',
            'Stime' if 'Stime' in df.columns else 'stime',
            'anomaly_score', 'sbytes', 'dbytes'
        ]].copy()
        
        anomalies_file = file_manager.get_output_path(f"anomalies_only_{timestamp}.csv")
        anomaly_df.to_csv(anomalies_file, index=False)
        print(f"✅ Anomalies only: {anomalies_file.name}")
        
        # Save metadata
        metadata = {
            "timestamp": timestamp,
            "model_config": "Config4_HBOS_COPOD",
            "weights": self.weights,
            "features": self.ml_features,
            "threshold": float(threshold),
            "total_events": len(df),
            "anomalies_detected": int(y_pred.sum()),
            "anomaly_rate": float(y_pred.sum() / len(df))
        }
        
        metadata_file = file_manager.save_metadata(
            metadata, f"metadata_{timestamp}.json"
        )
        print(f"✅ Metadata: {Path(metadata_file).name}")
        
        # Register files
        file_manager.register_file("forensiq_results", str(results_file))
        file_manager.register_file("anomalies_only", str(anomalies_file))
        file_manager.register_file("metadata", metadata_file)
        
        return {
            "output_files": {
                "forensiq_results": str(results_file),
                "anomalies_only": str(anomalies_file),
                "metadata": metadata_file
            },
            "statistics": {
                "total_events": len(df),
                "anomalies_detected": int(y_pred.sum()),
                "anomaly_rate": float(y_pred.sum() / len(df)),
                "threshold": float(threshold)
            }
        }


# Singleton instance
anomaly_detection_service = AnomalyDetectionService()
