"""
Correlation Engine Service - Module 2
Hybrid correlation with context and baseline analysis
"""
import pandas as pd
import numpy as np
from datetime import datetime
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Optional, Set
import json
from pathlib import Path

from app.core.config import settings
from app.core.file_manager import file_manager


class HybridCorrelationEngine:
    """
    Advanced correlation engine with hybrid approach:
    1. Load full dataset for baseline establishment
    2. Use anomalies as trigger points
    3. Analyze surrounding context (normal + anomaly events)
    4. Detect gradual escalation patterns
    5. Calculate baseline deviation scores
    """
    
    def __init__(self):
        self.time_window = settings.time_window_seconds
        self.baseline_window = settings.baseline_window_hours * 3600
        self.context_window = settings.context_window_seconds
        self.ngram_size = settings.ngram_size
        self.min_chain_size = settings.min_chain_size
        self.rarity_threshold = settings.rarity_threshold
        
        # Data storage
        self.full_df = None
        self.anomaly_df = None
        self.anomaly_indices = set()
        
        # N-gram baseline
        self.ngram_frequencies = Counter()
        self.total_ngrams = 0
        
        # Baseline cache
        self.baseline_cache = {}
        
        # Statistics
        self.stats = {
            'total_events': 0,
            'total_anomalies': 0,
            'unique_attackers': 0,
            'chains_created': 0,
            'chains_merged': 0,
            'patterns_detected': defaultdict(int),
            'escalation_detected': 0,
            'baseline_deviations': 0
        }
    
    async def correlate(self, full_results_file: str, anomaly_file: str) -> Dict:
        """
        Main correlation pipeline
        
        Args:
            full_results_file: forensiq_results_*.csv
            anomaly_file: anomalies_only_*.csv
        
        Returns:
            Dictionary with output files and statistics
        """
        print(f"\n{'='*80}")
        print("🔗 ForensIQ Hybrid Correlation Engine")
        print("    Context-Aware Attack Chain Detection")
        print(f"{'='*80}")
        
        # Load data
        self._load_data(full_results_file, anomaly_file)
        
        # Build n-gram baseline
        self._build_ngram_baseline()
        
        # Correlate with context
        chains = self._correlate_hybrid()
        
        # Merge overlaps
        final_chains = self._merge_overlapping_chains(chains)
        
        # Generate summary
        summary_df = self._generate_summary_table(final_chains)
        
        # Print statistics
        self._print_statistics(final_chains, summary_df)
        
        # Save results
        return await self._save_results(final_chains, summary_df)
    
    def _load_data(self, full_results_file: str, anomaly_file: str):
        """Load both full dataset and anomalies"""
        print(f"\n{'='*80}")
        print("📥 Loading Data for Hybrid Correlation")
        print(f"{'='*80}")
        
        # Load full results
        print(f"\n1️⃣ Loading full dataset: {Path(full_results_file).name}")
        self.full_df = pd.read_csv(full_results_file, low_memory=False)
        
        # Standardize column names
        if 'Stime' in self.full_df.columns and 'stime' not in self.full_df.columns:
            self.full_df['stime'] = self.full_df['Stime']
        
        self.full_df = self.full_df.sort_values('stime').reset_index(drop=True)
        self.stats['total_events'] = len(self.full_df)
        print(f"   ✅ Loaded {len(self.full_df):,} total events")
        
        # Load anomalies
        print(f"\n2️⃣ Loading anomalies: {Path(anomaly_file).name}")
        self.anomaly_df = pd.read_csv(anomaly_file, low_memory=False)
        
        if 'Stime' in self.anomaly_df.columns and 'stime' not in self.anomaly_df.columns:
            self.anomaly_df['stime'] = self.anomaly_df['Stime']
        
        self.stats['total_anomalies'] = len(self.anomaly_df)
        print(f"   ✅ Loaded {len(self.anomaly_df):,} anomalies")
        
        # Build anomaly index
        print("\n3️⃣ Building anomaly index...")
        self.anomaly_indices = self._build_anomaly_index()
        print(f"   ✅ Indexed {len(self.anomaly_indices):,} anomaly events")
        
        # Mark anomalies in full dataset
        self.full_df['is_detected_anomaly'] = self.full_df.index.isin(self.anomaly_indices)
        
        # Statistics
        time_range = (
            datetime.fromtimestamp(self.full_df['stime'].min()).strftime('%Y-%m-%d %H:%M'),
            datetime.fromtimestamp(self.full_df['stime'].max()).strftime('%Y-%m-%d %H:%M')
        )
        self.stats['unique_attackers'] = self.anomaly_df['srcip'].nunique()
        
        print(f"\n📊 Dataset Summary:")
        print(f"   Time range: {time_range[0]} to {time_range[1]}")
        print(f"   Unique attacker IPs: {self.stats['unique_attackers']:,}")
        print(f"   Anomaly rate: {self.stats['total_anomalies']/self.stats['total_events']*100:.2f}%")
    
    def _build_anomaly_index(self) -> Set[int]:
        """Build index mapping anomalies to full dataset"""
        anomaly_set = set()
        
        anomaly_keys = set(
            tuple(row) for row in
            self.anomaly_df[['srcip', 'dstip', 'stime']].values
        )
        
        for idx, row in self.full_df.iterrows():
            key = (row['srcip'], row['dstip'], row['stime'])
            if key in anomaly_keys:
                anomaly_set.add(idx)
        
        return anomaly_set
    
    def _create_event_signature(self, row: pd.Series) -> str:
        """Create event signature for n-gram analysis"""
        if 'anomaly_score' in row.index:
            score = row['anomaly_score']
        else:
            score = 0.5
        
        if score >= 0.9:
            level = 'critical'
        elif score >= 0.7:
            level = 'high'
        elif score >= 0.5:
            level = 'medium'
        else:
            level = 'low'
        
        proto = str(row.get('proto', 'unknown')).lower()
        state = str(row.get('state', 'unknown')).upper()
        
        return f"{proto}|{state}|{level}"
    
    def _build_ngram_baseline(self):
        """Build n-gram frequency baseline from full dataset"""
        print(f"\n{'='*80}")
        print("🧬 Building N-gram Baseline from Full Dataset")
        print(f"{'='*80}")
        
        print(f"   Creating signatures for {len(self.full_df):,} events...")
        signatures = self.full_df.apply(self._create_event_signature, axis=1).tolist()
        
        print(f"   Extracting {self.ngram_size}-grams...")
        ngrams = self._extract_ngrams(signatures)
        
        self.ngram_frequencies = Counter(ngrams)
        self.total_ngrams = len(ngrams)
        
        unique_patterns = len(self.ngram_frequencies)
        avg_frequency = self.total_ngrams / unique_patterns if unique_patterns > 0 else 0
        
        print(f"\n   ✅ Baseline complete:")
        print(f"      Unique {self.ngram_size}-grams: {unique_patterns:,}")
        print(f"      Total sequences: {self.total_ngrams:,}")
        print(f"      Average frequency: {avg_frequency:.2f}")
        
        print(f"\n   📊 Top 5 most common patterns:")
        for pattern, count in self.ngram_frequencies.most_common(5):
            pattern_str = ' → '.join(pattern)
            freq_pct = (count / self.total_ngrams) * 100
            print(f"      {pattern_str}: {count} ({freq_pct:.2f}%)")
    
    def _extract_ngrams(self, signatures: List[str]) -> List[Tuple[str, ...]]:
        """Extract n-gram sequences"""
        if len(signatures) < self.ngram_size:
            return []
        
        ngrams = []
        for i in range(len(signatures) - self.ngram_size + 1):
            ngram = tuple(signatures[i:i + self.ngram_size])
            ngrams.append(ngram)
        
        return ngrams
    
    def _build_baseline_for_attacker(self, attacker_ip: str, current_time: int) -> Optional[Dict]:
        """Build behavioral baseline for an attacker"""
        cache_key = f"{attacker_ip}_{current_time}"
        if cache_key in self.baseline_cache:
            return self.baseline_cache[cache_key]
        
        baseline_start = current_time - self.baseline_window
        
        baseline_traffic = self.full_df[
            (self.full_df['srcip'] == attacker_ip) &
            (self.full_df['stime'] >= baseline_start) &
            (self.full_df['stime'] < current_time)
        ]
        
        if len(baseline_traffic) < 5:
            return None
        
        total_hours = (current_time - baseline_start) / 3600
        
        baseline = {
            'total_events': len(baseline_traffic),
            'events_per_hour': len(baseline_traffic) / total_hours,
            'unique_targets': baseline_traffic['dstip'].nunique(),
            'target_diversity': baseline_traffic['dstip'].nunique() / len(baseline_traffic),
            'unique_ports': baseline_traffic['dsport'].nunique(),
            'common_ports': baseline_traffic['dsport'].value_counts().head(5).to_dict(),
            'protocols': baseline_traffic['proto'].value_counts().to_dict(),
            'states': baseline_traffic['state'].value_counts().to_dict(),
            'avg_sbytes': baseline_traffic['sbytes'].mean(),
            'avg_dbytes': baseline_traffic['dbytes'].mean(),
            'total_bytes': baseline_traffic['sbytes'].sum() + baseline_traffic['dbytes'].sum(),
            'avg_bytes_per_event': (baseline_traffic['sbytes'].sum() + baseline_traffic['dbytes'].sum()) / len(baseline_traffic)
        }
        
        self.baseline_cache[cache_key] = baseline
        return baseline
    
    def _detect_gradual_escalation(self, events: pd.DataFrame) -> Dict:
        """Detect gradual escalation from normal to anomalous behavior"""
        if len(events) < 5:
            return {'is_escalating': False, 'escalation_rate': 0.0}
        
        events = events.sort_values('stime')
        
        chunk_size = len(events) // 5
        if chunk_size == 0:
            return {'is_escalating': False, 'escalation_rate': 0.0}
        
        anomaly_ratios = []
        for i in range(5):
            start_idx = i * chunk_size
            end_idx = start_idx + chunk_size if i < 4 else len(events)
            chunk = events.iloc[start_idx:end_idx]
            
            anomaly_ratio = chunk['is_detected_anomaly'].mean()
            anomaly_ratios.append(anomaly_ratio)
        
        is_escalating = all(
            anomaly_ratios[i] <= anomaly_ratios[i+1]
            for i in range(len(anomaly_ratios)-1)
        )
        
        if is_escalating and anomaly_ratios[0] < anomaly_ratios[-1]:
            escalation_rate = (anomaly_ratios[-1] - anomaly_ratios[0]) / 5
        else:
            escalation_rate = 0.0
        
        return {
            'is_escalating': is_escalating,
            'escalation_rate': escalation_rate,
            'anomaly_progression': anomaly_ratios,
            'start_ratio': anomaly_ratios[0],
            'end_ratio': anomaly_ratios[-1]
        }
    
    def _calculate_baseline_deviation(self, current_metrics: Dict, baseline: Optional[Dict]) -> Dict:
        """Calculate deviation from baseline behavior"""
        if baseline is None:
            return {
                'deviation_score': 0.0,
                'has_baseline': False,
                'deviations': {}
            }
        
        deviations = {}
        deviation_score = 0.0
        
        # Event frequency deviation
        freq_ratio = current_metrics['events_per_hour'] / baseline['events_per_hour']
        if freq_ratio > 3:
            deviations['frequency'] = {
                'current': current_metrics['events_per_hour'],
                'baseline': baseline['events_per_hour'],
                'ratio': freq_ratio,
                'severity': 'HIGH' if freq_ratio > 10 else 'MEDIUM'
            }
            deviation_score += 0.3
        
        # Target diversity deviation
        if baseline['target_diversity'] > 0:
            target_ratio = current_metrics['target_diversity'] / baseline['target_diversity']
            if target_ratio > 2:
                deviations['target_diversity'] = {
                    'current': current_metrics['target_diversity'],
                    'baseline': baseline['target_diversity'],
                    'ratio': target_ratio,
                    'severity': 'HIGH' if target_ratio > 5 else 'MEDIUM'
                }
                deviation_score += 0.3
        
        # New port usage
        current_ports = set(current_metrics.get('ports', []))
        baseline_ports = set(baseline['common_ports'].keys())
        new_ports = current_ports - baseline_ports
        
        if len(new_ports) > 3:
            deviations['new_ports'] = {
                'count': len(new_ports),
                'ports': list(new_ports)[:10],
                'severity': 'HIGH' if len(new_ports) > 10 else 'MEDIUM'
            }
            deviation_score += 0.2
        
        # Data volume deviation
        if baseline['avg_bytes_per_event'] > 0:
            byte_ratio = current_metrics['avg_bytes_per_event'] / baseline['avg_bytes_per_event']
            if byte_ratio > 5:
                deviations['data_volume'] = {
                    'current': current_metrics['avg_bytes_per_event'],
                    'baseline': baseline['avg_bytes_per_event'],
                    'ratio': byte_ratio,
                    'severity': 'HIGH' if byte_ratio > 20 else 'MEDIUM'
                }
                deviation_score += 0.2
        
        return {
            'deviation_score': min(1.0, deviation_score),
            'has_baseline': True,
            'deviations': deviations,
            'baseline_window_hours': self.baseline_window / 3600
        }
    
    def _correlate_hybrid(self) -> List[Dict]:
        """Main hybrid correlation logic"""
        print(f"\n{'='*80}")
        print("🔗 Hybrid Correlation: Context + Baseline Analysis")
        print(f"{'='*80}")
        
        chains = []
        chain_id = 1
        
        attacker_groups = self.anomaly_df.groupby('srcip')
        
        print(f"\n   Processing {len(attacker_groups)} unique attackers...")
        
        for attacker_ip, anomaly_group in attacker_groups:
            if len(anomaly_group) < self.min_chain_size:
                continue
            
            anomaly_group = anomaly_group.sort_values('stime')
            first_anomaly_time = anomaly_group['stime'].min()
            
            baseline = self._build_baseline_for_attacker(attacker_ip, first_anomaly_time)
            
            window_start = 0
            
            while window_start < len(anomaly_group):
                window_end_time = anomaly_group.iloc[window_start]['stime'] + self.time_window
                
                window_anomalies = anomaly_group[
                    anomaly_group['stime'] <= window_end_time
                ].iloc[window_start:]
                
                if len(window_anomalies) < self.min_chain_size:
                    window_start += 1
                    continue
                
                context_start = window_anomalies['stime'].min() - self.context_window
                context_end = window_anomalies['stime'].max() + self.context_window
                
                context_events = self.full_df[
                    (self.full_df['srcip'] == attacker_ip) &
                    (self.full_df['stime'] >= context_start) &
                    (self.full_df['stime'] <= context_end)
                ].copy()
                
                if len(context_events) >= self.min_chain_size:
                    chain = self._create_hybrid_chain(
                        context_events,
                        attacker_ip,
                        f"CHAIN_{chain_id:04d}",
                        baseline
                    )
                    
                    if chain:
                        chains.append(chain)
                        chain_id += 1
                
                window_start += max(1, len(window_anomalies) // 2)
        
        self.stats['chains_created'] = len(chains)
        print(f"\n   ✅ Created {len(chains)} attack chains with context")
        
        return chains
    
    def _create_hybrid_chain(self, events: pd.DataFrame, attacker_ip: str,
                            chain_id: str, baseline: Optional[Dict]) -> Optional[Dict]:
        """Create attack chain with hybrid analysis"""
        events = events.sort_values('stime')
        
        total_hours = (events['stime'].max() - events['stime'].min()) / 3600
        if total_hours == 0:
            total_hours = 0.01
        
        current_metrics = {
            'events_per_hour': len(events) / total_hours,
            'target_diversity': events['dstip'].nunique() / len(events),
            'ports': events['dsport'].unique().tolist(),
            'avg_bytes_per_event': (events['sbytes'].sum() + events['dbytes'].sum()) / len(events)
        }
        
        deviation_analysis = self._calculate_baseline_deviation(current_metrics, baseline)
        if deviation_analysis['deviation_score'] > 0.3:
            self.stats['baseline_deviations'] += 1
        
        escalation_analysis = self._detect_gradual_escalation(events)
        if escalation_analysis['is_escalating']:
            self.stats['escalation_detected'] += 1
        
        signatures = events.apply(self._create_event_signature, axis=1).tolist()
        ngrams = self._extract_ngrams(signatures)
        ngram_rarity = self._calculate_ngram_rarity(ngrams)
        rare_patterns = self._identify_rare_patterns(ngrams)
        
        attack_pattern = self._detect_attack_pattern(events)
        self.stats['patterns_detected'][attack_pattern] += 1
        
        severity = self._calculate_hybrid_severity(
            events,
            ngram_rarity,
            rare_patterns,
            deviation_analysis,
            escalation_analysis
        )
        
        normal_events = events[~events['is_detected_anomaly']]
        anomaly_events = events[events['is_detected_anomaly']]
        
        chain = {
            'chain_id': chain_id,
            'severity': round(severity, 2),
            'severity_level': self._classify_severity(severity),
            
            'attacker_ip': attacker_ip,
            'target_ips': events['dstip'].unique().tolist(),
            'num_targets': events['dstip'].nunique(),
            
            'start_time': int(events['stime'].min()),
            'end_time': int(events['stime'].max()),
            'duration': int(events['stime'].max() - events['stime'].min()),
            
            'total_events': len(events),
            'anomaly_events': len(anomaly_events),
            'normal_events': len(normal_events),
            'anomaly_ratio': len(anomaly_events) / len(events),
            
            'attack_pattern': attack_pattern,
            
            'avg_anomaly_score': float(events['anomaly_score'].mean()) if 'anomaly_score' in events.columns else 0.0,
            'max_anomaly_score': float(events['anomaly_score'].max()) if 'anomaly_score' in events.columns else 0.0,
            
            'ngram_rarity': round(ngram_rarity, 4),
            'rare_patterns': rare_patterns[:5],
            'total_rare_patterns': len(rare_patterns),
            
            'baseline_deviation': deviation_analysis,
            'escalation_analysis': escalation_analysis,
            
            'protocols': events['proto'].value_counts().to_dict(),
            'states': events['state'].value_counts().to_dict(),
            'unique_dst_ports': events['dsport'].nunique(),
            'common_ports': events['dsport'].value_counts().head(10).to_dict(),
            'total_bytes': int(events['sbytes'].sum() + events['dbytes'].sum()),
            
            'sample_normal_events': normal_events[[
                'stime', 'srcip', 'dstip', 'sport', 'dsport',
                'proto', 'state', 'sbytes', 'dbytes'
            ]].head(10).to_dict('records') if len(normal_events) > 0 else [],
            
            'anomaly_events_detail': anomaly_events[[
                'stime', 'srcip', 'dstip', 'sport', 'dsport',
                'proto', 'state', 'sbytes', 'dbytes', 'anomaly_score'
            ]].to_dict('records') if 'anomaly_score' in anomaly_events.columns else []
        }
        
        return chain
    
    def _calculate_ngram_rarity(self, ngrams: List[Tuple[str, ...]]) -> float:
        """Calculate rarity score for n-gram sequence"""
        if not ngrams or self.total_ngrams == 0:
            return 0.0
        
        rarity_scores = []
        for ngram in ngrams:
            freq = self.ngram_frequencies.get(ngram, 0)
            normalized_freq = freq / self.total_ngrams
            rarity = 1.0 - normalized_freq
            rarity_scores.append(rarity)
        
        return np.mean(rarity_scores)
    
    def _identify_rare_patterns(self, ngrams: List[Tuple[str, ...]]) -> List[Dict]:
        """Identify rare n-gram patterns"""
        rare_patterns = []
        
        for ngram in ngrams:
            freq = self.ngram_frequencies.get(ngram, 0)
            freq_ratio = freq / self.total_ngrams if self.total_ngrams > 0 else 0
            rarity = 1.0 - freq_ratio
            
            if rarity >= self.rarity_threshold:
                pattern_str = ' → '.join(ngram)
                rare_patterns.append({
                    'pattern': pattern_str,
                    'rarity': round(rarity, 4),
                    'frequency': freq,
                    'percentile': round(rarity * 100, 2)
                })
        
        rare_patterns.sort(key=lambda x: x['rarity'], reverse=True)
        return rare_patterns
    
    def _calculate_hybrid_severity(self, events: pd.DataFrame, ngram_rarity: float,
                                   rare_patterns: List[Dict], deviation_analysis: Dict,
                                   escalation_analysis: Dict) -> float:
        """Enhanced severity calculation"""
        severity = 0.0
        
        # Event count (15 points)
        event_count = len(events)
        severity += min(15, (event_count / 50) * 15)
        
        # Max anomaly score (20 points)
        if 'anomaly_score' in events.columns:
            max_score = events['anomaly_score'].max()
            severity += max_score * 20
        
        # N-gram rarity (15 points)
        severity += ngram_rarity * 15
        
        # Target diversity (10 points)
        num_targets = events['dstip'].nunique()
        severity += min(10, (num_targets / 10) * 10)
        
        # Data volume (10 points)
        total_bytes = events['sbytes'].sum() + events['dbytes'].sum()
        severity += min(10, (total_bytes / 10000000) * 10)
        
        # Rare pattern bonus (10 points)
        if rare_patterns:
            top_rarities = [p['rarity'] for p in rare_patterns[:3]]
            severity += np.mean(top_rarities) * 10
        
        # Baseline deviation (15 points)
        if deviation_analysis['has_baseline']:
            severity += deviation_analysis['deviation_score'] * 15
        
        # Escalation bonus (5 points)
        if escalation_analysis['is_escalating']:
            severity += escalation_analysis['escalation_rate'] * 50
        
        return min(100.0, severity)
    
    def _detect_attack_pattern(self, events: pd.DataFrame) -> str:
        """Detect attack pattern from behavioral signatures"""
        num_events = len(events)
        num_targets = events['dstip'].nunique()
        num_ports = events['dsport'].nunique()
        duration = events['stime'].max() - events['stime'].min()
        total_bytes = events['sbytes'].sum() + events['dbytes'].sum()
        
        # Port scan
        if num_ports >= 10 and num_targets <= 5 and duration <= 120:
            return 'PORT_SCAN'
        
        # Brute force
        auth_ports = events['dsport'].isin([22, 3389, 21, 23])
        if num_events >= 20 and auth_ports.any() and num_targets <= 2:
            return 'BRUTE_FORCE'
        
        # Lateral movement
        if num_targets >= 3 and duration >= 300:
            return 'LATERAL_MOVEMENT'
        
        # Data exfiltration
        if total_bytes >= 1000000 and duration >= 120:
            return 'DATA_EXFILTRATION'
        
        # DDoS
        if num_events >= 100 and duration <= 120 and num_targets == 1:
            return 'DDOS'
        
        # Reconnaissance
        if num_ports >= 5 and total_bytes < 100000:
            return 'RECONNAISSANCE'
        
        return 'UNKNOWN'
    
    def _classify_severity(self, severity: float) -> str:
        """Classify severity into levels"""
        if severity >= 75:
            return 'CRITICAL'
        elif severity >= 50:
            return 'HIGH'
        elif severity >= 25:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _merge_overlapping_chains(self, chains: List[Dict]) -> List[Dict]:
        """Merge temporally overlapping chains"""
        print("\n🔗 Merging overlapping chains...")
        
        if not chains:
            return []
        
        attacker_groups = defaultdict(list)
        for chain in chains:
            attacker_groups[chain['attacker_ip']].append(chain)
        
        merged_chains = []
        merge_count = 0
        
        for attacker_ip, attacker_chains in attacker_groups.items():
            attacker_chains.sort(key=lambda x: x['start_time'])
            
            current_chain = attacker_chains[0]
            
            for next_chain in attacker_chains[1:]:
                time_gap = next_chain['start_time'] - current_chain['end_time']
                
                if time_gap <= 60:
                    current_chain = self._merge_two_chains(current_chain, next_chain)
                    merge_count += 1
                else:
                    merged_chains.append(current_chain)
                    current_chain = next_chain
            
            merged_chains.append(current_chain)
        
        self.stats['chains_merged'] = merge_count
        print(f"   ✅ Merged {merge_count} overlapping chains")
        print(f"   Final chain count: {len(merged_chains)}")
        
        return merged_chains
    
    def _merge_two_chains(self, chain1: Dict, chain2: Dict) -> Dict:
        """Merge two chains"""
        merged = chain1.copy()
        
        merged['start_time'] = min(chain1['start_time'], chain2['start_time'])
        merged['end_time'] = max(chain1['end_time'], chain2['end_time'])
        merged['duration'] = merged['end_time'] - merged['start_time']
        
        all_targets = set(chain1['target_ips'] + chain2['target_ips'])
        merged['target_ips'] = list(all_targets)
        merged['num_targets'] = len(all_targets)
        
        merged['total_events'] = chain1['total_events'] + chain2['total_events']
        merged['anomaly_events'] = chain1['anomaly_events'] + chain2['anomaly_events']
        merged['normal_events'] = chain1['normal_events'] + chain2['normal_events']
        merged['anomaly_ratio'] = merged['anomaly_events'] / merged['total_events']
        
        merged['avg_anomaly_score'] = (
            chain1['avg_anomaly_score'] * chain1['total_events'] +
            chain2['avg_anomaly_score'] * chain2['total_events']
        ) / merged['total_events']
        
        merged['max_anomaly_score'] = max(
            chain1['max_anomaly_score'],
            chain2['max_anomaly_score']
        )
        
        merged['severity'] = max(chain1['severity'], chain2['severity'])
        merged['severity_level'] = self._classify_severity(merged['severity'])
        
        merged['total_bytes'] = chain1['total_bytes'] + chain2['total_bytes']
        
        return merged
    
    def _generate_summary_table(self, chains: List[Dict]) -> pd.DataFrame:
        """Generate summary table"""
        summary_data = []
        
        for chain in chains:
            summary_data.append({
                'chain_id': chain['chain_id'],
                'severity_level': chain['severity_level'],
                'severity_score': chain['severity'],
                'attacker_ip': chain['attacker_ip'],
                'num_targets': chain['num_targets'],
                'total_events': chain['total_events'],
                'anomaly_events': chain['anomaly_events'],
                'normal_events': chain['normal_events'],
                'anomaly_ratio': round(chain['anomaly_ratio'], 3),
                'attack_pattern': chain['attack_pattern'],
                'start_time': datetime.fromtimestamp(chain['start_time']).strftime('%Y-%m-%d %H:%M:%S'),
                'duration_sec': chain['duration'],
                'avg_anomaly_score': chain['avg_anomaly_score'],
                'ngram_rarity': chain['ngram_rarity'],
                'baseline_deviation': chain['baseline_deviation']['deviation_score'],
                'is_escalating': chain['escalation_analysis']['is_escalating'],
                'total_bytes': chain['total_bytes']
            })
        
        df = pd.DataFrame(summary_data)
        df = df.sort_values('severity_score', ascending=False).reset_index(drop=True)
        
        return df
    
    def _print_statistics(self, chains: List[Dict], summary_df: pd.DataFrame):
        """Print statistics"""
        print(f"\n{'='*80}")
        print("📊 HYBRID CORRELATION ENGINE STATISTICS")
        print(f"{'='*80}")
        
        print(f"\n🔢 Processing Summary:")
        print(f"   Total events processed: {self.stats['total_events']:,}")
        print(f"   Total anomalies: {self.stats['total_anomalies']:,}")
        print(f"   Unique attackers: {self.stats['unique_attackers']:,}")
        print(f"   Preliminary chains created: {self.stats['chains_created']:,}")
        print(f"   Chains merged: {self.stats['chains_merged']:,}")
        print(f"   Final attack chains: {len(chains):,}")
        
        print(f"\n📈 Severity Distribution:")
        for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = len(summary_df[summary_df['severity_level'] == level])
            pct = (count / len(summary_df) * 100) if len(summary_df) > 0 else 0
            print(f"   {level:8s}: {count:4d} chains ({pct:5.1f}%)")
        
        print(f"\n🎯 Attack Pattern Distribution:")
        for pattern, count in self.stats['patterns_detected'].items():
            pct = (count / len(chains) * 100) if len(chains) > 0 else 0
            print(f"   {pattern:20s}: {count:4d} chains ({pct:5.1f}%)")
        
        print(f"\n🔍 Hybrid Features Detected:")
        print(f"   Chains with baseline deviation: {self.stats['baseline_deviations']:,}")
        print(f"   Chains with escalation pattern: {self.stats['escalation_detected']:,}")
    
    async def _save_results(self, chains: List[Dict], summary_df: pd.DataFrame) -> Dict:
        """Save results"""
        timestamp = file_manager.generate_timestamp()
        
        # Full chains (JSON)
        chains_file = file_manager.get_output_path(f"hybrid_attack_chains_{timestamp}.json")
        with open(chains_file, 'w') as f:
            json.dump(chains, f, indent=2)
        
        # Summary (CSV)
        summary_file = file_manager.get_output_path(f"hybrid_chain_summary_{timestamp}.csv")
        summary_df.to_csv(summary_file, index=False)
        
        # Statistics
        stats_file = file_manager.get_output_path(f"hybrid_correlation_stats_{timestamp}.json")
        stats_copy = self.stats.copy()
        stats_copy['patterns_detected'] = dict(stats_copy['patterns_detected'])
        with open(stats_file, 'w') as f:
            json.dump(stats_copy, f, indent=2)
        
        print(f"\n💾 Results saved:")
        print(f"   Full chains: {chains_file.name}")
        print(f"   Summary: {summary_file.name}")
        print(f"   Statistics: {stats_file.name}")
        
        # Register files
        file_manager.register_file("attack_chains", str(chains_file))
        file_manager.register_file("chain_summary", str(summary_file))
        file_manager.register_file("correlation_stats", str(stats_file))
        
        return {
            "output_files": {
                "attack_chains": str(chains_file),
                "chain_summary": str(summary_file),
                "statistics": str(stats_file)
            },
            "statistics": {
                "total_chains": len(chains),
                "unique_attackers": self.stats['unique_attackers'],
                "baseline_deviations": self.stats['baseline_deviations'],
                "escalations_detected": self.stats['escalation_detected']
            }
        }


# Singleton instance
correlation_engine = HybridCorrelationEngine()
