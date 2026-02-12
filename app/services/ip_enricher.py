"""
IP Enrichment Service - Module 3
Ground truth IP reputation from UNSW dataset labels
"""
import pandas as pd
import json
from datetime import datetime
from pathlib import Path
from collections import Counter
from typing import Dict, Optional

from app.core.file_manager import file_manager


class IPEnrichmentService:
    """
    Enriches attack chains with ground truth IP reputation
    Uses UNSW dataset labels + behavior analysis
    """
    
    def __init__(self):
        self.ground_truth_reputation = {}
    
    async def enrich_chains(self, chains_file: str, dataset_file: str) -> Dict:
        """
        Enrich attack chains with IP reputation
        
        Args:
            chains_file: Path to attack chains JSON
            dataset_file: Path to UNSW dataset for ground truth
        
        Returns:
            Dictionary with output files and statistics
        """
        print(f"\n{'='*80}")
        print("🎯 Ground Truth IP Reputation Enrichment")
        print("   Using UNSW Dataset Labels + Behavior Analysis")
        print(f"{'='*80}")
        
        # Extract ground truth IP reputation
        self._extract_malicious_ips(dataset_file)
        
        # Load chains
        print(f"\n📥 Loading attack chains...")
        with open(chains_file, 'r') as f:
            chains = json.load(f)
        
        print(f"   ✅ Loaded {len(chains)} chains")
        
        # Enrich chains
        print(f"\n💎 Enriching chains with ground truth reputation...")
        
        enriched_count = 0
        for chain in chains:
            attacker_ip = chain['attacker_ip']
            
            # Get ground truth data
            ground_truth = self.ground_truth_reputation.get(attacker_ip, {})
            
            if ground_truth:
                # Calculate scores
                gt_score = ground_truth['abuse_score']
                behavior_score = self._calculate_behavior_score(chain)
                
                # Combined score (70% ground truth, 30% behavior)
                final_score = int((gt_score * 0.7) + (behavior_score * 0.3))
                
                # Create reputation entry
                chain['ip_reputation'] = {
                    'ip': attacker_ip,
                    'abuse_score': final_score,
                    'ground_truth_score': gt_score,
                    'behavior_score': behavior_score,
                    'total_records': ground_truth.get('total_records', 0),
                    'malicious_records': ground_truth.get('malicious_records', 0),
                    'malicious_ratio': ground_truth.get('malicious_ratio', 0),
                    'attack_types_detected': ground_truth.get('attack_types', {}),
                    'total_reports': ground_truth.get('malicious_records', 0),
                    'num_distinct_users': int(ground_truth.get('malicious_records', 0) * 0.3),
                    'severity': self._classify_severity(final_score),
                    'country_code': 'UNKNOWN',  # Can be enriched with GeoIP
                    'scoring_method': 'Ground Truth (70%) + Behavior (30%)',
                    'data_sources': ['UNSW Dataset Labels', 'Behavior Analysis'],
                    'enriched_at': datetime.now().isoformat()
                }
                enriched_count += 1
            else:
                # Fallback to behavior-only
                behavior_score = self._calculate_behavior_score(chain)
                
                chain['ip_reputation'] = {
                    'ip': attacker_ip,
                    'abuse_score': behavior_score,
                    'ground_truth_score': 0,
                    'behavior_score': behavior_score,
                    'total_records': 0,
                    'malicious_records': 0,
                    'malicious_ratio': 0,
                    'attack_types_detected': {},
                    'total_reports': 0,
                    'num_distinct_users': 0,
                    'severity': self._classify_severity(behavior_score),
                    'country_code': 'UNKNOWN',
                    'scoring_method': 'Behavior Analysis Only',
                    'data_sources': ['Behavior Analysis'],
                    'enriched_at': datetime.now().isoformat()
                }
        
        print(f"   ✅ Enriched {enriched_count}/{len(chains)} chains with ground truth data")
        
        # Print statistics
        self._print_statistics(chains)
        
        # Save results
        return await self._save_results(chains)
    
    def _extract_malicious_ips(self, dataset_file: str):
        """Extract malicious IPs from UNSW dataset using ground truth labels"""
        print(f"\n{'='*80}")
        print("🔍 Extracting Ground Truth IP Reputation from UNSW Dataset")
        print(f"{'='*80}")
        
        print(f"\n📥 Loading dataset: {Path(dataset_file).name}")
        df = pd.read_csv(dataset_file, low_memory=False)
        
        print(f"   ✅ Loaded {len(df):,} records")
        
        # Check for label column
        label_col = None
        for col in ['label', 'Label', 'attack_cat', 'Attack_cat']:
            if col in df.columns:
                label_col = col
                break
        
        if label_col is None:
            print("\n⚠️  No label column found. Using behavior-only scoring.")
            return
        
        print(f"\n✅ Found label column: '{label_col}'")
        print(f"   Unique labels: {df[label_col].nunique()}")
        
        # Analyze malicious IPs
        print("\n🔍 Analyzing attacker IPs (srcip)...")
        
        ip_reputation = {}
        
        for ip in df['srcip'].unique():
            ip_data = df[df['srcip'] == ip]
            total_records = len(ip_data)
            
            # Check if label indicates attack
            malicious_records = ip_data[
                (ip_data[label_col] != 'Normal') &
                (ip_data[label_col] != 0) &
                (ip_data[label_col] != '0')
            ]
            
            malicious_count = len(malicious_records)
            malicious_ratio = malicious_count / total_records if total_records > 0 else 0
            
            # Get attack categories
            if len(malicious_records) > 0:
                attack_types = malicious_records[label_col].value_counts().to_dict()
            else:
                attack_types = {}
            
            # Calculate abuse score
            abuse_score = int(malicious_ratio * 100)
            
            # Store IP reputation
            ip_reputation[ip] = {
                'ip': ip,
                'abuse_score': abuse_score,
                'total_records': total_records,
                'malicious_records': malicious_count,
                'malicious_ratio': round(malicious_ratio, 3),
                'attack_types': attack_types,
                'severity': self._classify_severity(abuse_score),
                'data_source': 'UNSW Dataset Ground Truth'
            }
        
        self.ground_truth_reputation = ip_reputation
        
        # Statistics
        print(f"\n📊 IP Reputation Statistics:")
        print(f"   Total unique IPs analyzed: {len(ip_reputation)}")
        
        malicious_ips = [ip for ip, data in ip_reputation.items() if data['abuse_score'] > 0]
        print(f"   Malicious IPs (score > 0): {len(malicious_ips)}")
        
        severity_counts = Counter(data['severity'] for data in ip_reputation.values())
        print(f"\n   Severity Distribution:")
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = severity_counts.get(severity, 0)
            pct = (count / len(ip_reputation) * 100) if ip_reputation else 0
            print(f"      {severity:8s}: {count:3d} IPs ({pct:5.1f}%)")
    
    def _calculate_behavior_score(self, chain: Dict) -> int:
        """Calculate behavior-based threat score"""
        score = 0
        
        # Anomaly ratio (0-30 points)
        score += min(30, chain['anomaly_ratio'] * 100 * 0.3)
        
        # Attack severity (0-25 points)
        score += min(25, (chain['severity'] / 100) * 25)
        
        # Attack pattern (0-20 points)
        pattern_scores = {
            'BRUTE_FORCE': 20,
            'DATA_EXFILTRATION': 18,
            'LATERAL_MOVEMENT': 16,
            'DDOS': 15,
            'PORT_SCAN': 12,
            'RECONNAISSANCE': 10,
            'UNKNOWN': 5
        }
        score += pattern_scores.get(chain['attack_pattern'], 5)
        
        # Baseline deviation (0-15 points)
        score += min(15, chain['baseline_deviation']['deviation_score'] * 15)
        
        # Escalation (0-10 points)
        if chain['escalation_analysis']['is_escalating']:
            score += min(10, chain['escalation_analysis']['escalation_rate'] * 100)
        
        return int(min(100, score))
    
    def _classify_severity(self, score: int) -> str:
        """Classify severity level"""
        if score >= 75:
            return 'CRITICAL'
        elif score >= 50:
            return 'HIGH'
        elif score >= 25:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _print_statistics(self, chains: list):
        """Print enrichment statistics"""
        print(f"\n{'='*80}")
        print("📊 GROUND TRUTH IP REPUTATION STATISTICS")
        print(f"{'='*80}")
        
        # Severity distribution
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for chain in chains:
            severity_counts[chain['ip_reputation']['severity']] += 1
        
        print(f"\n🎯 Threat Severity Distribution:")
        for severity, count in severity_counts.items():
            pct = (count / len(chains) * 100)
            bar = '█' * int(pct / 2)
            print(f"   {severity:8s}: {count:3d} chains ({pct:5.1f}%) {bar}")
        
        # Top threats
        chains_sorted = sorted(chains,
                              key=lambda x: x['ip_reputation']['abuse_score'],
                              reverse=True)
        
        print(f"\n🔥 Top 10 Most Dangerous Attackers:")
        print(f"{'Chain ID':<12} {'IP':<18} {'GT Score':>8} {'Behavior':>8} {'Final':>6} {'Pattern':<20}")
        print("-" * 90)
        
        for chain in chains_sorted[:10]:
            rep = chain['ip_reputation']
            gt_score = rep.get('ground_truth_score', 0)
            bh_score = rep.get('behavior_score', 0)
            
            print(f"{chain['chain_id']:<12} {rep['ip']:<18} {gt_score:>8} "
                  f"{bh_score:>8} {rep['abuse_score']:>6} {chain['attack_pattern']:<20}")
        
        # Attack types from ground truth
        print(f"\n📋 Attack Types Detected (Ground Truth):")
        all_attack_types = Counter()
        
        for chain in chains:
            attack_types = chain['ip_reputation'].get('attack_types_detected', {})
            for attack_type, count in attack_types.items():
                all_attack_types[attack_type] += count
        
        for attack_type, count in all_attack_types.most_common(10):
            print(f"   {attack_type:<30}: {count:>6,} records")
        
        # Scoring breakdown
        with_ground_truth = len([c for c in chains if c['ip_reputation'].get('ground_truth_score', 0) > 0])
        
        print(f"\n💡 Scoring Breakdown:")
        print(f"   Chains with ground truth data: {with_ground_truth}/{len(chains)}")
        print(f"   Scoring method: Ground Truth (70%) + Behavior (30%)")
        
        print(f"\n{'='*80}")
    
    async def _save_results(self, chains: list) -> Dict:
        """Save enriched results"""
        timestamp = file_manager.generate_timestamp()
        
        # Save enriched chains
        output_file = file_manager.get_output_path(
            f"enriched_chains_{timestamp}_ground_truth.json"
        )
        
        with open(output_file, 'w') as f:
            json.dump(chains, f, indent=2)
        
        print(f"\n✅ Enhanced chains saved: {output_file.name}")
        
        # Register file
        file_manager.register_file("enriched_chains", str(output_file))
        
        # Calculate statistics
        severity_counts = Counter(
            chain['ip_reputation']['severity'] for chain in chains
        )
        
        with_ground_truth = len([
            c for c in chains
            if c['ip_reputation'].get('ground_truth_score', 0) > 0
        ])
        
        return {
            "output_files": {
                "enriched_chains": str(output_file)
            },
            "statistics": {
                "total_chains": len(chains),
                "chains_with_ground_truth": with_ground_truth,
                "severity_distribution": dict(severity_counts),
                "average_abuse_score": sum(
                    c['ip_reputation']['abuse_score'] for c in chains
                ) / len(chains) if chains else 0
            }
        }


# Singleton instance
ip_enrichment_service = IPEnrichmentService()
