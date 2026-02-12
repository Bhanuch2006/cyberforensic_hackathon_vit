"""
MITRE ATT&CK Mapping Service - Module 4
Maps attack chains to MITRE ATT&CK framework
"""
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List
from collections import Counter

from app.core.file_manager import file_manager


class MITREAttackMapper:
    """
    Maps attack chains to MITRE ATT&CK framework
    Provides tactics, techniques, and sub-techniques classification
    """
    
    def __init__(self):
        # MITRE ATT&CK Tactics (ordered by attack lifecycle)
        self.tactics = {
            'TA0043': {'name': 'Reconnaissance', 'description': 'Gathering information about target'},
            'TA0001': {'name': 'Initial Access', 'description': 'Trying to get into network'},
            'TA0002': {'name': 'Execution', 'description': 'Running malicious code'},
            'TA0003': {'name': 'Persistence', 'description': 'Maintaining foothold'},
            'TA0004': {'name': 'Privilege Escalation', 'description': 'Gaining higher privileges'},
            'TA0005': {'name': 'Defense Evasion', 'description': 'Avoiding detection'},
            'TA0006': {'name': 'Credential Access', 'description': 'Stealing credentials'},
            'TA0007': {'name': 'Discovery', 'description': 'Exploring environment'},
            'TA0008': {'name': 'Lateral Movement', 'description': 'Moving through network'},
            'TA0009': {'name': 'Collection', 'description': 'Gathering data of interest'},
            'TA0011': {'name': 'Command and Control', 'description': 'Communicating with systems'},
            'TA0010': {'name': 'Exfiltration', 'description': 'Stealing data'},
            'TA0040': {'name': 'Impact', 'description': 'Disrupting operations'}
        }
        
        # MITRE ATT&CK Techniques mapping
        self.technique_mappings = {
            'PORT_SCAN': {
                'tactics': ['TA0043'],
                'techniques': [
                    {
                        'id': 'T1046',
                        'name': 'Network Service Discovery',
                        'description': 'Adversaries scan target network to identify services',
                        'indicators': ['multiple_ports', 'scan_pattern', 'low_data_transfer']
                    }
                ]
            },
            'RECONNAISSANCE': {
                'tactics': ['TA0043', 'TA0007'],
                'techniques': [
                    {
                        'id': 'T1595',
                        'name': 'Active Scanning',
                        'description': 'Scanning IP blocks, ports, or services',
                        'indicators': ['multiple_targets', 'sequential_scanning']
                    },
                    {
                        'id': 'T1590',
                        'name': 'Gather Victim Network Information',
                        'description': 'Collecting network topology information',
                        'indicators': ['network_mapping', 'service_enumeration']
                    }
                ]
            },
            'BRUTE_FORCE': {
                'tactics': ['TA0006', 'TA0001'],
                'techniques': [
                    {
                        'id': 'T1110',
                        'name': 'Brute Force',
                        'description': 'Trying multiple passwords to gain access',
                        'sub_techniques': [
                            {'id': 'T1110.001', 'name': 'Password Guessing'},
                            {'id': 'T1110.003', 'name': 'Password Spraying'}
                        ],
                        'indicators': ['auth_ports', 'repeated_attempts', 'failed_logins']
                    },
                    {
                        'id': 'T1078',
                        'name': 'Valid Accounts',
                        'description': 'Attempting to use legitimate credentials',
                        'indicators': ['ssh_attempts', 'rdp_attempts']
                    }
                ]
            },
            'LATERAL_MOVEMENT': {
                'tactics': ['TA0008'],
                'techniques': [
                    {
                        'id': 'T1021',
                        'name': 'Remote Services',
                        'description': 'Using remote services to move between systems',
                        'sub_techniques': [
                            {'id': 'T1021.001', 'name': 'Remote Desktop Protocol'},
                            {'id': 'T1021.004', 'name': 'SSH'},
                            {'id': 'T1021.002', 'name': 'SMB/Windows Admin Shares'}
                        ],
                        'indicators': ['multiple_internal_targets', 'escalating_access']
                    },
                    {
                        'id': 'T1570',
                        'name': 'Lateral Tool Transfer',
                        'description': 'Transferring tools between systems',
                        'indicators': ['file_transfers', 'tool_deployment']
                    }
                ]
            },
            'DATA_EXFILTRATION': {
                'tactics': ['TA0010', 'TA0009'],
                'techniques': [
                    {
                        'id': 'T1041',
                        'name': 'Exfiltration Over C2 Channel',
                        'description': 'Stealing data over command and control channel',
                        'indicators': ['high_data_transfer', 'sustained_connections']
                    },
                    {
                        'id': 'T1048',
                        'name': 'Exfiltration Over Alternative Protocol',
                        'description': 'Using uncommon protocols to exfiltrate',
                        'indicators': ['unusual_protocols', 'encrypted_traffic']
                    },
                    {
                        'id': 'T1020',
                        'name': 'Automated Exfiltration',
                        'description': 'Automated data collection and transfer',
                        'indicators': ['regular_intervals', 'large_volumes']
                    }
                ]
            },
            'DDOS': {
                'tactics': ['TA0040'],
                'techniques': [
                    {
                        'id': 'T1498',
                        'name': 'Network Denial of Service',
                        'description': 'Overwhelming network resources',
                        'sub_techniques': [
                            {'id': 'T1498.001', 'name': 'Direct Network Flood'},
                            {'id': 'T1498.002', 'name': 'Reflection Amplification'}
                        ],
                        'indicators': ['high_volume', 'single_target', 'short_duration']
                    },
                    {
                        'id': 'T1499',
                        'name': 'Endpoint Denial of Service',
                        'description': 'Exhausting system resources',
                        'indicators': ['resource_exhaustion', 'service_unavailability']
                    }
                ]
            },
            'UNKNOWN': {
                'tactics': ['TA0043'],
                'techniques': [
                    {
                        'id': 'T1595',
                        'name': 'Active Scanning',
                        'description': 'General scanning activity',
                        'indicators': ['unclassified_behavior']
                    }
                ]
            }
        }
    
    async def map_chains(self, enriched_chains_file: str) -> Dict:
        """
        Map all attack chains to MITRE ATT&CK
        
        Args:
            enriched_chains_file: Path to enriched chains JSON
        
        Returns:
            Dictionary with output files and statistics
        """
        print(f"\n{'='*80}")
        print("🎯 MITRE ATT&CK Framework Mapping")
        print(f"{'='*80}")
        
        # Load chains
        print(f"\n📥 Loading chains: {Path(enriched_chains_file).name}")
        with open(enriched_chains_file, 'r') as f:
            chains = json.load(f)
        
        print(f"   ✅ Loaded {len(chains)} chains")
        
        # Map each chain
        print(f"\n🔍 Mapping chains to MITRE ATT&CK...")
        
        for i, chain in enumerate(chains, 1):
            mitre_mapping = self._map_chain_to_mitre(chain)
            chain['mitre_attack'] = mitre_mapping
            
            if i % 10 == 0:
                print(f"   Progress: {i}/{len(chains)} chains mapped")
        
        print(f"   ✅ All chains mapped")
        
        # Print statistics
        self._print_mitre_stats(chains)
        
        # Save results
        return await self._save_results(chains)
    
    def _map_chain_to_mitre(self, chain: Dict) -> Dict:
        """Map single attack chain to MITRE ATT&CK framework"""
        attack_pattern = chain['attack_pattern']
        
        # Get technique mapping
        mapping = self.technique_mappings.get(
            attack_pattern,
            self.technique_mappings['UNKNOWN']
        )
        
        # Extract tactics
        tactics = []
        for tactic_id in mapping['tactics']:
            tactics.append({
                'id': tactic_id,
                'name': self.tactics[tactic_id]['name'],
                'description': self.tactics[tactic_id]['description']
            })
        
        # Extract techniques with confidence scores
        techniques = []
        for tech in mapping['techniques']:
            confidence = self._calculate_technique_confidence(chain, tech)
            
            technique_entry = {
                'id': tech['id'],
                'name': tech['name'],
                'description': tech['description'],
                'confidence': confidence,
                'evidence': self._extract_evidence(chain, tech)
            }
            
            # Add sub-techniques if present
            if 'sub_techniques' in tech:
                technique_entry['sub_techniques'] = tech['sub_techniques']
            
            techniques.append(technique_entry)
        
        # Build MITRE mapping
        mitre_mapping = {
            'chain_id': chain['chain_id'],
            'attack_pattern': attack_pattern,
            'tactics': tactics,
            'techniques': techniques,
            'kill_chain_phase': self._determine_kill_chain_phase(tactics),
            'mitre_attack_url': self._generate_mitre_url(techniques[0]['id']) if techniques else None
        }
        
        return mitre_mapping
    
    def _calculate_technique_confidence(self, chain: Dict, technique: Dict) -> float:
        """Calculate confidence score for technique match"""
        confidence = 0.5  # Base confidence
        
        indicators = technique.get('indicators', [])
        
        if 'auth_ports' in indicators:
            auth_ports = [22, 3389, 21, 23]
            if any(port in chain['common_ports'] for port in auth_ports):
                confidence += 0.2
        
        if 'multiple_targets' in indicators or 'multiple_internal_targets' in indicators:
            if chain['num_targets'] >= 5:
                confidence += 0.15
        
        if 'high_data_transfer' in indicators:
            if chain['total_bytes'] > 1000000:
                confidence += 0.2
        
        if 'escalating_access' in indicators:
            if chain['escalation_analysis']['is_escalating']:
                confidence += 0.15
        
        if 'multiple_ports' in indicators:
            if chain['unique_dst_ports'] >= 10:
                confidence += 0.15
        
        # Anomaly ratio boost
        if chain['anomaly_ratio'] > 0.5:
            confidence += 0.1
        
        # Baseline deviation boost
        if chain['baseline_deviation']['deviation_score'] > 0.5:
            confidence += 0.1
        
        return min(1.0, confidence)
    
    def _extract_evidence(self, chain: Dict, technique: Dict) -> List[str]:
        """Extract evidence supporting technique identification"""
        evidence = []
        
        # Common evidence
        evidence.append(f"Total events: {chain['total_events']:,}")
        evidence.append(f"Anomaly ratio: {chain['anomaly_ratio']:.1%}")
        evidence.append(f"Targets affected: {chain['num_targets']}")
        
        # Pattern-specific evidence
        if chain['attack_pattern'] == 'BRUTE_FORCE':
            evidence.append(f"Authentication attempts on ports: {list(chain['common_ports'].keys())[:3]}")
            evidence.append(f"Repeated connection attempts detected")
        
        elif chain['attack_pattern'] == 'LATERAL_MOVEMENT':
            evidence.append(f"Internal network traversal detected")
            if chain['escalation_analysis']['is_escalating']:
                evidence.append(f"Gradual escalation observed (rate: {chain['escalation_analysis']['escalation_rate']:.2f})")
            evidence.append(f"Multiple internal targets: {chain['num_targets']}")
        
        elif chain['attack_pattern'] == 'DATA_EXFILTRATION':
            evidence.append(f"Data transfer: {chain['total_bytes']:,} bytes")
            evidence.append(f"Sustained connections over {chain['duration']} seconds")
        
        elif chain['attack_pattern'] == 'PORT_SCAN':
            evidence.append(f"Ports scanned: {chain['unique_dst_ports']}")
            evidence.append(f"Scan pattern detected across multiple services")
        
        elif chain['attack_pattern'] == 'DDOS':
            evidence.append(f"High volume attack: {chain['total_events']:,} requests")
            evidence.append(f"Single target overwhelmed")
        
        elif chain['attack_pattern'] == 'RECONNAISSANCE':
            evidence.append(f"Network mapping activity detected")
            evidence.append(f"Service enumeration across {chain['unique_dst_ports']} ports")
        
        # Baseline deviation
        if chain['baseline_deviation']['deviation_score'] > 0.3:
            evidence.append(f"Baseline deviation: {chain['baseline_deviation']['deviation_score']:.2f}")
            
            deviations = chain['baseline_deviation'].get('deviations', {})
            if 'frequency' in deviations:
                evidence.append(f"Abnormal frequency: {deviations['frequency']['ratio']:.1f}x baseline")
            if 'target_diversity' in deviations:
                evidence.append(f"Unusual target diversity pattern")
        
        return evidence
    
    def _determine_kill_chain_phase(self, tactics: List[Dict]) -> str:
        """Determine Lockheed Martin Cyber Kill Chain phase"""
        tactic_names = [t['name'] for t in tactics]
        
        if 'Reconnaissance' in tactic_names:
            return 'Reconnaissance'
        elif 'Initial Access' in tactic_names:
            return 'Weaponization/Delivery'
        elif 'Execution' in tactic_names or 'Persistence' in tactic_names:
            return 'Exploitation/Installation'
        elif 'Credential Access' in tactic_names or 'Privilege Escalation' in tactic_names:
            return 'Installation/Command & Control'
        elif 'Lateral Movement' in tactic_names or 'Discovery' in tactic_names:
            return 'Command & Control'
        elif 'Exfiltration' in tactic_names or 'Collection' in tactic_names:
            return 'Actions on Objectives'
        elif 'Impact' in tactic_names:
            return 'Actions on Objectives'
        else:
            return 'Unknown'
    
    def _generate_mitre_url(self, technique_id: str) -> str:
        """Generate MITRE ATT&CK URL for technique"""
        return f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"
    
    def _print_mitre_stats(self, chains: List[Dict]):
        """Print MITRE ATT&CK mapping statistics"""
        print(f"\n{'='*80}")
        print("📊 MITRE ATT&CK MAPPING STATISTICS")
        print(f"{'='*80}")
        
        # Tactic distribution
        all_tactics = []
        for chain in chains:
            for tactic in chain['mitre_attack']['tactics']:
                all_tactics.append(tactic['name'])
        
        tactic_counts = Counter(all_tactics)
        
        print(f"\n🎯 Tactic Distribution:")
        for tactic, count in tactic_counts.most_common():
            pct = (count / len(chains)) * 100
            bar = '█' * int(pct / 5)
            print(f"   {tactic:<25}: {count:3d} chains ({pct:5.1f}%) {bar}")
        
        # Technique distribution
        all_techniques = []
        for chain in chains:
            for tech in chain['mitre_attack']['techniques']:
                all_techniques.append(f"{tech['id']}: {tech['name']}")
        
        technique_counts = Counter(all_techniques)
        
        print(f"\n🔧 Top 10 Techniques Detected:")
        for technique, count in technique_counts.most_common(10):
            print(f"   {technique:<50}: {count:3d} chains")
        
        # Kill chain phases
        kill_chain_phases = [chain['mitre_attack']['kill_chain_phase'] for chain in chains]
        phase_counts = Counter(kill_chain_phases)
        
        print(f"\n⚔️  Cyber Kill Chain Phase Distribution:")
        for phase, count in phase_counts.most_common():
            pct = (count / len(chains)) * 100
            print(f"   {phase:<35}: {count:3d} chains ({pct:5.1f}%)")
        
        # High confidence matches
        high_confidence = []
        for chain in chains:
            for tech in chain['mitre_attack']['techniques']:
                if tech['confidence'] >= 0.8:
                    high_confidence.append(chain['chain_id'])
        
        print(f"\n✅ High Confidence Matches (≥80%):")
        print(f"   {len(set(high_confidence))} chains with high-confidence technique matches")
        
        print(f"\n{'='*80}")
    
    async def _save_results(self, chains: List[Dict]) -> Dict:
        """Save MITRE-mapped results"""
        timestamp = file_manager.generate_timestamp()
        
        # Save MITRE-mapped chains
        mitre_file = file_manager.get_output_path(
            f"enriched_chains_{timestamp}_ground_truth_mitre.json"
        )
        
        with open(mitre_file, 'w') as f:
            json.dump(chains, f, indent=2)
        
        print(f"\n✅ MITRE-mapped chains saved: {mitre_file.name}")
        
        # Generate markdown report
        report_file = await self._generate_mitre_report(chains, timestamp)
        
        # Register files
        file_manager.register_file("mitre_chains", str(mitre_file))
        file_manager.register_file("mitre_report", str(report_file))
        
        # Calculate statistics
        tactic_counts = Counter()
        technique_counts = Counter()
        
        for chain in chains:
            for tactic in chain['mitre_attack']['tactics']:
                tactic_counts[tactic['name']] += 1
            for tech in chain['mitre_attack']['techniques']:
                technique_counts[tech['id']] += 1
        
        return {
            "output_files": {
                "mitre_chains": str(mitre_file),
                "mitre_report": str(report_file)
            },
            "statistics": {
                "total_chains": len(chains),
                "unique_tactics": len(tactic_counts),
                "unique_techniques": len(technique_counts),
                "most_common_tactic": tactic_counts.most_common(1)[0] if tactic_counts else None,
                "most_common_technique": technique_counts.most_common(1)[0] if technique_counts else None
            }
        }
    
    async def _generate_mitre_report(self, chains: List[Dict], timestamp: str) -> Path:
        """Generate MITRE ATT&CK mapping report"""
        print(f"\n📄 Generating MITRE ATT&CK Report...")
        
        # Sort by severity
        chains_sorted = sorted(chains, key=lambda x: x['severity'], reverse=True)
        
        report_file = file_manager.get_output_path(f"mitre_attack_report_{timestamp}.md")
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("# 🎯 ForensIQ MITRE ATT&CK Mapping Report\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S IST')}\n\n")
            f.write(f"**Total Attack Chains:** {len(chains)}\n\n")
            
            f.write("---\n\n")
            
            # Tactic overview
            f.write("## 📊 MITRE ATT&CK Tactics Overview\n\n")
            
            all_tactics = []
            for chain in chains:
                for tactic in chain['mitre_attack']['tactics']:
                    all_tactics.append(tactic['name'])
            
            tactic_counts = Counter(all_tactics)
            
            f.write("| Tactic | Chains | Percentage |\n")
            f.write("|--------|--------|------------|\n")
            for tactic, count in tactic_counts.most_common():
                pct = (count / len(chains)) * 100
                f.write(f"| {tactic} | {count} | {pct:.1f}% |\n")
            
            f.write("\n---\n\n")
            
            # Top 10 chains
            f.write("## 🔥 Top 10 Attack Chains with MITRE Mapping\n\n")
            
            for i, chain in enumerate(chains_sorted[:10], 1):
                mitre = chain['mitre_attack']
                rep = chain['ip_reputation']
                
                f.write(f"### {i}. {chain['chain_id']} - {chain['attack_pattern']}\n\n")
                
                f.write(f"**Severity:** {chain['severity_level']} ({chain['severity']:.1f}/100)\n\n")
                f.write(f"**Attacker:** `{rep['ip']}` ({rep.get('country_code', 'UNKNOWN')})\n\n")
                
                f.write(f"#### 🎯 MITRE ATT&CK Mapping\n\n")
                
                f.write(f"**Tactics:**\n")
                for tactic in mitre['tactics']:
                    f.write(f"- **{tactic['id']}**: {tactic['name']} - {tactic['description']}\n")
                
                f.write(f"\n**Techniques:**\n")
                for tech in mitre['techniques']:
                    conf_emoji = '🟢' if tech['confidence'] >= 0.8 else '🟡' if tech['confidence'] >= 0.6 else '🟠'
                    tech_url = self._generate_mitre_url(tech['id'])
                    f.write(f"- {conf_emoji} **[{tech['id']}]({tech_url})**: {tech['name']}\n")
                    f.write(f"  - Confidence: {tech['confidence']:.0%}\n")
                    f.write(f"  - {tech['description']}\n")
                    
                    if tech.get('sub_techniques'):
                        f.write(f"  - Sub-techniques:\n")
                        for sub in tech['sub_techniques']:
                            f.write(f"    - {sub['id']}: {sub['name']}\n")
                
                f.write(f"\n**Kill Chain Phase:** {mitre['kill_chain_phase']}\n\n")
                
                f.write(f"**Evidence:**\n")
                for evidence in mitre['techniques'][0]['evidence']:
                    f.write(f"- {evidence}\n")
                
                f.write("\n---\n\n")
            
            f.write("\n## 🔗 References\n\n")
            f.write("- [MITRE ATT&CK Framework](https://attack.mitre.org/)\n")
            f.write("- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)\n")
            f.write("- [Lockheed Martin Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)\n")
        
        print(f"✅ MITRE report saved: {report_file.name}")
        return report_file


# Singleton instance
mitre_mapper = MITREAttackMapper()
