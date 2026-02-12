"""
Attack Story Generation Service - Module 5
Generates human-readable attack narratives
"""
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from app.core.file_manager import file_manager


class AttackStoryGenerator:
    """
    Generates human-readable attack narratives from technical data
    Creates executive summaries and detailed incident timelines
    """
    
    def __init__(self):
        # Story templates for different attack patterns
        self.story_templates = {
            'LATERAL_MOVEMENT': {
                'summary': 'The attacker established a foothold and systematically moved through the network',
                'intro': 'gained initial access and began exploring the internal network infrastructure',
                'progression': 'moved laterally across multiple systems, escalating privileges',
                'impact': 'compromised internal systems and gained unauthorized access to sensitive areas'
            },
            'BRUTE_FORCE': {
                'summary': 'The attacker attempted to gain unauthorized access through credential attacks',
                'intro': 'launched a systematic credential attack against authentication services',
                'progression': 'continued password guessing attempts across multiple accounts',
                'impact': 'potentially compromised user credentials through repeated authentication attempts'
            },
            'DATA_EXFILTRATION': {
                'summary': 'The attacker extracted sensitive data from the network',
                'intro': 'established a covert data transfer channel',
                'progression': 'systematically collected and transmitted data to external systems',
                'impact': 'successfully exfiltrated sensitive information from the network'
            },
            'PORT_SCAN': {
                'summary': 'The attacker conducted reconnaissance to map network services',
                'intro': 'began scanning the network to identify available services and vulnerabilities',
                'progression': 'systematically probed multiple ports and services',
                'impact': 'gathered intelligence about network topology and potential attack vectors'
            },
            'RECONNAISSANCE': {
                'summary': 'The attacker performed extensive network reconnaissance',
                'intro': 'initiated comprehensive network mapping activities',
                'progression': 'gathered information about network structure, services, and vulnerabilities',
                'impact': 'collected detailed intelligence for potential future attacks'
            },
            'DDOS': {
                'summary': 'The attacker launched a denial of service attack',
                'intro': 'initiated a high-volume attack to overwhelm target systems',
                'progression': 'sustained the attack with massive traffic floods',
                'impact': 'disrupted services and caused potential downtime'
            },
            'UNKNOWN': {
                'summary': 'The attacker exhibited suspicious behavior',
                'intro': 'initiated unusual network activity',
                'progression': 'continued anomalous behavior patterns',
                'impact': 'posed potential security risks requiring investigation'
            }
        }
        
        # Recommendation templates
        self.recommendation_templates = {
            'LATERAL_MOVEMENT': [
                'Implement network segmentation to limit lateral movement',
                'Deploy endpoint detection and response (EDR) solutions',
                'Enforce least privilege access controls',
                'Monitor for unusual internal network traversal patterns',
                'Implement multi-factor authentication for all internal services'
            ],
            'BRUTE_FORCE': [
                'Implement account lockout policies after failed login attempts',
                'Deploy multi-factor authentication on all authentication endpoints',
                'Use rate limiting on authentication services',
                'Monitor for repeated failed login attempts',
                'Implement strong password policies and password managers'
            ],
            'DATA_EXFILTRATION': [
                'Implement data loss prevention (DLP) solutions',
                'Monitor outbound traffic for unusual data transfers',
                'Encrypt sensitive data at rest and in transit',
                'Implement egress filtering and traffic inspection',
                'Deploy network behavior analytics to detect exfiltration patterns'
            ],
            'PORT_SCAN': [
                'Deploy intrusion detection/prevention systems (IDS/IPS)',
                'Implement network access controls and firewalls',
                'Disable unnecessary services and close unused ports',
                'Monitor for scanning activities in network logs',
                'Use network segmentation to limit exposure'
            ],
            'RECONNAISSANCE': [
                'Implement honeypots to detect reconnaissance activities',
                'Deploy threat intelligence feeds to identify known attackers',
                'Monitor for unusual service enumeration activities',
                'Harden external-facing services',
                'Implement rate limiting on public services'
            ],
            'DDOS': [
                'Deploy DDoS mitigation services and rate limiting',
                'Implement traffic filtering and blackholing',
                'Use content delivery networks (CDN) for distributed protection',
                'Monitor traffic patterns for volumetric attacks',
                'Establish incident response procedures for DDoS events'
            ],
            'UNKNOWN': [
                'Conduct thorough investigation of anomalous activities',
                'Implement comprehensive logging and monitoring',
                'Deploy security information and event management (SIEM)',
                'Establish baseline behavior patterns for detection',
                'Engage threat hunting teams for proactive detection'
            ]
        }
    
    async def generate_stories(self, mitre_chains_file: str) -> Dict:
        """
        Generate attack stories for all chains
        
        Args:
            mitre_chains_file: Path to MITRE-mapped chains JSON
        
        Returns:
            Dictionary with output files and statistics
        """
        print(f"\n{'='*80}")
        print("📖 ForensIQ Attack Story Generator")
        print("    Creating Human-Readable Incident Narratives")
        print(f"{'='*80}")
        
        # Load chains
        print(f"\n📥 Loading MITRE-mapped chains: {Path(mitre_chains_file).name}")
        with open(mitre_chains_file, 'r') as f:
            chains = json.load(f)
        
        print(f"   ✅ Loaded {len(chains)} chains")
        
        # Generate stories
        print(f"\n✍️  Generating attack narratives...")
        
        for i, chain in enumerate(chains, 1):
            story = self._generate_chain_story(chain)
            chain['attack_story'] = story
            
            if i % 10 == 0:
                print(f"   Progress: {i}/{len(chains)} stories generated")
        
        print(f"   ✅ All stories generated")
        
        # Print statistics
        self._print_statistics(chains)
        
        # Save results
        return await self._save_results(chains)
    
    def _generate_chain_story(self, chain: Dict) -> Dict:
        """Generate comprehensive attack story for a chain"""
        attack_pattern = chain['attack_pattern']
        template = self.story_templates.get(
            attack_pattern,
            self.story_templates['UNKNOWN']
        )
        
        # Executive summary
        executive_summary = self._create_executive_summary(chain, template)
        
        # Detailed narrative
        detailed_narrative = self._create_detailed_narrative(chain, template)
        
        # Timeline
        timeline = self._create_timeline(chain)
        
        # Technical details
        technical_details = self._extract_technical_details(chain)
        
        # Recommendations
        recommendations = self._get_recommendations(chain)
        
        # Risk assessment
        risk_assessment = self._assess_risk(chain)
        
        story = {
            'chain_id': chain['chain_id'],
            'title': self._generate_title(chain),
            'executive_summary': executive_summary,
            'detailed_narrative': detailed_narrative,
            'timeline': timeline,
            'technical_details': technical_details,
            'mitre_context': self._format_mitre_context(chain),
            'risk_assessment': risk_assessment,
            'recommendations': recommendations,
            'generated_at': datetime.now().isoformat()
        }
        
        return story
    
    def _generate_title(self, chain: Dict) -> str:
        """Generate story title"""
        pattern = chain['attack_pattern'].replace('_', ' ').title()
        severity = chain['severity_level']
        attacker = chain['attacker_ip']
        
        return f"{severity} Severity {pattern} Attack from {attacker}"
    
    def _create_executive_summary(self, chain: Dict, template: Dict) -> str:
        """Create executive summary"""
        attacker_ip = chain['attacker_ip']
        severity = chain['severity_level']
        pattern = chain['attack_pattern'].replace('_', ' ').lower()
        num_targets = chain['num_targets']
        duration = self._format_duration(chain['duration'])
        reputation = chain['ip_reputation']
        
        summary = f"""
{template['summary']}.

**Threat Actor:** {attacker_ip} (Reputation Score: {reputation['abuse_score']}/100, Severity: {reputation['severity']})

**Attack Classification:** {pattern.title()}

**Scope:** This {severity.lower()}-severity incident targeted {num_targets} system(s) over a period of {duration}. 
The attack exhibited characteristics consistent with {template['summary'].lower()}.

**MITRE ATT&CK Mapping:** The attack aligned with {len(chain['mitre_attack']['tactics'])} MITRE ATT&CK tactic(s), 
specifically {', '.join([t['name'] for t in chain['mitre_attack']['tactics']])}.

**Ground Truth Analysis:** Based on historical data, this IP address has been associated with 
{reputation.get('malicious_records', 0)} malicious activities out of {reputation.get('total_records', 0)} total events, 
representing a {reputation.get('malicious_ratio', 0):.1%} malicious activity rate.
""".strip()
        
        return summary
    
    def _create_detailed_narrative(self, chain: Dict, template: Dict) -> str:
        """Create detailed attack narrative"""
        attacker_ip = chain['attacker_ip']
        start_time = datetime.fromtimestamp(chain['start_time']).strftime('%Y-%m-%d %H:%M:%S')
        end_time = datetime.fromtimestamp(chain['end_time']).strftime('%Y-%m-%d %H:%M:%S')
        
        # Introduction
        narrative = f"On {start_time}, the threat actor at IP address {attacker_ip} {template['intro']}. "
        
        # Context from escalation analysis
        if chain['escalation_analysis']['is_escalating']:
            narrative += f"The attack demonstrated a gradual escalation pattern, with anomalous activity " \
                        f"increasing from {chain['escalation_analysis']['start_ratio']:.1%} to " \
                        f"{chain['escalation_analysis']['end_ratio']:.1%} over the incident timeline. "
        
        # Baseline deviation
        if chain['baseline_deviation']['has_baseline'] and chain['baseline_deviation']['deviation_score'] > 0.3:
            narrative += f"This activity deviated significantly from established baseline behavior patterns, " \
                        f"with a deviation score of {chain['baseline_deviation']['deviation_score']:.2f}. "
            
            deviations = chain['baseline_deviation'].get('deviations', {})
            if 'frequency' in deviations:
                narrative += f"Event frequency was {deviations['frequency']['ratio']:.1f}x normal baseline levels. "
            if 'target_diversity' in deviations:
                narrative += f"Target diversity patterns were also abnormal. "
        
        # Progression
        narrative += f"\n\nThroughout the attack, the adversary {template['progression']}. "
        narrative += f"The incident involved {chain['total_events']} total network events, of which " \
                    f"{chain['anomaly_events']} ({chain['anomaly_ratio']:.1%}) were classified as anomalous. "
        
        # Targets
        if chain['num_targets'] > 1:
            narrative += f"The attack targeted {chain['num_targets']} distinct systems: " \
                        f"{', '.join(chain['target_ips'][:5])}" \
                        f"{'...' if len(chain['target_ips']) > 5 else ''}. "
        else:
            narrative += f"The attack focused on a single target: {chain['target_ips'][0]}. "
        
        # Network characteristics
        narrative += f"\n\nNetwork analysis revealed activity across {chain['unique_dst_ports']} unique ports, " \
                    f"with the most common being {', '.join([str(p) for p in list(chain['common_ports'].keys())[:3]])}. "
        
        protocols = ', '.join(chain['protocols'].keys())
        narrative += f"The attack primarily utilized {protocols} protocol(s). "
        
        # Data volume
        data_mb = chain['total_bytes'] / (1024 * 1024)
        narrative += f"A total of {data_mb:.2f} MB of data was transferred during the incident. "
        
        # Conclusion
        narrative += f"\n\nThe attack concluded at {end_time}. {template['impact'].capitalize()}."
        
        return narrative
    
    def _create_timeline(self, chain: Dict) -> List[Dict]:
        """Create incident timeline"""
        timeline = []
        
        # Start event
        timeline.append({
            'timestamp': datetime.fromtimestamp(chain['start_time']).isoformat(),
            'event': 'Attack Initiated',
            'description': f"First anomalous activity detected from {chain['attacker_ip']}",
            'severity': 'WARNING'
        })
        
        # Key events from anomaly details
        if chain.get('anomaly_events_detail'):
            # Sample some key anomaly events
            sample_events = sorted(
                chain['anomaly_events_detail'],
                key=lambda x: x.get('anomaly_score', 0),
                reverse=True
            )[:5]
            
            for event in sample_events:
                timeline.append({
                    'timestamp': datetime.fromtimestamp(event['stime']).isoformat(),
                    'event': f"High-severity event to {event['dstip']}:{event['dsport']}",
                    'description': f"Protocol: {event['proto']}, State: {event['state']}, " \
                                  f"Anomaly Score: {event.get('anomaly_score', 0):.2f}",
                    'severity': 'CRITICAL' if event.get('anomaly_score', 0) > 0.9 else 'HIGH'
                })
        
        # Escalation points
        if chain['escalation_analysis']['is_escalating']:
            mid_time = (chain['start_time'] + chain['end_time']) / 2
            timeline.append({
                'timestamp': datetime.fromtimestamp(mid_time).isoformat(),
                'event': 'Escalation Pattern Detected',
                'description': f"Attack intensity increasing (rate: {chain['escalation_analysis']['escalation_rate']:.2f})",
                'severity': 'HIGH'
            })
        
        # End event
        timeline.append({
            'timestamp': datetime.fromtimestamp(chain['end_time']).isoformat(),
            'event': 'Attack Concluded',
            'description': f"Last detected activity from {chain['attacker_ip']}",
            'severity': 'INFO'
        })
        
        return sorted(timeline, key=lambda x: x['timestamp'])
    
    def _extract_technical_details(self, chain: Dict) -> Dict:
        """Extract technical details"""
        return {
            'chain_id': chain['chain_id'],
            'attacker_ip': chain['attacker_ip'],
            'target_ips': chain['target_ips'],
            'attack_pattern': chain['attack_pattern'],
            'duration_seconds': chain['duration'],
            'total_events': chain['total_events'],
            'anomaly_events': chain['anomaly_events'],
            'anomaly_ratio': round(chain['anomaly_ratio'], 3),
            'severity_score': chain['severity'],
            'severity_level': chain['severity_level'],
            'protocols_used': list(chain['protocols'].keys()),
            'states_observed': list(chain['states'].keys()),
            'unique_dst_ports': chain['unique_dst_ports'],
            'common_ports': chain['common_ports'],
            'total_bytes_transferred': chain['total_bytes'],
            'avg_anomaly_score': round(chain['avg_anomaly_score'], 4),
            'max_anomaly_score': round(chain['max_anomaly_score'], 4),
            'ngram_rarity': chain['ngram_rarity'],
            'baseline_deviation_score': chain['baseline_deviation']['deviation_score'],
            'is_escalating': chain['escalation_analysis']['is_escalating']
        }
    
    def _format_mitre_context(self, chain: Dict) -> Dict:
        """Format MITRE ATT&CK context"""
        mitre = chain['mitre_attack']
        
        return {
            'tactics': [
                f"{t['id']}: {t['name']}" for t in mitre['tactics']
            ],
            'techniques': [
                {
                    'id': t['id'],
                    'name': t['name'],
                    'confidence': f"{t['confidence']:.0%}",
                    'url': self._generate_mitre_url(t['id'])
                }
                for t in mitre['techniques']
            ],
            'kill_chain_phase': mitre['kill_chain_phase']
        }
    
    def _assess_risk(self, chain: Dict) -> Dict:
        """Assess overall risk"""
        severity_score = chain['severity']
        reputation_score = chain['ip_reputation']['abuse_score']
        
        # Combined risk score
        risk_score = (severity_score * 0.6) + (reputation_score * 0.4)
        
        if risk_score >= 75:
            risk_level = 'CRITICAL'
            priority = 'IMMEDIATE'
        elif risk_score >= 50:
            risk_level = 'HIGH'
            priority = 'URGENT'
        elif risk_score >= 25:
            risk_level = 'MEDIUM'
            priority = 'ELEVATED'
        else:
            risk_level = 'LOW'
            priority = 'ROUTINE'
        
        return {
            'risk_score': round(risk_score, 2),
            'risk_level': risk_level,
            'response_priority': priority,
            'contributing_factors': [
                f"Attack severity: {chain['severity_level']} ({severity_score}/100)",
                f"IP reputation: {chain['ip_reputation']['severity']} ({reputation_score}/100)",
                f"Anomaly ratio: {chain['anomaly_ratio']:.1%}",
                f"Targets affected: {chain['num_targets']}",
                f"Baseline deviation: {chain['baseline_deviation']['deviation_score']:.2f}"
            ]
        }
    
    def _get_recommendations(self, chain: Dict) -> List[str]:
        """Get security recommendations"""
        attack_pattern = chain['attack_pattern']
        recommendations = self.recommendation_templates.get(
            attack_pattern,
            self.recommendation_templates['UNKNOWN']
        ).copy()
        
        # Add IP-specific recommendation
        if chain['ip_reputation']['abuse_score'] > 70:
            recommendations.insert(0, f"Immediately block IP address {chain['attacker_ip']} at network perimeter")
        
        # Add escalation-specific recommendation
        if chain['escalation_analysis']['is_escalating']:
            recommendations.append("Implement automated alerting for gradual escalation patterns")
        
        # Add deviation-specific recommendation
        if chain['baseline_deviation']['deviation_score'] > 0.5:
            recommendations.append("Review and update baseline behavior profiles for affected systems")
        
        return recommendations
    
    def _format_duration(self, seconds: int) -> str:
        """Format duration in human-readable form"""
        if seconds < 60:
            return f"{seconds} seconds"
        elif seconds < 3600:
            minutes = seconds // 60
            return f"{minutes} minute{'s' if minutes != 1 else ''}"
        else:
            hours = seconds // 3600
            minutes = (seconds % 3600) // 60
            return f"{hours} hour{'s' if hours != 1 else ''} and {minutes} minute{'s' if minutes != 1 else ''}"
    
    def _generate_mitre_url(self, technique_id: str) -> str:
        """Generate MITRE ATT&CK URL"""
        return f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"
    
    def _print_statistics(self, chains: List[Dict]):
        """Print story generation statistics"""
        print(f"\n{'='*80}")
        print("📊 ATTACK STORY GENERATION STATISTICS")
        print(f"{'='*80}")
        
        from collections import Counter
        
        # Risk distribution
        risk_levels = [chain['attack_story']['risk_assessment']['risk_level'] for chain in chains]
        risk_counts = Counter(risk_levels)
        
        print(f"\n⚠️  Risk Level Distribution:")
        for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = risk_counts.get(level, 0)
            pct = (count / len(chains) * 100) if chains else 0
            bar = '█' * int(pct / 2)
            print(f"   {level:8s}: {count:3d} incidents ({pct:5.1f}%) {bar}")
        
        # Average story lengths
        total_chars = sum(len(chain['attack_story']['detailed_narrative']) for chain in chains)
        avg_length = total_chars // len(chains) if chains else 0
        
        print(f"\n📝 Story Statistics:")
        print(f"   Total stories generated: {len(chains)}")
        print(f"   Average narrative length: {avg_length} characters")
        print(f"   Average timeline events: {sum(len(chain['attack_story']['timeline']) for chain in chains) / len(chains):.1f}")
        
        # Top attack patterns
        patterns = [chain['attack_pattern'] for chain in chains]
        pattern_counts = Counter(patterns)
        
        print(f"\n🎯 Attack Pattern Distribution:")
        for pattern, count in pattern_counts.most_common(5):
            print(f"   {pattern:<20}: {count:3d} incidents")
        
        print(f"\n{'='*80}")
    
    async def _save_results(self, chains: List[Dict]) -> Dict:
        """Save story results"""
        timestamp = file_manager.generate_timestamp()
        
        # Save stories with chains
        stories_file = file_manager.get_output_path(
            f"enriched_chains_{timestamp}_ground_truth_stories.json"
        )
        
        with open(stories_file, 'w') as f:
            json.dump(chains, f, indent=2)
        
        print(f"\n✅ Attack stories saved: {stories_file.name}")
        
        # Generate markdown report
        report_file = await self._generate_stories_report(chains, timestamp)
        
        # Register files
        file_manager.register_file("attack_stories", str(stories_file))
        file_manager.register_file("stories_report", str(report_file))
        
        # Calculate statistics
        from collections import Counter
        risk_levels = [chain['attack_story']['risk_assessment']['risk_level'] for chain in chains]
        risk_counts = Counter(risk_levels)
        
        return {
            "output_files": {
                "attack_stories": str(stories_file),
                "stories_report": str(report_file)
            },
            "statistics": {
                "total_stories": len(chains),
                "risk_distribution": dict(risk_counts),
                "critical_incidents": risk_counts.get('CRITICAL', 0),
                "high_risk_incidents": risk_counts.get('HIGH', 0)
            }
        }
    
    async def _generate_stories_report(self, chains: List[Dict], timestamp: str) -> Path:
        """Generate attack stories report"""
        print(f"\n📄 Generating Attack Stories Report...")
        
        # Sort by risk score
        chains_sorted = sorted(
            chains,
            key=lambda x: x['attack_story']['risk_assessment']['risk_score'],
            reverse=True
        )
        
        report_file = file_manager.get_output_path(f"attack_stories_report_{timestamp}.md")
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("# 📖 ForensIQ Attack Story Report\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S IST')}\n\n")
            f.write(f"**Total Incidents:** {len(chains)}\n\n")
            
            f.write("---\n\n")
            
            # Executive Overview
            f.write("## 📊 Executive Overview\n\n")
            
            from collections import Counter
            risk_levels = [chain['attack_story']['risk_assessment']['risk_level'] for chain in chains]
            risk_counts = Counter(risk_levels)
            
            f.write("| Risk Level | Count | Percentage |\n")
            f.write("|------------|-------|------------|\n")
            for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                count = risk_counts.get(level, 0)
                pct = (count / len(chains) * 100) if chains else 0
                f.write(f"| {level} | {count} | {pct:.1f}% |\n")
            
            f.write("\n---\n\n")
            
            # Top 10 incidents
            f.write("## 🔥 Top 10 Critical Incidents\n\n")
            
            for i, chain in enumerate(chains_sorted[:10], 1):
                story = chain['attack_story']
                
                f.write(f"### {i}. {story['title']}\n\n")
                
                # Risk badge
                risk_level = story['risk_assessment']['risk_level']
                risk_emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}
                f.write(f"{risk_emoji.get(risk_level, '⚪')} **Risk: {risk_level}** ")
                f.write(f"(Score: {story['risk_assessment']['risk_score']:.1f}/100)\n\n")
                
                # Executive summary
                f.write(f"#### Executive Summary\n\n")
                f.write(f"{story['executive_summary']}\n\n")
                
                # Timeline
                f.write(f"#### Timeline\n\n")
                for event in story['timeline']:
                    event_time = datetime.fromisoformat(event['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
                    f.write(f"- **{event_time}** - {event['event']}: {event['description']}\n")
                
                f.write(f"\n")
                
                # MITRE context
                f.write(f"#### MITRE ATT&CK Context\n\n")
                f.write(f"**Tactics:** {', '.join(story['mitre_context']['tactics'])}\n\n")
                f.write(f"**Techniques:**\n")
                for tech in story['mitre_context']['techniques']:
                    f.write(f"- [{tech['id']}: {tech['name']}]({tech['url']}) (Confidence: {tech['confidence']})\n")
                
                f.write(f"\n**Kill Chain Phase:** {story['mitre_context']['kill_chain_phase']}\n\n")
                
                # Recommendations
                f.write(f"#### Recommended Actions\n\n")
                for j, rec in enumerate(story['recommendations'], 1):
                    f.write(f"{j}. {rec}\n")
                
                f.write("\n---\n\n")
            
            f.write("\n## 📚 Additional Resources\n\n")
            f.write("- [MITRE ATT&CK Framework](https://attack.mitre.org/)\n")
            f.write("- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)\n")
            f.write("- [SANS Incident Response Guide](https://www.sans.org/white-papers/)\n")
        
        print(f"✅ Stories report saved: {report_file.name}")
        return report_file


# Singleton instance
story_generator = AttackStoryGenerator()
