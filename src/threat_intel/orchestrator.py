"""
Threat Intelligence Orchestration Framework
Main orchestrator for collecting, processing, and operationalizing IOCs
"""

import logging
from datetime import datetime, timedelta
from typing import List, Dict, Set, Optional
import hashlib
import json
from dataclasses import dataclass, asdict, field
from enum import Enum

logger = logging.getLogger(__name__)


class IOCType(Enum):
    """Types of Indicators of Compromise"""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH_MD5 = "file_hash_md5"
    FILE_HASH_SHA1 = "file_hash_sha1"
    FILE_HASH_SHA256 = "file_hash_sha256"
    EMAIL = "email"
    REGISTRY_KEY = "registry_key"
    MUTEX = "mutex"
    USER_AGENT = "user_agent"
    CVE = "cve"


class ThreatSeverity(Enum):
    """Threat severity levels aligned with CVSS"""
    CRITICAL = 5  # 9.0-10.0
    HIGH = 4      # 7.0-8.9
    MEDIUM = 3    # 4.0-6.9
    LOW = 2       # 0.1-3.9
    INFO = 1      # Informational


@dataclass
class IOCIndicator:
    """
    Standardized IOC data structure
    
    Attributes:
        indicator_value: The actual IOC value (IP, domain, hash, etc.)
        indicator_type: Type of indicator
        source: Origin of the intelligence
        confidence: Confidence score (0-100)
        severity: Threat severity level
        first_seen: First observation timestamp
        last_seen: Most recent observation timestamp
        description: Human-readable description
        tags: List of associated tags
        threat_actor: Associated threat actor (if known)
        campaign: Associated campaign name (if known)
        mitre_tactics: MITRE ATT&CK tactic IDs
        mitre_techniques: MITRE ATT&CK technique IDs
        false_positive_rate: Historical false positive rate (0.0-1.0)
        tlp: Traffic Light Protocol classification
    """
    indicator_value: str
    indicator_type: IOCType
    source: str
    confidence: int
    severity: ThreatSeverity
    first_seen: datetime
    last_seen: datetime
    description: str
    tags: List[str] = field(default_factory=list)
    threat_actor: Optional[str] = None
    campaign: Optional[str] = None
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    false_positive_rate: float = 0.0
    tlp: str = "white"
    ioc_id: str = field(init=False)
    
    def __post_init__(self):
        """Validate and normalize data"""
        if not 0 <= self.confidence <= 100:
            raise ValueError("Confidence must be between 0 and 100")
        
        if not 0.0 <= self.false_positive_rate <= 1.0:
            raise ValueError("False positive rate must be between 0.0 and 1.0")
        
        # Generate unique ID for deduplication
        self.ioc_id = self._generate_id()
        
        # Normalize tags
        self.tags = [tag.lower().strip() for tag in self.tags]
    
    def _generate_id(self) -> str:
        """Generate unique identifier for IOC based on value, type, and source"""
        data = f"{self.indicator_value}:{self.indicator_type.value}:{self.source}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        data['indicator_type'] = self.indicator_type.value
        data['severity'] = self.severity.name
        data['first_seen'] = self.first_seen.isoformat()
        data['last_seen'] = self.last_seen.isoformat()
        return data
    
    def is_stale(self, days: int = 90) -> bool:
        """
        Check if indicator is stale based on last seen date
        
        Args:
            days: Number of days to consider stale
            
        Returns:
            True if indicator is stale, False otherwise
        """
        age = datetime.now() - self.last_seen
        return age.days > days
    
    def should_operationalize(self, 
                            min_confidence: int = 70, 
                            max_fp_rate: float = 0.1,
                            max_staleness_days: int = 90) -> bool:
        """
        Determine if IOC should be operationalized based on quality criteria
        
        Args:
            min_confidence: Minimum confidence threshold
            max_fp_rate: Maximum acceptable false positive rate
            max_staleness_days: Maximum age in days
            
        Returns:
            True if IOC meets operationalization criteria
        """
        if self.is_stale(max_staleness_days):
            logger.debug(f"IOC {self.ioc_id} rejected: stale")
            return False
        
        if self.confidence < min_confidence:
            logger.debug(f"IOC {self.ioc_id} rejected: low confidence ({self.confidence})")
            return False
        
        if self.false_positive_rate > max_fp_rate:
            logger.debug(f"IOC {self.ioc_id} rejected: high FP rate ({self.false_positive_rate})")
            return False
        
        return True
    
    def calculate_priority_score(self) -> float:
        """
        Calculate priority score using weighted algorithm
        
        Score = (Severity × 0.5) + (Confidence × 0.3) + (Recency × 0.2) - (FP_Rate × 0.2)
        
        Returns:
            Priority score (0-100 scale)
        """
        # Severity component (0-50 points)
        severity_score = self.severity.value * 10
        
        # Confidence component (0-30 points)
        confidence_score = (self.confidence / 100) * 30
        
        # Recency component (0-20 points)
        age_days = (datetime.now() - self.last_seen).days
        recency_score = max(0, 20 - (age_days / 5))
        
        # False positive penalty
        fp_penalty = self.false_positive_rate * 20
        
        total_score = severity_score + confidence_score + recency_score - fp_penalty
        return max(0, min(100, total_score))


class ThreatIntelligenceOrchestrator:
    """
    Main orchestration class for threat intelligence operations
    
    This class manages the complete lifecycle of threat intelligence:
    1. Collection from multiple sources
    2. Normalization and deduplication
    3. Enrichment with context
    4. Prioritization based on risk
    5. Export to SIEM platforms
    """
    
    def __init__(self, config: Dict):
        """
        Initialize orchestrator
        
        Args:
            config: Configuration dictionary containing:
                - min_confidence: Minimum confidence threshold (default: 70)
                - max_false_positive_rate: Max FP rate (default: 0.1)
                - staleness_days: Days before IOC is stale (default: 90)
                - sources: List of source configurations
        """
        self.config = config
        self.ioc_storage: Dict[str, IOCIndicator] = {}
        self.statistics = {
            'total_collected': 0,
            'deduplicated': 0,
            'enriched': 0,
            'operationalized': 0,
            'rejected_low_confidence': 0,
            'rejected_stale': 0,
            'rejected_high_fp': 0,
            'processing_time': 0.0
        }
        
        # Extract configuration parameters
        self.min_confidence = config.get('min_confidence', 70)
        self.max_fp_rate = config.get('max_false_positive_rate', 0.1)
        self.staleness_days = config.get('staleness_days', 90)
        
        logger.info("Threat Intelligence Orchestrator initialized")
        logger.info(f"Configuration: min_confidence={self.min_confidence}, "
                   f"max_fp_rate={self.max_fp_rate}, staleness_days={self.staleness_days}")
    
    def process_pipeline(self, raw_iocs: List[IOCIndicator]) -> List[IOCIndicator]:
        """
        Execute full processing pipeline
        
        Args:
            raw_iocs: List of raw IOC indicators from collection
            
        Returns:
            List of operationalized IOCs ready for SIEM integration
        """
        start_time = datetime.now()
        logger.info(f"Starting pipeline with {len(raw_iocs)} raw IOCs")
        
        # Step 1: Normalize and deduplicate
        unique_iocs = self.normalize_and_deduplicate(raw_iocs)
        
        # Step 2: Enrich with context
        enriched_iocs = self.enrich_indicators(unique_iocs)
        
        # Step 3: Prioritize
        prioritized_iocs = self.prioritize_indicators(enriched_iocs)
        
        # Step 4: Filter for operationalization
        operational_iocs = self.filter_for_operationalization(prioritized_iocs)
        
        # Update statistics
        self.statistics['processing_time'] = (datetime.now() - start_time).total_seconds()
        
        logger.info(f"Pipeline complete: {len(operational_iocs)} IOCs ready for operationalization")
        logger.info(f"Processing time: {self.statistics['processing_time']:.2f}s")
        
        return operational_iocs
    
    def normalize_and_deduplicate(self, iocs: List[IOCIndicator]) -> List[IOCIndicator]:
        """
        Normalize formats and remove duplicates
        
        Args:
            iocs: List of IOC indicators
            
        Returns:
            Deduplicated list of IOCs with normalized values
        """
        unique_iocs = {}
        
        for ioc in iocs:
            try:
                # Normalize the indicator value
                normalized_value = self._normalize_indicator(
                    ioc.indicator_value, 
                    ioc.indicator_type
                )
                ioc.indicator_value = normalized_value
                
                # Check for duplicates using IOC ID
                if ioc.ioc_id in unique_iocs:
                    # Merge with existing IOC - keep most recent
                    existing = unique_iocs[ioc.ioc_id]
                    if ioc.last_seen > existing.last_seen:
                        # Update with newer data
                        unique_iocs[ioc.ioc_id] = self._merge_iocs(existing, ioc)
                    self.statistics['deduplicated'] += 1
                else:
                    unique_iocs[ioc.ioc_id] = ioc
                    
            except Exception as e:
                logger.error(f"Error normalizing IOC: {str(e)}")
                continue
        
        logger.info(f"Normalized and deduplicated: {len(unique_iocs)} unique IOCs "
                   f"({self.statistics['deduplicated']} duplicates removed)")
        
        return list(unique_iocs.values())
    
    def _normalize_indicator(self, value: str, ioc_type: IOCType) -> str:
        """
        Normalize indicator values to standard formats
        
        Args:
            value: Raw indicator value
            ioc_type: Type of indicator
            
        Returns:
            Normalized indicator value
        """
        value = value.strip()
        
        if ioc_type == IOCType.DOMAIN:
            # Remove protocol and trailing slash
            value = value.replace('http://', '').replace('https://', '')
            value = value.split('/')[0]  # Remove path
            value = value.lower()
        
        elif ioc_type == IOCType.URL:
            value = value.lower()
        
        elif ioc_type in [IOCType.FILE_HASH_MD5, IOCType.FILE_HASH_SHA1, IOCType.FILE_HASH_SHA256]:
            # Consistent case for hashes
            value = value.upper().replace(' ', '')
        
        elif ioc_type == IOCType.IP_ADDRESS:
            # Remove leading zeros from IP octets
            try:
                parts = value.split('.')
                if len(parts) == 4:
                    value = '.'.join(str(int(part)) for part in parts)
            except ValueError:
                pass  # Keep original if not valid IP
        
        elif ioc_type == IOCType.EMAIL:
            value = value.lower()
        
        return value
    
    def _merge_iocs(self, existing: IOCIndicator, new: IOCIndicator) -> IOCIndicator:
        """
        Merge duplicate IOCs, keeping best data from each
        
        Args:
            existing: Existing IOC
            new: New IOC with same ID
            
        Returns:
            Merged IOC
        """
        # Use higher confidence
        if new.confidence > existing.confidence:
            existing.confidence = new.confidence
        
        # Use more severe severity
        if new.severity.value > existing.severity.value:
            existing.severity = new.severity
        
        # Merge tags
        existing.tags = list(set(existing.tags + new.tags))
        
        # Merge MITRE mappings
        existing.mitre_tactics = list(set(existing.mitre_tactics + new.mitre_tactics))
        existing.mitre_techniques = list(set(existing.mitre_techniques + new.mitre_techniques))
        
        # Update timestamps
        if new.first_seen < existing.first_seen:
            existing.first_seen = new.first_seen
        if new.last_seen > existing.last_seen:
            existing.last_seen = new.last_seen
        
        # Update description if new one is longer
        if len(new.description) > len(existing.description):
            existing.description = new.description
        
        return existing
    
    def enrich_indicators(self, iocs: List[IOCIndicator]) -> List[IOCIndicator]:
        """
        Enrich IOCs with additional context
        
        Args:
            iocs: List of IOC indicators
            
        Returns:
            Enriched list of IOCs
        """
        enriched = []
        
        for ioc in iocs:
            try:
                # Add contextual enrichment (placeholder for external API calls)
                ioc = self._enrich_with_context(ioc)
                
                # Map to MITRE ATT&CK
                ioc = self._map_to_mitre(ioc)
                
                enriched.append(ioc)
                self.statistics['enriched'] += 1
            except Exception as e:
                logger.error(f"Error enriching IOC {ioc.ioc_id}: {str(e)}")
                enriched.append(ioc)  # Include even if enrichment fails
        
        logger.info(f"Enriched {len(enriched)} indicators")
        return enriched
    
    def _enrich_with_context(self, ioc: IOCIndicator) -> IOCIndicator:
        """
        Add contextual information to IOC
        In production, this would call external enrichment services
        
        Args:
            ioc: IOC indicator
            
        Returns:
            Enriched IOC
        """
        # Placeholder for enrichment logic
        # In production, integrate with:
        # - VirusTotal
        # - PassiveTotal
        # - Shodan
        # - AbuseIPDB reputation check
        # - Geolocation services
        
        return ioc
    
    def _map_to_mitre(self, ioc: IOCIndicator) -> IOCIndicator:
        """
        Map IOC to MITRE ATT&CK framework based on tags and context
        
        Args:
            ioc: IOC indicator
            
        Returns:
            IOC with MITRE mappings
        """
        # Simple tag-based mapping (expand with more sophisticated logic)
        tag_to_technique = {
            'ransomware': ['T1486', 'T1490'],  # Data Encrypted for Impact, Inhibit System Recovery
            'phishing': ['T1566'],  # Phishing
            'malware': ['T1204'],  # User Execution
            'c2': ['T1071', 'T1095'],  # Application Layer Protocol, Non-Application Layer Protocol
            'lateral-movement': ['T1021'],  # Remote Services
            'credential-access': ['T1003', 'T1110'],  # OS Credential Dumping, Brute Force
            'persistence': ['T1547'],  # Boot or Logon Autostart Execution
        }
        
        for tag in ioc.tags:
            if tag in tag_to_technique:
                ioc.mitre_techniques.extend(tag_to_technique[tag])
        
        # Remove duplicates
        ioc.mitre_techniques = list(set(ioc.mitre_techniques))
        
        return ioc
    
    def prioritize_indicators(self, iocs: List[IOCIndicator]) -> List[IOCIndicator]:
        """
        Prioritize IOCs based on calculated priority scores
        
        Args:
            iocs: List of IOC indicators
            
        Returns:
            Sorted list of prioritized IOCs (highest priority first)
        """
        # Calculate priority scores
        for ioc in iocs:
            ioc.priority_score = ioc.calculate_priority_score()
        
        # Sort by priority score (highest first)
        prioritized = sorted(iocs, key=lambda x: x.priority_score, reverse=True)
        
        logger.info(f"Prioritized {len(prioritized)} indicators")
        if prioritized:
            logger.info(f"Top priority score: {prioritized[0].priority_score:.2f}")
            logger.info(f"Lowest priority score: {prioritized[-1].priority_score:.2f}")
        
        return prioritized
    
    def filter_for_operationalization(self, iocs: List[IOCIndicator]) -> List[IOCIndicator]:
        """
        Filter IOCs that meet criteria for operationalization
        
        Args:
            iocs: List of IOC indicators
            
        Returns:
            Filtered list ready for SIEM integration
        """
        operational_iocs = []
        
        for ioc in iocs:
            if ioc.should_operationalize(
                self.min_confidence, 
                self.max_fp_rate,
                self.staleness_days
            ):
                operational_iocs.append(ioc)
                self.statistics['operationalized'] += 1
            else:
                # Track rejection reasons
                if ioc.confidence < self.min_confidence:
                    self.statistics['rejected_low_confidence'] += 1
                if ioc.is_stale(self.staleness_days):
                    self.statistics['rejected_stale'] += 1
                if ioc.false_positive_rate > self.max_fp_rate:
                    self.statistics['rejected_high_fp'] += 1
        
        logger.info(f"Filtered to {len(operational_iocs)} operational indicators")
        logger.info(f"Rejected - Low confidence: {self.statistics['rejected_low_confidence']}, "
                   f"Stale: {self.statistics['rejected_stale']}, "
                   f"High FP: {self.statistics['rejected_high_fp']}")
        
        return operational_iocs
    
    def export_for_siem(self, iocs: List[IOCIndicator], format_type: str = 'json') -> str:
        """
        Export IOCs in SIEM-compatible format
        
        Args:
            iocs: List of IOC indicators
            format_type: Export format ('json', 'csv', 'stix', 'cef', 'leef')
            
        Returns:
            Formatted string for SIEM ingestion
        """
        if format_type == 'json':
            return self._export_json(iocs)
        elif format_type == 'csv':
            return self._export_csv(iocs)
        elif format_type == 'stix':
            return self._export_stix(iocs)
        elif format_type == 'cef':
            return self._export_cef(iocs)
        elif format_type == 'leef':
            return self._export_leef(iocs)
        else:
            raise ValueError(f"Unsupported format: {format_type}")
    
    def _export_json(self, iocs: List[IOCIndicator]) -> str:
        """Export as JSON"""
        data = {
            'export_timestamp': datetime.now().isoformat(),
            'indicator_count': len(iocs),
            'statistics': self.statistics,
            'indicators': [ioc.to_dict() for ioc in iocs]
        }
        return json.dumps(data, indent=2)
    
    def _export_csv(self, iocs: List[IOCIndicator]) -> str:
        """Export as CSV"""
        import csv
        import io
        
        output = io.StringIO()
        fieldnames = [
            'indicator_value', 'indicator_type', 'severity', 'confidence', 
            'source', 'description', 'tags', 'threat_actor', 'campaign',
            'first_seen', 'last_seen', 'mitre_techniques', 'tlp'
        ]
        
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        for ioc in iocs:
            row = {
                'indicator_value': ioc.indicator_value,
                'indicator_type': ioc.indicator_type.value,
                'severity': ioc.severity.name,
                'confidence': ioc.confidence,
                'source': ioc.source,
                'description': ioc.description,
                'tags': '|'.join(ioc.tags),
                'threat_actor': ioc.threat_actor or '',
                'campaign': ioc.campaign or '',
                'first_seen': ioc.first_seen.isoformat(),
                'last_seen': ioc.last_seen.isoformat(),
                'mitre_techniques': '|'.join(ioc.mitre_techniques),
                'tlp': ioc.tlp
            }
            writer.writerow(row)
        
        return output.getvalue()
    
    def _export_stix(self, iocs: List[IOCIndicator]) -> str:
        """Export as STIX 2.1 format"""
        stix_bundle = {
            'type': 'bundle',
            'id': f"bundle--{hashlib.sha256(str(datetime.now()).encode()).hexdigest()}",
            'objects': []
        }
        
        for ioc in iocs:
            # Create STIX indicator object
            pattern_type = self._get_stix_pattern_type(ioc.indicator_type)
            pattern = f"[{pattern_type}:value = '{ioc.indicator_value}']"
            
            indicator = {
                'type': 'indicator',
                'spec_version': '2.1',
                'id': f"indicator--{ioc.ioc_id}",
                'created': ioc.first_seen.isoformat() + 'Z',
                'modified': ioc.last_seen.isoformat() + 'Z',
                'name': f"{ioc.indicator_type.value}: {ioc.indicator_value}",
                'description': ioc.description,
                'pattern': pattern,
                'pattern_type': 'stix',
                'valid_from': ioc.first_seen.isoformat() + 'Z',
                'labels': ioc.tags,
                'confidence': ioc.confidence,
                'external_references': [{
                    'source_name': ioc.source,
                    'description': f"Threat severity: {ioc.severity.name}"
                }]
            }
            
            if ioc.threat_actor:
                indicator['threat_actor'] = ioc.threat_actor
            
            if ioc.mitre_techniques:
                indicator['kill_chain_phases'] = [
                    {'kill_chain_name': 'mitre-attack', 'phase_name': tech}
                    for tech in ioc.mitre_techniques
                ]
            
            stix_bundle['objects'].append(indicator)
        
        return json.dumps(stix_bundle, indent=2)
    
    def _get_stix_pattern_type(self, ioc_type: IOCType) -> str:
        """Map IOC type to STIX pattern type"""
        mapping = {
            IOCType.IP_ADDRESS: 'ipv4-addr',
            IOCType.DOMAIN: 'domain-name',
            IOCType.URL: 'url',
            IOCType.FILE_HASH_MD5: 'file',
            IOCType.FILE_HASH_SHA1: 'file',
            IOCType.FILE_HASH_SHA256: 'file',
            IOCType.EMAIL: 'email-addr',
        }
        return mapping.get(ioc_type, 'unknown')
    
    def _export_cef(self, iocs: List[IOCIndicator]) -> str:
        """Export as Common Event Format (CEF) for ArcSight/Splunk"""
        cef_events = []
        
        for ioc in iocs:
            # CEF Format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
            cef = f"CEF:0|ThreatIntel|Automation|1.0|{ioc.indicator_type.value}|IOC Detected|{ioc.severity.value}|"
            cef += f"src={ioc.indicator_value} "
            cef += f"cn1={ioc.confidence} cn1Label=Confidence "
            cef += f"cs1={ioc.source} cs1Label=Source "
            cef += f"cs2={'|'.join(ioc.tags)} cs2Label=Tags "
            cef += f"msg={ioc.description}"
            
            cef_events.append(cef)
        
        return '\n'.join(cef_events)
    
    def _export_leef(self, iocs: List[IOCIndicator]) -> str:
        """Export as Log Event Extended Format (LEEF) for QRadar"""
        leef_events = []
        
        for ioc in iocs:
            # LEEF Format: LEEF:Version|Vendor|Product|Version|EventID|
            leef = f"LEEF:2.0|ThreatIntel|Automation|1.0|IOC|"
            leef += f"devTime={ioc.last_seen.isoformat()}\t"
            leef += f"src={ioc.indicator_value}\t"
            leef += f"cat={ioc.indicator_type.value}\t"
            leef += f"sev={ioc.severity.value}\t"
            leef += f"confidence={ioc.confidence}\t"
            leef += f"source={ioc.source}\t"
            leef += f"tags={'|'.join(ioc.tags)}"
            
            leef_events.append(leef)
        
        return '\n'.join(leef_events)
    
    def get_statistics(self) -> Dict:
        """Get processing statistics"""
        stats = self.statistics.copy()
        
        # Calculate efficiency metrics
        if stats['total_collected'] > 0:
            stats['deduplication_rate'] = (stats['deduplicated'] / stats['total_collected']) * 100
            stats['operationalization_rate'] = (stats['operationalized'] / stats['total_collected']) * 100
        
        return stats
    
    def reset_statistics(self):
        """Reset all statistics counters"""
        for key in self.statistics:
            if isinstance(self.statistics[key], (int, float)):
                self.statistics[key] = 0
        
        logger.info("Statistics reset")
