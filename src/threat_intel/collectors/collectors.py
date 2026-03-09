"""
Threat Intelligence Source Collectors
Implementations for collecting IOCs from various threat intelligence feeds
"""

import requests
import logging
from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta
from abc import ABC, abstractmethod
import time

from threat_intel.orchestrator import IOCIndicator, IOCType, ThreatSeverity

logger = logging.getLogger(__name__)


class ThreatIntelCollector(ABC):
    """Abstract base class for threat intelligence collectors"""
    
    def __init__(self, api_key: Optional[str] = None, config: Optional[Dict[str, Any]] = None):
        """
        Initialize collector
        
        Args:
            api_key: API key for the threat intelligence source
            config: Additional configuration parameters
        """
        self.api_key = api_key
        self.config = config or {}
        self.session = requests.Session()
        self.rate_limit_delay = self.config.get('rate_limit_delay', 1.0)
        self.timeout = self.config.get('timeout', 30)
        self.max_retries = self.config.get('max_retries', 3)
    
    @abstractmethod
    def collect(self) -> List[IOCIndicator]:
        """
        Collect IOCs from the source
        
        Returns:
            List of IOC indicators
        """
        pass
    
    def _respect_rate_limit(self):
        """Respect API rate limits"""
        time.sleep(self.rate_limit_delay)
    
    def _make_request(self, 
                     url: str, 
                     params: Optional[Dict[str, Any]] = None, 
                     headers: Optional[Dict[str, Any]] = None,
                     method: str = 'GET') -> Dict[str, Any]:
        """
        Make HTTP request with error handling and retries
        
        Args:
            url: Request URL
            params: Query parameters
            headers: Request headers
            method: HTTP method
            
        Returns:
            Response JSON data
        """
        for attempt in range(self.max_retries):
            try:
                self._respect_rate_limit()
                
                if method.upper() == 'GET':
                    response = self.session.get(
                        url, 
                        params=params, 
                        headers=headers, 
                        timeout=self.timeout
                    )
                elif method.upper() == 'POST':
                    response = self.session.post(
                        url, 
                        json=params, 
                        headers=headers, 
                        timeout=self.timeout
                    )
                else:
                    raise ValueError(f"Unsupported HTTP method: {method}")
                
                response.raise_for_status()
                return response.json()
                
            except requests.exceptions.Timeout:
                logger.warning(f"Request timeout for {url} (attempt {attempt + 1}/{self.max_retries})")
                if attempt == self.max_retries - 1:
                    logger.error(f"Max retries reached for {url}")
                    return {}
                time.sleep(2 ** attempt)  # Exponential backoff
                
            except requests.exceptions.RequestException as e:
                logger.error(f"Request failed for {url}: {str(e)}")
                if attempt == self.max_retries - 1:
                    return {}
                time.sleep(2 ** attempt)
        
        return {}


class AlienVaultOTXCollector(ThreatIntelCollector):
    """
    Collector for AlienVault Open Threat Exchange (OTX)
    
    API Documentation: https://otx.alienvault.com/api
    """
    
    def __init__(self, api_key: str, config: Optional[Dict[str, Any]] = None):
        super().__init__(api_key, config)
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.source_name = "AlienVault_OTX"
        self.lookback_days = config.get('lookback_days', 7) if config else 7
    
    def collect(self) -> List[IOCIndicator]:
        """Collect IOCs from AlienVault OTX"""
        iocs = []
        
        try:
            logger.info(f"Collecting from {self.source_name}")
            
            # Get subscribed pulses (threat intelligence packages)
            modified_since = (datetime.now() - timedelta(days=self.lookback_days)).isoformat()
            
            headers = {'X-OTX-API-KEY': self.api_key}
            params: Dict[str, Any] = {
                'modified_since': modified_since, 
                'limit': 50
            }
            
            url = f"{self.base_url}/pulses/subscribed"
            data = self._make_request(url, params=params, headers=headers)
            
            if 'results' in data:
                for pulse in data['results']:
                    pulse_iocs = self._parse_pulse(pulse)
                    iocs.extend(pulse_iocs)
            
            logger.info(f"Collected {len(iocs)} IOCs from {self.source_name}")
            
        except Exception as e:
            logger.error(f"Error collecting from {self.source_name}: {str(e)}")
        
        return iocs
    
    def _parse_pulse(self, pulse: Dict[str, Any]) -> List[IOCIndicator]:
        """Parse an OTX pulse and extract IOCs"""
        iocs: List[IOCIndicator] = []
        
        # Extract pulse metadata
        tags = pulse.get('tags', [])
        description = pulse.get('description', '')
        created = self._parse_timestamp(pulse.get('created'))
        modified = self._parse_timestamp(pulse.get('modified'))
        adversary = pulse.get('adversary', None)
        
        # Map TLP to confidence score
        tlp = pulse.get('TLP', 'white').lower()
        confidence_map = {
            'red': 95,
            'amber': 80,
            'green': 65,
            'white': 50
        }
        confidence = confidence_map.get(tlp, 50)
        
        # Process indicators
        for indicator in pulse.get('indicators', []):
            try:
                ioc_type = self._map_indicator_type(indicator.get('type'))
                if not ioc_type:
                    continue
                
                # Determine severity from tags
                severity = self._determine_severity(tags)
                
                ioc = IOCIndicator(
                    indicator_value=indicator.get('indicator', ''),
                    indicator_type=ioc_type,
                    source=self.source_name,
                    confidence=confidence,
                    severity=severity,
                    first_seen=created,
                    last_seen=modified,
                    description=description[:500],  # Truncate long descriptions
                    tags=tags,
                    threat_actor=adversary,
                    tlp=tlp
                )
                iocs.append(ioc)
                
            except Exception as e:
                logger.warning(f"Error parsing indicator from pulse: {str(e)}")
                continue
        
        return iocs
    
    def _map_indicator_type(self, otx_type: str) -> Optional[IOCType]:
        """Map OTX indicator types to IOCType enum"""
        mapping = {
            'IPv4': IOCType.IP_ADDRESS,
            'IPv6': IOCType.IP_ADDRESS,
            'domain': IOCType.DOMAIN,
            'hostname': IOCType.DOMAIN,
            'URL': IOCType.URL,
            'FileHash-MD5': IOCType.FILE_HASH_MD5,
            'FileHash-SHA1': IOCType.FILE_HASH_SHA1,
            'FileHash-SHA256': IOCType.FILE_HASH_SHA256,
            'email': IOCType.EMAIL,
            'Mutex': IOCType.MUTEX,
            'CVE': IOCType.CVE
        }
        return mapping.get(otx_type)
    
    def _determine_severity(self, tags: List[str]) -> ThreatSeverity:
        """Determine severity from tags"""
        high_severity_tags = ['ransomware', 'apt', 'zero-day', 'critical']
        medium_severity_tags = ['malware', 'trojan', 'backdoor']
        
        tags_lower = [tag.lower() for tag in tags]
        
        if any(tag in tags_lower for tag in high_severity_tags):
            return ThreatSeverity.HIGH
        elif any(tag in tags_lower for tag in medium_severity_tags):
            return ThreatSeverity.MEDIUM
        else:
            return ThreatSeverity.LOW
    
    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse ISO timestamp from OTX"""
        try:
            # Remove 'Z' and parse
            ts = timestamp_str.replace('Z', '+00:00') if timestamp_str else None
            return datetime.fromisoformat(ts) if ts else datetime.now()
        except:
            return datetime.now()


class AbuseIPDBCollector(ThreatIntelCollector):
    """
    Collector for AbuseIPDB
    
    API Documentation: https://docs.abuseipdb.com/
    """
    
    def __init__(self, api_key: str, config: Optional[Dict] = None):
        super().__init__(api_key, config)
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.source_name = "AbuseIPDB"
        self.min_confidence = config.get('min_confidence', 75) if config else 75
    
    def collect(self) -> List[IOCIndicator]:
        """Collect malicious IPs from AbuseIPDB blacklist"""
        iocs = []
        
        try:
            logger.info(f"Collecting from {self.source_name}")
            
            headers = {
                'Key': self.api_key,
                'Accept': 'application/json'
            }
            
            params = {
                'confidenceMinimum': self.min_confidence,
                'limit': 10000
            }
            
            url = f"{self.base_url}/blacklist"
            data = self._make_request(url, params=params, headers=headers)
            
            if 'data' in data:
                for entry in data['data']:
                    ioc = self._parse_ip_entry(entry)
                    if ioc:
                        iocs.append(ioc)
            
            logger.info(f"Collected {len(iocs)} IOCs from {self.source_name}")
            
        except Exception as e:
            logger.error(f"Error collecting from {self.source_name}: {str(e)}")
        
        return iocs
    
    def _parse_ip_entry(self, entry: Dict) -> Optional[IOCIndicator]:
        """Parse an IP entry from AbuseIPDB"""
        try:
            confidence = entry.get('abuseConfidenceScore', 0)
            
            # Map abuse confidence score to severity
            if confidence >= 90:
                severity = ThreatSeverity.CRITICAL
            elif confidence >= 75:
                severity = ThreatSeverity.HIGH
            elif confidence >= 50:
                severity = ThreatSeverity.MEDIUM
            else:
                severity = ThreatSeverity.LOW
            
            last_reported = entry.get('lastReportedAt', datetime.now().isoformat())
            num_reports = entry.get('numDistinctUsers', 0)
            
            ioc = IOCIndicator(
                indicator_value=entry.get('ipAddress', ''),
                indicator_type=IOCType.IP_ADDRESS,
                source=self.source_name,
                confidence=confidence,
                severity=severity,
                first_seen=datetime.now() - timedelta(days=30),
                last_seen=datetime.fromisoformat(last_reported.replace('Z', '+00:00')),
                description=f"Reported {num_reports} times for abusive behavior",
                tags=['malicious-ip', 'abusive-behavior'],
                false_positive_rate=0.05  # AbuseIPDB has low FP rate
            )
            return ioc
            
        except Exception as e:
            logger.warning(f"Error parsing IP entry: {str(e)}")
            return None


class MISPCollector(ThreatIntelCollector):
    """
    Collector for MISP (Malware Information Sharing Platform)
    
    API Documentation: https://www.misp-project.org/openapi/
    """
    
    def __init__(self, api_key: str, config: Dict):
        super().__init__(api_key, config)
        self.base_url = config.get('misp_url', 'https://misp.instance.org')
        self.source_name = "MISP"
        self.verify_ssl = config.get('verify_ssl', True)
        self.lookback_days = config.get('lookback_days', 7)
    
    def collect(self) -> List[IOCIndicator]:
        """Collect IOCs from MISP"""
        iocs = []
        
        try:
            logger.info(f"Collecting from {self.source_name}")
            
            headers = {
                'Authorization': self.api_key,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
            
            # Search for recent published attributes
            search_params = {
                'returnFormat': 'json',
                'published': 1,
                'timestamp': f'{self.lookback_days}d'
            }
            
            url = f"{self.base_url}/attributes/restSearch"
            
            # Modify session to handle SSL
            original_verify = self.session.verify
            self.session.verify = self.verify_ssl
            
            data = self._make_request(url, params=search_params, headers=headers, method='POST')
            
            # Restore original verify setting
            self.session.verify = original_verify
            
            if 'response' in data and 'Attribute' in data['response']:
                for attribute in data['response']['Attribute']:
                    ioc = self._parse_attribute(attribute)
                    if ioc:
                        iocs.append(ioc)
            
            logger.info(f"Collected {len(iocs)} IOCs from {self.source_name}")
            
        except Exception as e:
            logger.error(f"Error collecting from {self.source_name}: {str(e)}")
        
        return iocs
    
    def _parse_attribute(self, attribute: Dict) -> Optional[IOCIndicator]:
        """Parse a MISP attribute"""
        try:
            # Map MISP types to our IOC types
            misp_type = attribute.get('type')
            ioc_type = self._map_misp_type(misp_type)
            
            if not ioc_type:
                return None
            
            # Extract tags
            tags = [tag['name'] for tag in attribute.get('Tag', [])]
            
            # Determine severity and confidence from MISP threat level
            threat_level = attribute.get('Event', {}).get('threat_level_id', 3)
            severity, confidence = self._map_threat_level(threat_level)
            
            ioc = IOCIndicator(
                indicator_value=attribute.get('value', ''),
                indicator_type=ioc_type,
                source=self.source_name,
                confidence=confidence,
                severity=severity,
                first_seen=datetime.fromtimestamp(int(attribute.get('timestamp', 0))),
                last_seen=datetime.now(),
                description=attribute.get('comment', ''),
                tags=tags,
                tlp=self._extract_tlp(tags)
            )
            return ioc
            
        except Exception as e:
            logger.warning(f"Error parsing MISP attribute: {str(e)}")
            return None
    
    def _map_misp_type(self, misp_type: str) -> Optional[IOCType]:
        """Map MISP attribute types to IOCType"""
        mapping = {
            'ip-src': IOCType.IP_ADDRESS,
            'ip-dst': IOCType.IP_ADDRESS,
            'domain': IOCType.DOMAIN,
            'hostname': IOCType.DOMAIN,
            'url': IOCType.URL,
            'md5': IOCType.FILE_HASH_MD5,
            'sha1': IOCType.FILE_HASH_SHA1,
            'sha256': IOCType.FILE_HASH_SHA256,
            'email-src': IOCType.EMAIL,
            'email-dst': IOCType.EMAIL,
            'mutex': IOCType.MUTEX,
            'user-agent': IOCType.USER_AGENT
        }
        return mapping.get(misp_type)
    
    def _map_threat_level(self, threat_level: int) -> tuple:
        """Map MISP threat level to severity and confidence"""
        mapping = {
            1: (ThreatSeverity.HIGH, 90),      # High threat
            2: (ThreatSeverity.MEDIUM, 75),    # Medium threat
            3: (ThreatSeverity.LOW, 60),       # Low threat
            4: (ThreatSeverity.INFO, 50)       # Undefined
        }
        return mapping.get(threat_level, (ThreatSeverity.LOW, 50))
    
    def _extract_tlp(self, tags: List[str]) -> str:
        """Extract TLP from tags"""
        for tag in tags:
            tag_lower = tag.lower()
            if 'tlp:red' in tag_lower:
                return 'red'
            elif 'tlp:amber' in tag_lower:
                return 'amber'
            elif 'tlp:green' in tag_lower:
                return 'green'
            elif 'tlp:white' in tag_lower:
                return 'white'
        return 'white'


class AbuseCHCollector(ThreatIntelCollector):
    """
    Collector for Abuse.ch threat feeds
    Multiple feeds: URLhaus, ThreatFox, SSLBlacklist, etc.
    
    API Documentation: https://abuse.ch/
    """
    
    def __init__(self, config: Optional[Dict] = None):
        super().__init__(None, config)  # No API key required for public feeds
        self.source_name = "AbuseCH"
        self.feed_type = config.get('feed_type', 'threatfox') if config else 'threatfox'
    
    def collect(self) -> List[IOCIndicator]:
        """Collect IOCs from Abuse.ch"""
        if self.feed_type == 'threatfox':
            return self._collect_threatfox()
        elif self.feed_type == 'urlhaus':
            return self._collect_urlhaus()
        else:
            logger.error(f"Unsupported feed type: {self.feed_type}")
            return []
    
    def _collect_threatfox(self) -> List[IOCIndicator]:
        """Collect from ThreatFox feed"""
        iocs = []
        
        try:
            logger.info(f"Collecting from {self.source_name}/ThreatFox")
            
            url = "https://threatfox-api.abuse.ch/api/v1/"
            params = {
                'query': 'get_iocs',
                'days': 7
            }
            
            data = self._make_request(url, params=params, method='POST')
            
            if data.get('query_status') == 'ok' and 'data' in data:
                for entry in data['data']:
                    ioc = self._parse_threatfox_entry(entry)
                    if ioc:
                        iocs.append(ioc)
            
            logger.info(f"Collected {len(iocs)} IOCs from ThreatFox")
            
        except Exception as e:
            logger.error(f"Error collecting from ThreatFox: {str(e)}")
        
        return iocs
    
    def _parse_threatfox_entry(self, entry: Dict) -> Optional[IOCIndicator]:
        """Parse ThreatFox entry"""
        try:
            ioc_type_map = {
                'ip:port': IOCType.IP_ADDRESS,
                'domain': IOCType.DOMAIN,
                'url': IOCType.URL,
                'md5_hash': IOCType.FILE_HASH_MD5,
                'sha256_hash': IOCType.FILE_HASH_SHA256
            }
            
            ioc_type = ioc_type_map.get(entry.get('ioc_type'))
            if not ioc_type:
                return None
            
            # Parse timestamps
            first_seen = datetime.strptime(entry.get('first_seen', ''), '%Y-%m-%d %H:%M:%S')
            
            ioc = IOCIndicator(
                indicator_value=entry.get('ioc', ''),
                indicator_type=ioc_type,
                source=f"{self.source_name}/ThreatFox",
                confidence=int(entry.get('confidence_level', 50)),
                severity=ThreatSeverity.HIGH,
                first_seen=first_seen,
                last_seen=first_seen,
                description=entry.get('malware', 'Unknown'),
                tags=[entry.get('threat_type', '')],
                false_positive_rate=0.05
            )
            return ioc
            
        except Exception as e:
            logger.warning(f"Error parsing ThreatFox entry: {str(e)}")
            return None
    
    def _collect_urlhaus(self) -> List[IOCIndicator]:
        """Collect from URLhaus feed"""
        iocs = []
        
        try:
            logger.info(f"Collecting from {self.source_name}/URLhaus")
            
            url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
            data = self._make_request(url, method='POST')
            
            if data.get('query_status') == 'ok' and 'urls' in data:
                for entry in data['urls']:
                    ioc = self._parse_urlhaus_entry(entry)
                    if ioc:
                        iocs.append(ioc)
            
            logger.info(f"Collected {len(iocs)} IOCs from URLhaus")
            
        except Exception as e:
            logger.error(f"Error collecting from URLhaus: {str(e)}")
        
        return iocs
    
    def _parse_urlhaus_entry(self, entry: Dict) -> Optional[IOCIndicator]:
        """Parse URLhaus entry"""
        try:
            # Parse timestamp
            date_added = datetime.strptime(
                entry.get('dateadded', ''), 
                '%Y-%m-%d %H:%M:%S'
            )
            
            # Determine severity from threat status
            threat = entry.get('threat', 'unknown')
            severity = ThreatSeverity.HIGH if 'malware' in threat.lower() else ThreatSeverity.MEDIUM
            
            ioc = IOCIndicator(
                indicator_value=entry.get('url', ''),
                indicator_type=IOCType.URL,
                source=f"{self.source_name}/URLhaus",
                confidence=75,
                severity=severity,
                first_seen=date_added,
                last_seen=date_added,
                description=f"Malicious URL - {threat}",
                tags=[threat, 'malware-distribution'],
                false_positive_rate=0.08
            )
            return ioc
            
        except Exception as e:
            logger.warning(f"Error parsing URLhaus entry: {str(e)}")
            return None


# Factory function for easy collector instantiation
def create_collector(source_name: str, api_key: Optional[str] = None, config: Optional[Dict] = None) -> ThreatIntelCollector:
    """
    Factory function to create collectors
    
    Args:
        source_name: Name of the threat intelligence source
        api_key: API key (if required)
        config: Configuration dictionary
        
    Returns:
        Initialized collector instance
    """
    collectors = {
        'otx': AlienVaultOTXCollector,
        'alienvault': AlienVaultOTXCollector,
        'abuseipdb': AbuseIPDBCollector,
        'misp': MISPCollector,
        'abuse.ch': AbuseCHCollector,
        'abusech': AbuseCHCollector,
        'threatfox': AbuseCHCollector,
        'urlhaus': AbuseCHCollector
    }
    
    collector_class = collectors.get(source_name.lower())
    if not collector_class:
        raise ValueError(f"Unknown collector: {source_name}")
    
    if collector_class == AbuseCHCollector:
        return collector_class(config)
    elif collector_class == MISPCollector:
        if not config:
            raise ValueError("MISP collector requires configuration")
        return collector_class(api_key, config)
    else:
        return collector_class(api_key, config)
