"""
Splunk SIEM Integration Module
Pushes threat intelligence IOCs to Splunk via HTTP Event Collector (HEC)
"""

import json
import logging
from typing import List, Dict, Optional
import requests
from datetime import datetime

from threat_intel.orchestrator import IOCIndicator

logger = logging.getLogger(__name__)


class SplunkConnector:
    """
    Splunk HTTP Event Collector (HEC) integration
    
    Pushes IOCs to Splunk for SIEM correlation and detection
    """
    
    def __init__(self, config: Dict):
        """
        Initialize Splunk connector
        
        Args:
            config: Configuration dictionary containing:
                - url: Splunk HEC endpoint URL
                - token: HEC authentication token
                - index: Target Splunk index
                - source: Event source name (default: threat_intel)
                - sourcetype: Event sourcetype (default: threat_intel:ioc)
                - verify_ssl: SSL verification (default: True)
        """
        self.url = config.get('url')
        self.token = config.get('token')
        self.index = config.get('index', 'threat_intel')
        self.source = config.get('source', 'threat_intel')
        self.sourcetype = config.get('sourcetype', 'threat_intel:ioc')
        self.verify_ssl = config.get('verify_ssl', True)
        
        if not self.url or not self.token:
            raise ValueError("Splunk URL and token are required")
        
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Splunk {self.token}',
            'Content-Type': 'application/json'
        })
        
        logger.info(f"Splunk connector initialized for index: {self.index}")
    
    def push_iocs(self, iocs: List[IOCIndicator], batch_size: int = 100) -> Dict:
        """
        Push IOCs to Splunk HEC
        
        Args:
            iocs: List of IOC indicators
            batch_size: Number of events per batch
            
        Returns:
            Dictionary with push statistics
        """
        results = {
            'success_count': 0,
            'failure_count': 0,
            'errors': []
        }
        
        logger.info(f"Pushing {len(iocs)} IOCs to Splunk")
        
        # Process in batches
        for i in range(0, len(iocs), batch_size):
            batch = iocs[i:i + batch_size]
            
            try:
                batch_result = self._push_batch(batch)
                results['success_count'] += batch_result['success']
                results['failure_count'] += batch_result['failure']
                
                if batch_result.get('errors'):
                    results['errors'].extend(batch_result['errors'])
                    
            except Exception as e:
                logger.error(f"Error pushing batch: {str(e)}")
                results['failure_count'] += len(batch)
                results['errors'].append(str(e))
        
        logger.info(f"Splunk push complete: {results['success_count']} successful, "
                   f"{results['failure_count']} failed")
        
        return results
    
    def _push_batch(self, iocs: List[IOCIndicator]) -> Dict:
        """Push a batch of IOCs"""
        events = []
        
        for ioc in iocs:
            event = self._create_splunk_event(ioc)
            events.append(event)
        
        # Send batch to HEC
        try:
            response = self.session.post(
                self.url,
                data='\n'.join(json.dumps(e) for e in events),
                verify=self.verify_ssl,
                timeout=30
            )
            
            if response.status_code == 200:
                return {'success': len(iocs), 'failure': 0}
            else:
                logger.error(f"Splunk HEC error: {response.status_code} - {response.text}")
                return {
                    'success': 0, 
                    'failure': len(iocs),
                    'errors': [response.text]
                }
                
        except Exception as e:
            logger.error(f"Error sending batch to Splunk: {str(e)}")
            return {
                'success': 0,
                'failure': len(iocs),
                'errors': [str(e)]
            }
    
    def _create_splunk_event(self, ioc: IOCIndicator) -> Dict:
        """
        Create Splunk HEC event from IOC
        
        Args:
            ioc: IOC indicator
            
        Returns:
            Splunk event dictionary
        """
        event_data = {
            'ioc_id': ioc.ioc_id,
            'indicator_value': ioc.indicator_value,
            'indicator_type': ioc.indicator_type.value,
            'severity': ioc.severity.name,
            'severity_level': ioc.severity.value,
            'confidence': ioc.confidence,
            'source': ioc.source,
            'description': ioc.description,
            'tags': ioc.tags,
            'first_seen': ioc.first_seen.isoformat(),
            'last_seen': ioc.last_seen.isoformat(),
            'false_positive_rate': ioc.false_positive_rate,
            'tlp': ioc.tlp
        }
        
        # Add optional fields
        if ioc.threat_actor:
            event_data['threat_actor'] = ioc.threat_actor
        
        if ioc.campaign:
            event_data['campaign'] = ioc.campaign
        
        if ioc.mitre_techniques:
            event_data['mitre_techniques'] = ioc.mitre_techniques
        
        if ioc.mitre_tactics:
            event_data['mitre_tactics'] = ioc.mitre_tactics
        
        # Create Splunk event
        splunk_event = {
            'time': int(ioc.last_seen.timestamp()),
            'host': 'threat-intel-automation',
            'source': self.source,
            'sourcetype': self.sourcetype,
            'index': self.index,
            'event': event_data
        }
        
        return splunk_event
    
    def create_lookup_table(self, iocs: List[IOCIndicator], filename: str) -> bool:
        """
        Create Splunk lookup table CSV from IOCs
        
        Args:
            iocs: List of IOC indicators
            filename: Output filename
            
        Returns:
            True if successful
        """
        try:
            import csv
            
            with open(filename, 'w', newline='') as f:
                fieldnames = [
                    'indicator_value', 'indicator_type', 'severity',
                    'confidence', 'source', 'description', 'tags',
                    'threat_actor', 'campaign', 'mitre_techniques'
                ]
                
                writer = csv.DictWriter(f, fieldnames=fieldnames)
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
                        'mitre_techniques': '|'.join(ioc.mitre_techniques)
                    }
                    writer.writerow(row)
            
            logger.info(f"Created Splunk lookup table: {filename}")
            return True
            
        except Exception as e:
            logger.error(f"Error creating lookup table: {str(e)}")
            return False
    
    def test_connection(self) -> bool:
        """
        Test Splunk HEC connection
        
        Returns:
            True if connection successful
        """
        try:
            # Send test event
            test_event = {
                'time': int(datetime.now().timestamp()),
                'host': 'threat-intel-automation',
                'source': self.source,
                'sourcetype': self.sourcetype,
                'index': self.index,
                'event': {
                    'message': 'Connection test',
                    'test': True
                }
            }
            
            response = self.session.post(
                self.url,
                data=json.dumps(test_event),
                verify=self.verify_ssl,
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info("Splunk connection test successful")
                return True
            else:
                logger.error(f"Splunk connection test failed: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Splunk connection test failed: {str(e)}")
            return False
