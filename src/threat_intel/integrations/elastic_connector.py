"""
Elastic Stack (ELK) SIEM Integration Module
Pushes threat intelligence IOCs to Elasticsearch
"""

import json
import logging
from typing import List, Dict, Optional
from datetime import datetime

try:
    from elasticsearch import Elasticsearch, helpers
    ELASTICSEARCH_AVAILABLE = True
except ImportError:
    ELASTICSEARCH_AVAILABLE = False
    logger.warning("elasticsearch package not installed. Install with: pip install elasticsearch")

from threat_intel.orchestrator import IOCIndicator

logger = logging.getLogger(__name__)


class ElasticConnector:
    """
    Elasticsearch integration for threat intelligence
    
    Pushes IOCs to Elasticsearch using bulk API with ECS field mapping
    """
    
    def __init__(self, config: Dict):
        """
        Initialize Elastic connector
        
        Args:
            config: Configuration dictionary containing:
                - hosts: List of Elasticsearch host URLs
                - api_key: Elasticsearch API key
                - index: Target index name
                - username: Basic auth username (alternative to api_key)
                - password: Basic auth password
                - verify_ssl: SSL verification (default: True)
        """
        if not ELASTICSEARCH_AVAILABLE:
            raise ImportError("elasticsearch package required. Install with: pip install elasticsearch")
        
        self.hosts = config.get('hosts', ['http://localhost:9200'])
        self.index = config.get('index', 'threat-intel')
        self.verify_ssl = config.get('verify_ssl', True)
        
        # Authentication setup
        auth_params = {}
        
        if 'api_key' in config:
            auth_params['api_key'] = config['api_key']
        elif 'username' in config and 'password' in config:
            auth_params['basic_auth'] = (config['username'], config['password'])
        
        try:
            self.es = Elasticsearch(
                self.hosts,
                verify_certs=self.verify_ssl,
                **auth_params
            )
            
            # Test connection
            if self.es.ping():
                logger.info(f"Elasticsearch connector initialized for index: {self.index}")
            else:
                raise ConnectionError("Failed to connect to Elasticsearch")
                
        except Exception as e:
            logger.error(f"Failed to initialize Elasticsearch: {str(e)}")
            raise
    
    def push_iocs(self, iocs: List[IOCIndicator]) -> Dict:
        """
        Push IOCs to Elasticsearch using bulk API
        
        Args:
            iocs: List of IOC indicators
            
        Returns:
            Dictionary with push statistics
        """
        results = {
            'success_count': 0,
            'failure_count': 0,
            'errors': []
        }
        
        logger.info(f"Pushing {len(iocs)} IOCs to Elasticsearch")
        
        # Ensure index exists with proper mapping
        self._ensure_index_exists()
        
        # Prepare bulk actions
        actions = []
        for ioc in iocs:
            action = {
                '_index': self.index,
                '_id': ioc.ioc_id,
                '_source': self._create_elastic_document(ioc)
            }
            actions.append(action)
        
        # Execute bulk operation
        try:
            success, failed = helpers.bulk(
                self.es,
                actions,
                raise_on_error=False,
                raise_on_exception=False
            )
            
            results['success_count'] = success
            results['failure_count'] = len(failed) if isinstance(failed, list) else failed
            
            if failed:
                results['errors'] = [str(f) for f in failed] if isinstance(failed, list) else [str(failed)]
            
            logger.info(f"Elasticsearch push complete: {results['success_count']} successful, "
                       f"{results['failure_count']} failed")
            
        except Exception as e:
            logger.error(f"Error during bulk operation: {str(e)}")
            results['failure_count'] = len(iocs)
            results['errors'].append(str(e))
        
        return results
    
    def _create_elastic_document(self, ioc: IOCIndicator) -> Dict:
        """
        Create Elasticsearch document from IOC using ECS format
        
        Elastic Common Schema (ECS) compatible structure
        
        Args:
            ioc: IOC indicator
            
        Returns:
            ECS-formatted document
        """
        doc = {
            # Timestamp fields
            '@timestamp': ioc.last_seen.isoformat(),
            'event': {
                'created': datetime.now().isoformat(),
                'kind': 'enrichment',
                'category': ['threat'],
                'type': ['indicator'],
                'dataset': 'threat.indicator'
            },
            
            # Threat intelligence fields
            'threat': {
                'indicator': {
                    'type': ioc.indicator_type.value,
                    'description': ioc.description,
                    'confidence': ioc.confidence / 100.0,  # ECS uses 0.0-1.0
                    'first_seen': ioc.first_seen.isoformat(),
                    'last_seen': ioc.last_seen.isoformat(),
                    'provider': ioc.source,
                    'marking': {
                        'tlp': ioc.tlp.upper()
                    }
                }
            },
            
            # Tags
            'tags': ioc.tags,
            
            # Custom fields
            'ioc': {
                'id': ioc.ioc_id,
                'value': ioc.indicator_value,
                'severity': ioc.severity.name,
                'severity_level': ioc.severity.value,
                'false_positive_rate': ioc.false_positive_rate
            }
        }
        
        # Add indicator value based on type
        if ioc.indicator_type.value == 'ip_address':
            doc['threat']['indicator']['ip'] = ioc.indicator_value
        elif 'domain' in ioc.indicator_type.value:
            doc['threat']['indicator']['domain'] = ioc.indicator_value
        elif 'url' in ioc.indicator_type.value:
            doc['threat']['indicator']['url'] = {
                'full': ioc.indicator_value
            }
        elif 'file_hash' in ioc.indicator_type.value:
            hash_type = ioc.indicator_type.value.split('_')[-1].lower()
            doc['threat']['indicator']['file'] = {
                'hash': {
                    hash_type: ioc.indicator_value
                }
            }
        elif ioc.indicator_type.value == 'email':
            doc['threat']['indicator']['email'] = {
                'address': ioc.indicator_value
            }
        
        # Add optional fields
        if ioc.threat_actor:
            doc['threat']['group'] = {
                'name': ioc.threat_actor
            }
        
        if ioc.campaign:
            doc['threat']['indicator']['campaign'] = ioc.campaign
        
        if ioc.mitre_techniques:
            doc['threat']['technique'] = {
                'id': ioc.mitre_techniques
            }
        
        if ioc.mitre_tactics:
            doc['threat']['tactic'] = {
                'id': ioc.mitre_tactics
            }
        
        return doc
    
    def _ensure_index_exists(self):
        """Create index with proper mapping if it doesn't exist"""
        if self.es.indices.exists(index=self.index):
            return
        
        # ECS-compatible mapping
        mapping = {
            'mappings': {
                'properties': {
                    '@timestamp': {'type': 'date'},
                    'event': {
                        'properties': {
                            'created': {'type': 'date'},
                            'kind': {'type': 'keyword'},
                            'category': {'type': 'keyword'},
                            'type': {'type': 'keyword'},
                            'dataset': {'type': 'keyword'}
                        }
                    },
                    'threat': {
                        'properties': {
                            'indicator': {
                                'properties': {
                                    'type': {'type': 'keyword'},
                                    'description': {'type': 'text'},
                                    'confidence': {'type': 'float'},
                                    'first_seen': {'type': 'date'},
                                    'last_seen': {'type': 'date'},
                                    'provider': {'type': 'keyword'},
                                    'ip': {'type': 'ip'},
                                    'domain': {'type': 'keyword'},
                                    'email': {
                                        'properties': {
                                            'address': {'type': 'keyword'}
                                        }
                                    },
                                    'file': {
                                        'properties': {
                                            'hash': {
                                                'properties': {
                                                    'md5': {'type': 'keyword'},
                                                    'sha1': {'type': 'keyword'},
                                                    'sha256': {'type': 'keyword'}
                                                }
                                            }
                                        }
                                    },
                                    'url': {
                                        'properties': {
                                            'full': {'type': 'keyword'}
                                        }
                                    },
                                    'marking': {
                                        'properties': {
                                            'tlp': {'type': 'keyword'}
                                        }
                                    }
                                }
                            },
                            'group': {
                                'properties': {
                                    'name': {'type': 'keyword'}
                                }
                            },
                            'technique': {
                                'properties': {
                                    'id': {'type': 'keyword'}
                                }
                            },
                            'tactic': {
                                'properties': {
                                    'id': {'type': 'keyword'}
                                }
                            }
                        }
                    },
                    'tags': {'type': 'keyword'},
                    'ioc': {
                        'properties': {
                            'id': {'type': 'keyword'},
                            'value': {'type': 'keyword'},
                            'severity': {'type': 'keyword'},
                            'severity_level': {'type': 'integer'},
                            'false_positive_rate': {'type': 'float'}
                        }
                    }
                }
            }
        }
        
        try:
            self.es.indices.create(index=self.index, body=mapping)
            logger.info(f"Created Elasticsearch index: {self.index}")
        except Exception as e:
            logger.error(f"Error creating index: {str(e)}")
    
    def search_iocs(self, 
                   indicator_value: Optional[str] = None,
                   indicator_type: Optional[str] = None,
                   min_confidence: Optional[int] = None) -> List[Dict]:
        """
        Search for IOCs in Elasticsearch
        
        Args:
            indicator_value: Specific indicator value to search
            indicator_type: Filter by indicator type
            min_confidence: Minimum confidence threshold
            
        Returns:
            List of matching IOC documents
        """
        query = {'bool': {'must': []}}
        
        if indicator_value:
            query['bool']['must'].append({
                'term': {'ioc.value': indicator_value}
            })
        
        if indicator_type:
            query['bool']['must'].append({
                'term': {'threat.indicator.type': indicator_type}
            })
        
        if min_confidence:
            query['bool']['must'].append({
                'range': {'threat.indicator.confidence': {'gte': min_confidence / 100.0}}
            })
        
        try:
            response = self.es.search(
                index=self.index,
                query=query,
                size=100
            )
            
            return [hit['_source'] for hit in response['hits']['hits']]
            
        except Exception as e:
            logger.error(f"Error searching IOCs: {str(e)}")
            return []
    
    def delete_stale_iocs(self, days: int = 90) -> int:
        """
        Delete IOCs older than specified days
        
        Args:
            days: Age threshold in days
            
        Returns:
            Number of documents deleted
        """
        cutoff_date = datetime.now() - timedelta(days=days)
        
        query = {
            'range': {
                'threat.indicator.last_seen': {
                    'lt': cutoff_date.isoformat()
                }
            }
        }
        
        try:
            response = self.es.delete_by_query(
                index=self.index,
                query=query
            )
            
            deleted = response.get('deleted', 0)
            logger.info(f"Deleted {deleted} stale IOCs")
            return deleted
            
        except Exception as e:
            logger.error(f"Error deleting stale IOCs: {str(e)}")
            return 0
    
    def test_connection(self) -> bool:
        """
        Test Elasticsearch connection
        
        Returns:
            True if connection successful
        """
        try:
            info = self.es.info()
            logger.info(f"Elasticsearch connection successful: {info['version']['number']}")
            return True
        except Exception as e:
            logger.error(f"Elasticsearch connection test failed: {str(e)}")
            return False
