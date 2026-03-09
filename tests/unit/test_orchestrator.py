"""
Unit tests for Threat Intelligence Orchestrator
"""

import pytest
from datetime import datetime, timedelta

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from threat_intel.orchestrator import (
    IOCIndicator,
    IOCType,
    ThreatSeverity,
    ThreatIntelligenceOrchestrator
)


class TestIOCIndicator:
    """Test IOCIndicator class"""
    
    def test_ioc_creation(self):
        """Test basic IOC creation"""
        ioc = IOCIndicator(
            indicator_value="192.168.1.1",
            indicator_type=IOCType.IP_ADDRESS,
            source="test_source",
            confidence=85,
            severity=ThreatSeverity.HIGH,
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            description="Test IOC",
            tags=["malware", "apt"]
        )
        
        assert ioc.indicator_value == "192.168.1.1"
        assert ioc.confidence == 85
        assert ioc.severity == ThreatSeverity.HIGH
        assert len(ioc.tags) == 2
    
    def test_ioc_id_generation(self):
        """Test unique ID generation"""
        ioc1 = IOCIndicator(
            indicator_value="192.168.1.1",
            indicator_type=IOCType.IP_ADDRESS,
            source="source1",
            confidence=80,
            severity=ThreatSeverity.MEDIUM,
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            description="Test",
            tags=[]
        )
        
        ioc2 = IOCIndicator(
            indicator_value="192.168.1.1",
            indicator_type=IOCType.IP_ADDRESS,
            source="source1",
            confidence=80,
            severity=ThreatSeverity.MEDIUM,
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            description="Test",
            tags=[]
        )
        
        # Same indicator should generate same ID
        assert ioc1.ioc_id == ioc2.ioc_id
    
    def test_staleness_check(self):
        """Test staleness detection"""
        # Fresh IOC
        fresh_ioc = IOCIndicator(
            indicator_value="192.168.1.1",
            indicator_type=IOCType.IP_ADDRESS,
            source="test",
            confidence=80,
            severity=ThreatSeverity.MEDIUM,
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            description="Test",
            tags=[]
        )
        
        assert not fresh_ioc.is_stale(90)
        
        # Stale IOC
        stale_ioc = IOCIndicator(
            indicator_value="192.168.1.2",
            indicator_type=IOCType.IP_ADDRESS,
            source="test",
            confidence=80,
            severity=ThreatSeverity.MEDIUM,
            first_seen=datetime.now() - timedelta(days=100),
            last_seen=datetime.now() - timedelta(days=100),
            description="Test",
            tags=[]
        )
        
        assert stale_ioc.is_stale(90)
    
    def test_priority_score(self):
        """Test priority score calculation"""
        high_priority = IOCIndicator(
            indicator_value="192.168.1.1",
            indicator_type=IOCType.IP_ADDRESS,
            source="test",
            confidence=95,
            severity=ThreatSeverity.CRITICAL,
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            description="Critical threat",
            tags=["ransomware"],
            false_positive_rate=0.02
        )
        
        score = high_priority.calculate_priority_score()
        assert score > 70  # High priority should have high score


class TestOrchestrator:
    """Test ThreatIntelligenceOrchestrator"""
    
    def test_orchestrator_initialization(self):
        """Test orchestrator initialization"""
        config = {
            'min_confidence': 70,
            'max_false_positive_rate': 0.15,
            'staleness_days': 90
        }
        
        orchestrator = ThreatIntelligenceOrchestrator(config)
        
        assert orchestrator.min_confidence == 70
        assert orchestrator.max_fp_rate == 0.15
        assert orchestrator.staleness_days == 90
    
    def test_normalization(self):
        """Test indicator normalization"""
        config = {'min_confidence': 70}
        orchestrator = ThreatIntelligenceOrchestrator(config)
        
        # Test IP normalization
        ip_normalized = orchestrator._normalize_indicator(
            "192.168.001.001",
            IOCType.IP_ADDRESS
        )
        assert ip_normalized == "192.168.1.1"
        
        # Test domain normalization
        domain_normalized = orchestrator._normalize_indicator(
            "HTTP://EXAMPLE.COM/",
            IOCType.DOMAIN
        )
        assert domain_normalized == "example.com"
    
    def test_deduplication(self):
        """Test IOC deduplication"""
        config = {'min_confidence': 70}
        orchestrator = ThreatIntelligenceOrchestrator(config)
        
        # Create duplicate IOCs
        iocs = [
            IOCIndicator(
                indicator_value="192.168.1.1",
                indicator_type=IOCType.IP_ADDRESS,
                source="source1",
                confidence=80,
                severity=ThreatSeverity.MEDIUM,
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                description="Test 1",
                tags=[]
            ),
            IOCIndicator(
                indicator_value="192.168.1.1",
                indicator_type=IOCType.IP_ADDRESS,
                source="source1",
                confidence=85,
                severity=ThreatSeverity.HIGH,
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                description="Test 2",
                tags=[]
            )
        ]
        
        unique = orchestrator.normalize_and_deduplicate(iocs)
        
        # Should have only one IOC after deduplication
        assert len(unique) == 1
        # Should keep higher confidence
        assert unique[0].confidence == 85
    
    def test_filtering(self):
        """Test filtering for operationalization"""
        config = {
            'min_confidence': 80,
            'max_false_positive_rate': 0.10,
            'staleness_days': 90
        }
        orchestrator = ThreatIntelligenceOrchestrator(config)
        
        iocs = [
            # Should pass
            IOCIndicator(
                indicator_value="192.168.1.1",
                indicator_type=IOCType.IP_ADDRESS,
                source="test",
                confidence=85,
                severity=ThreatSeverity.HIGH,
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                description="High confidence",
                tags=[],
                false_positive_rate=0.05
            ),
            # Should fail - low confidence
            IOCIndicator(
                indicator_value="192.168.1.2",
                indicator_type=IOCType.IP_ADDRESS,
                source="test",
                confidence=60,
                severity=ThreatSeverity.MEDIUM,
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                description="Low confidence",
                tags=[],
                false_positive_rate=0.05
            ),
            # Should fail - stale
            IOCIndicator(
                indicator_value="192.168.1.3",
                indicator_type=IOCType.IP_ADDRESS,
                source="test",
                confidence=85,
                severity=ThreatSeverity.HIGH,
                first_seen=datetime.now() - timedelta(days=100),
                last_seen=datetime.now() - timedelta(days=100),
                description="Stale",
                tags=[],
                false_positive_rate=0.05
            )
        ]
        
        operational = orchestrator.filter_for_operationalization(iocs)
        
        # Only first IOC should pass
        assert len(operational) == 1
        assert operational[0].indicator_value == "192.168.1.1"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
