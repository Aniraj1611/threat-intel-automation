"""
Basic Example: Collecting and Processing Threat Intelligence

This example demonstrates basic usage of the threat intelligence platform:
1. Collect IOCs from AlienVault OTX
2. Process through the pipeline
3. Export to JSON

Usage:
    python examples/basic_collection.py
"""

import sys
import os
import logging
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from threat_intel.orchestrator import ThreatIntelligenceOrchestrator
from threat_intel.collectors.collectors import AlienVaultOTXCollector, AbuseIPDBCollector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    """Run basic collection example"""
    
    print("="*70)
    print("Threat Intelligence Collection - Basic Example")
    print("="*70)
    
    # Configuration
    config = {
        'min_confidence': 75,
        'max_false_positive_rate': 0.10,
        'staleness_days': 90
    }
    
    # TODO: Replace with your actual API keys
    # Get free keys at:
    # - AlienVault OTX: https://otx.alienvault.com/
    # - AbuseIPDB: https://www.abuseipdb.com/
    
    OTX_API_KEY = os.getenv('OTX_API_KEY', 'YOUR_OTX_API_KEY_HERE')
    ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', 'YOUR_ABUSEIPDB_API_KEY_HERE')
    
    if OTX_API_KEY == 'YOUR_OTX_API_KEY_HERE':
        print("\n⚠️  Warning: Using placeholder API keys")
        print("Set your API keys as environment variables:")
        print("  export OTX_API_KEY='your_key_here'")
        print("  export ABUSEIPDB_API_KEY='your_key_here'")
        print("\nOr edit this file to add your keys directly.\n")
        return
    
    try:
        # Step 1: Initialize orchestrator
        logger.info("Initializing orchestrator...")
        orchestrator = ThreatIntelligenceOrchestrator(config)
        
        # Step 2: Collect from AlienVault OTX
        logger.info("Collecting from AlienVault OTX...")
        otx_collector = AlienVaultOTXCollector(
            api_key=OTX_API_KEY,
            config={'lookback_days': 7}
        )
        otx_iocs = otx_collector.collect()
        logger.info(f"Collected {len(otx_iocs)} IOCs from OTX")
        
        # Step 3: Collect from AbuseIPDB
        logger.info("Collecting from AbuseIPDB...")
        abuseipdb_collector = AbuseIPDBCollector(
            api_key=ABUSEIPDB_API_KEY,
            config={'min_confidence': 80}
        )
        abuseipdb_iocs = abuseipdb_collector.collect()
        logger.info(f"Collected {len(abuseipdb_iocs)} IOCs from AbuseIPDB")
        
        # Combine all IOCs
        all_iocs = otx_iocs + abuseipdb_iocs
        logger.info(f"Total IOCs collected: {len(all_iocs)}")
        
        if not all_iocs:
            logger.warning("No IOCs collected. Check your API keys.")
            return
        
        # Step 4: Process through pipeline
        logger.info("Processing IOCs through pipeline...")
        operational_iocs = orchestrator.process_pipeline(all_iocs)
        
        # Step 5: Display sample IOCs
        print("\n" + "="*70)
        print(f"RESULTS: {len(operational_iocs)} High-Confidence IOCs Ready")
        print("="*70)
        
        if operational_iocs:
            print("\nTop 5 Prioritized IOCs:")
            print("-" * 70)
            
            for i, ioc in enumerate(operational_iocs[:5], 1):
                print(f"\n{i}. {ioc.indicator_type.value.upper()}: {ioc.indicator_value}")
                print(f"   Severity: {ioc.severity.name} | Confidence: {ioc.confidence}%")
                print(f"   Source: {ioc.source}")
                print(f"   Tags: {', '.join(ioc.tags[:3])}")
                if ioc.description:
                    desc = ioc.description[:100] + "..." if len(ioc.description) > 100 else ioc.description
                    print(f"   Description: {desc}")
        
        # Step 6: Export to JSON
        output_file = 'output/example_iocs.json'
        os.makedirs('output', exist_ok=True)
        
        logger.info(f"Exporting to {output_file}...")
        json_data = orchestrator.export_for_siem(operational_iocs, format_type='json')
        
        with open(output_file, 'w') as f:
            f.write(json_data)
        
        print(f"\n✓ Exported {len(operational_iocs)} IOCs to: {output_file}")
        
        # Step 7: Print statistics
        stats = orchestrator.get_statistics()
        
        print("\n" + "="*70)
        print("PROCESSING STATISTICS")
        print("="*70)
        print(f"Total Collected:          {len(all_iocs)}")
        print(f"Deduplicated:             {stats['deduplicated']}")
        print(f"Enriched:                 {stats['enriched']}")
        print(f"Operationalized:          {len(operational_iocs)}")
        print(f"Processing Time:          {stats['processing_time']:.2f}s")
        
        if len(all_iocs) > 0:
            op_rate = (len(operational_iocs) / len(all_iocs)) * 100
            print(f"Operationalization Rate:  {op_rate:.1f}%")
        
        print("="*70 + "\n")
        
        print("✓ Example complete!")
        print(f"\nNext steps:")
        print("1. Review the output file: {output_file}")
        print("2. Configure SIEM integration in config/config.yaml")
        print("3. Run full automation: python main.py")
        
    except Exception as e:
        logger.error(f"Error: {str(e)}", exc_info=True)
        print(f"\n❌ Error: {str(e)}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
