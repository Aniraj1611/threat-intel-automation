"""
Main script for Threat Intelligence Automation Platform
Orchestrates the complete workflow from collection to operationalization
"""

import sys
import os
import argparse
import logging
import yaml
from datetime import datetime
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from threat_intel.orchestrator import ThreatIntelligenceOrchestrator
from threat_intel.collectors.collectors import create_collector
from threat_intel.integrations.splunk_connector import SplunkConnector
from threat_intel.integrations.elastic_connector import ElasticConnector


def setup_logging(config: dict):
    """Configure logging based on configuration"""
    log_level = getattr(logging, config.get('general', {}).get('log_level', 'INFO'))
    log_format = config.get('logging', {}).get('format', 
                                               '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Create logs directory if it doesn't exist
    log_file = config.get('logging', {}).get('file', 'logs/threat_intel.log')
    Path(log_file).parent.mkdir(parents=True, exist_ok=True)
    
    logging.basicConfig(
        level=log_level,
        format=log_format,
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )


def load_config(config_path: str) -> dict:
    """Load configuration from YAML file"""
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        return config
    except Exception as e:
        print(f"Error loading config: {str(e)}")
        sys.exit(1)


def collect_from_sources(config: dict):
    """Collect IOCs from all enabled sources"""
    logger = logging.getLogger(__name__)
    all_iocs = []
    
    sources_config = config.get('sources', {})
    
    for source_name, source_config in sources_config.items():
        if not source_config.get('enabled', False):
            logger.info(f"Skipping disabled source: {source_name}")
            continue
        
        try:
            logger.info(f"Collecting from source: {source_name}")
            
            # Get API key if present
            api_key = source_config.get('api_key')
            
            # Create collector
            collector = create_collector(source_name, api_key, source_config)
            
            # Collect IOCs
            iocs = collector.collect()
            all_iocs.extend(iocs)
            
            logger.info(f"Collected {len(iocs)} IOCs from {source_name}")
            
        except Exception as e:
            logger.error(f"Error collecting from {source_name}: {str(e)}")
            continue
    
    logger.info(f"Total IOCs collected: {len(all_iocs)}")
    return all_iocs


def push_to_siems(iocs: list, config: dict):
    """Push IOCs to configured SIEM platforms"""
    logger = logging.getLogger(__name__)
    siem_config = config.get('siem', {})
    results = {}
    
    # Push to Splunk
    if siem_config.get('splunk', {}).get('enabled', False):
        try:
            logger.info("Pushing IOCs to Splunk")
            splunk = SplunkConnector(siem_config['splunk'])
            results['splunk'] = splunk.push_iocs(iocs)
            logger.info(f"Splunk push complete: {results['splunk']}")
        except Exception as e:
            logger.error(f"Error pushing to Splunk: {str(e)}")
            results['splunk'] = {'error': str(e)}
    
    # Push to Elasticsearch
    if siem_config.get('elastic', {}).get('enabled', False):
        try:
            logger.info("Pushing IOCs to Elasticsearch")
            elastic = ElasticConnector(siem_config['elastic'])
            results['elastic'] = elastic.push_iocs(iocs)
            logger.info(f"Elastic push complete: {results['elastic']}")
        except Exception as e:
            logger.error(f"Error pushing to Elasticsearch: {str(e)}")
            results['elastic'] = {'error': str(e)}
    
    return results


def export_iocs(iocs: list, config: dict, orchestrator):
    """Export IOCs to configured formats"""
    logger = logging.getLogger(__name__)
    export_config = config.get('export', {})
    output_dir = config.get('general', {}).get('output_directory', 'output')
    
    # Create output directory
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    formats = export_config.get('formats', ['json'])
    
    for format_type in formats:
        try:
            logger.info(f"Exporting to {format_type.upper()}")
            
            # Get output path
            output_key = f"{format_type}_output"
            output_path = export_config.get(output_key, f"{output_dir}/iocs.{format_type}")
            
            # Export
            data = orchestrator.export_for_siem(iocs, format_type=format_type)
            
            # Write to file
            with open(output_path, 'w') as f:
                f.write(data)
            
            logger.info(f"Exported {len(iocs)} IOCs to {output_path}")
            
        except Exception as e:
            logger.error(f"Error exporting to {format_type}: {str(e)}")


def print_statistics(orchestrator, iocs_collected: int, iocs_operationalized: int):
    """Print processing statistics"""
    logger = logging.getLogger(__name__)
    stats = orchestrator.get_statistics()
    
    print("\n" + "="*60)
    print("THREAT INTELLIGENCE PROCESSING STATISTICS")
    print("="*60)
    print(f"IOCs Collected:           {iocs_collected}")
    print(f"IOCs Deduplicated:        {stats.get('deduplicated', 0)}")
    print(f"IOCs Enriched:            {stats.get('enriched', 0)}")
    print(f"IOCs Operationalized:     {iocs_operationalized}")
    print(f"\nRejection Reasons:")
    print(f"  - Low Confidence:       {stats.get('rejected_low_confidence', 0)}")
    print(f"  - Stale:                {stats.get('rejected_stale', 0)}")
    print(f"  - High False Positive:  {stats.get('rejected_high_fp', 0)}")
    print(f"\nProcessing Time:          {stats.get('processing_time', 0):.2f}s")
    
    if iocs_collected > 0:
        dedup_rate = (stats.get('deduplicated', 0) / iocs_collected) * 100
        op_rate = (iocs_operationalized / iocs_collected) * 100
        print(f"\nDeduplication Rate:       {dedup_rate:.1f}%")
        print(f"Operationalization Rate:  {op_rate:.1f}%")
    
    print("="*60 + "\n")


def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(
        description="Threat Intelligence Automation Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run with default configuration
  python main.py

  # Run with custom config
  python main.py --config config/custom.yaml

  # Export only (no SIEM push)
  python main.py --no-push

  # Push to specific SIEM
  python main.py --push-to splunk

  # Dry run (collect and process, but don't push)
  python main.py --dry-run
        """
    )
    
    parser.add_argument(
        '--config',
        default='config/config.yaml',
        help='Path to configuration file (default: config/config.yaml)'
    )
    
    parser.add_argument(
        '--no-push',
        action='store_true',
        help='Skip SIEM push (export only)'
    )
    
    parser.add_argument(
        '--push-to',
        choices=['splunk', 'elastic', 'all'],
        help='Push to specific SIEM only'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Collect and process, but do not push or export'
    )
    
    parser.add_argument(
        '--output',
        help='Override output file path'
    )
    
    args = parser.parse_args()
    
    # Check if config exists
    if not os.path.exists(args.config):
        print(f"Error: Configuration file not found: {args.config}")
        print("Please copy config/config.example.yaml to config/config.yaml and configure it.")
        sys.exit(1)
    
    # Load configuration
    config = load_config(args.config)
    
    # Setup logging
    setup_logging(config)
    logger = logging.getLogger(__name__)
    
    logger.info("=" * 60)
    logger.info("Threat Intelligence Automation Platform - Starting")
    logger.info(f"Timestamp: {datetime.now().isoformat()}")
    logger.info("=" * 60)
    
    try:
        # Step 1: Initialize orchestrator
        logger.info("Initializing orchestrator...")
        orchestrator = ThreatIntelligenceOrchestrator(config.get('processing', {}))
        
        # Step 2: Collect IOCs from sources
        logger.info("Starting collection phase...")
        raw_iocs = collect_from_sources(config)
        
        if not raw_iocs:
            logger.warning("No IOCs collected. Exiting.")
            return
        
        # Step 3: Process through pipeline
        logger.info("Processing IOCs through pipeline...")
        operational_iocs = orchestrator.process_pipeline(raw_iocs)
        
        # Step 4: Export to files
        if not args.dry_run:
            logger.info("Exporting IOCs...")
            export_iocs(operational_iocs, config, orchestrator)
        
        # Step 5: Push to SIEMs
        if not args.dry_run and not args.no_push:
            logger.info("Pushing IOCs to SIEM platforms...")
            
            if args.push_to:
                # Push to specific SIEM
                temp_config = config.copy()
                siem_config = temp_config.get('siem', {})
                
                # Disable all except specified
                for siem_name in siem_config:
                    siem_config[siem_name]['enabled'] = (
                        siem_name == args.push_to or args.push_to == 'all'
                    )
                
                push_results = push_to_siems(operational_iocs, temp_config)
            else:
                push_results = push_to_siems(operational_iocs, config)
            
            logger.info(f"SIEM push results: {push_results}")
        
        # Step 6: Print statistics
        print_statistics(orchestrator, len(raw_iocs), len(operational_iocs))
        
        logger.info("=" * 60)
        logger.info("Threat Intelligence Automation Platform - Complete")
        logger.info("=" * 60)
        
    except KeyboardInterrupt:
        logger.warning("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
