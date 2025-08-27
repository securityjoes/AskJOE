# AskJOE Threat Intelligence Analyzer - Gather threat intelligence from external sources
# @author Charles Lomboni (charlesl[at]securityjoes[dot]com)
# @category SecurityJOES
# @keybinding CTRL SHIFT T
# @menupath Tools.SecurityJOES.Threat Intelligence Analyzer
# @runtime PyGhidra

import os
import datetime
import hashlib
import requests
import configparser
import base64 # Added for X-Force Exchange

# Import standardized logging
from AskJOE.logging_utils import setup_logging, log_info, log_error, log_critical, log_warning

# Setup standardized logging
logger, log_file = setup_logging("threat_intelligence")

# Ghidra console output functions
def println(message):
    """Print message to Ghidra console"""
    print(message)

def monitor_message(message):
    """Send message to Ghidra monitor"""
    try:
        if 'monitor' in globals():
            monitor.setMessage(message)
    except:
        pass  # Monitor not available

class ThreatIntelligenceAnalyzer:
    """Gather threat intelligence from multiple external sources"""
    
    def __init__(self):
        self.config = self.load_config()
        self.results = {}
        
    def load_config(self):
        """Load configuration from AskJOE/config.ini"""
        try:
            # Try multiple possible paths for Ghidra environment
            possible_paths = [
                os.path.join(os.path.dirname(__file__), "AskJOE", "config.ini"),
                "AskJOE/config.ini",
                "/home/remnux/ghidra_scripts/AskJOE/config.ini",
                os.path.abspath("AskJOE/config.ini")
            ]
            
            config_path = None
            for path in possible_paths:
                log_info(logger, "DEBUG: Trying config path: {}".format(path))
                if os.path.exists(path):
                    config_path = path
                    log_info(logger, "DEBUG: Found config at: {}".format(config_path))
                    break
            
            if not config_path:
                log_warning(logger, "Config file not found in any of these locations: {}".format(possible_paths))
                log_warning(logger, "Please create AskJOE/config.ini with your API keys")
                return {}
            
            log_info(logger, "DEBUG: Config file found, reading...")
            config = configparser.ConfigParser()
            config.read(config_path)
            
            log_info(logger, "DEBUG: Config sections found: {}".format(config.sections()))
            
            # Convert to dictionary for easier access
            config_dict = {}
            for section in config.sections():
                config_dict[section] = dict(config.items(section))
                log_info(logger, "DEBUG: Section '{}' has {} items".format(section, len(config.items(section))))
            
            log_info(logger, "Configuration loaded successfully")
            log_info(logger, "DEBUG: Final config_dict keys: {}".format(list(config_dict.keys())))
            return config_dict
            
        except Exception as e:
            log_error(logger, "Error loading config: {}".format(e))
            return {}
    
    def get_file_hash(self, file_path):
        """Calculate SHA256 hash of the file"""
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            log_info(logger, "File hash calculated: {}".format(file_hash))
            return file_hash
        except Exception as e:
            log_error(logger, "Error calculating file hash: {}".format(e))
            return None
    
    def virustotal_lookup(self, file_hash):
        """Query VirusTotal for file information"""
        try:
            # Check if feature is enabled
            if not self.config.get('FEATURES', {}).get('enable_virustotal', 'true').lower() == 'true':
                log_info(logger, "VirusTotal analysis disabled in config")
                return {"error": "Feature disabled"}
            
            api_key = self.config.get("API_KEYS", {}).get("virustotal_api_key")
            log_info(logger, "DEBUG: Config sections: {}".format(list(self.config.keys())))
            log_info(logger, "DEBUG: API_KEYS section: {}".format(self.config.get("API_KEYS", {})))
            log_info(logger, "DEBUG: VirusTotal API key found: {}".format(api_key))
            
            if not api_key or api_key == "YOUR_VIRUSTOTAL_API_KEY_HERE":
                log_warning(logger, "VirusTotal API key not configured in AskJOE config.ini")
                return {"error": "API key not configured"}
            
            headers = {
                "x-apikey": api_key
            }
            
            base_url = self.config.get("ENDPOINTS", {}).get("virustotal_base_url", "https://www.virustotal.com/api/v3")
            url = "{}/files/{}".format(base_url, file_hash)
            
            log_info(logger, "Querying VirusTotal for hash: {}".format(file_hash))
            timeout = int(self.config.get('CONFIGURATION', {}).get('api_timeout', 30))
            response = requests.get(url, headers=headers, timeout=timeout)
            
            if response.status_code == 200:
                data = response.json()
                log_info(logger, "VirusTotal lookup successful")
                
                # Debug: Log the actual response structure
                log_info(logger, "VirusTotal response keys: {}".format(list(data.keys())))
                if "data" in data:
                    log_info(logger, "VirusTotal data keys: {}".format(list(data["data"].keys())))
                    if "attributes" in data["data"]:
                        log_info(logger, "VirusTotal attributes keys: {}".format(list(data["data"]["attributes"].keys())))
                        
                        # Log specific malware family related fields
                        attributes = data["data"]["attributes"]
                        log_info(logger, "Checking for malware family fields...")
                        
                        # Check various possible field names for malware families
                        possible_family_fields = [
                            'malware_families', 'threat_names', 'popular_threat_names', 
                            'suggested_threat_label', 'malware_categories', 'capabilities_tags',
                            'crowdsourced_context', 'sandbox_verdicts'
                        ]
                        
                        for field in possible_family_fields:
                            if field in attributes:
                                value = attributes[field]
                                log_info(logger, "Found field '{}': {}".format(field, value))
                            else:
                                log_info(logger, "Field '{}' NOT found in attributes".format(field))
                
                # Extract detailed analysis results
                attributes = data.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "total_engines": stats.get("total", 0),
                    "detection_ratio": "{}/{}".format(stats.get("malicious", 0), stats.get("total", 0)) if stats.get("total", 0) > 0 else "{}/{}".format(stats.get("malicious", 0), "Unknown"),
                    "first_seen": attributes.get("first_submission_date"),
                    "last_seen": attributes.get("last_analysis_date"),
                    "file_type": attributes.get("type_description"),
                    "file_size": attributes.get("size", 0),
                    "names": attributes.get("names", [])[:5],
                    "reputation": attributes.get("reputation", 0),
                    "tags": attributes.get("tags", []),
                    "signature_info": attributes.get("signature_info", {}),
                    "pe_info": attributes.get("pe_info", {}),
                    "pe_sections": attributes.get("pe_sections", []),
                    "imports": attributes.get("imports", {}),
                    "exports": attributes.get("exports", []),
                    "md5": attributes.get("md5", ""),
                    "sha1": attributes.get("sha1", ""),
                    "sha256": attributes.get("sha256", ""),
                    "submission_names": attributes.get("submission_names", []),
                    "meaningful_name": attributes.get("meaningful_name", ""),
                    "last_submission_date": attributes.get("last_submission_date"),
                    "times_submitted": attributes.get("times_submitted", 0),
                    "total_votes": attributes.get("total_votes", {}),
                    "community_reputation": attributes.get("community_reputation", 0),
                    "crowdsourced_context": attributes.get("crowdsourced_context", []),
                    "sandbox_verdicts": attributes.get("sandbox_verdicts", {}),
                    "capabilities_tags": attributes.get("capabilities_tags", []),
                    "suggested_threat_label": attributes.get("suggested_threat_label", ""),
                    "popular_threat_names": attributes.get("popular_threat_names", []),
                    "popular_threat_category": attributes.get("popular_threat_category", ""),
                    "threat_names": attributes.get("threat_names", []),
                    "malware_families": attributes.get("malware_families", []),
                    "malware_categories": attributes.get("malware_categories", [])
                }
            elif response.status_code == 404:
                log_info(logger, "File not found in VirusTotal database")
                return {"error": "File not found in VirusTotal database"}
            else:
                log_warning(logger, "VirusTotal API error: {}".format(response.status_code))
                return {"error": "API error: {}".format(response.status_code)}
                
        except Exception as e:
            log_error(logger, "VirusTotal lookup failed: {}".format(e))
            return {"error": str(e)}
    
    def hybrid_analysis_lookup(self, file_hash):
        """Query Hybrid Analysis for behavioral analysis and sandbox results"""
        try:
            if not self.config.get('FEATURES', {}).get('enable_hybrid_analysis', 'true').lower() == 'true':
                log_info(logger, "Hybrid Analysis disabled in config")
                return {"error": "Feature disabled"}
            
            api_key = self.config.get("API_KEYS", {}).get("hybrid_analysis_api_key")
            if not api_key or api_key == "YOUR_HYBRID_ANALYSIS_API_KEY_HERE":
                log_warning(logger, "Hybrid Analysis API key not configured")
                return {"error": "API key not configured"}
            
            headers = {
                "api-key": api_key,
                "user-agent": "AskJOE Threat Intelligence"
            }
            
            base_url = self.config.get("ENDPOINTS", {}).get("hybrid_analysis_base_url", "https://www.hybrid-analysis.com/api/v2")
            url = "{}/search/hash".format(base_url)
            params = {"hash": file_hash}
            
            log_info(logger, "Querying Hybrid Analysis for hash: {}".format(file_hash))
            timeout = int(self.config.get('CONFIGURATION', {}).get('api_timeout', 30))
            response = requests.get(url, headers=headers, params=params, timeout=timeout)
            
            if response.status_code == 200:
                data = response.json()
                log_info(logger, "Hybrid Analysis lookup successful")
                
                if data and data.get("reports") and len(data["reports"]) > 0:
                    # Get first report from the reports array
                    report = data["reports"][0]
                    return {
                        "status": "found",
                        "verdict": report.get("verdict", "unknown"),
                        "threat_score": 100 if report.get("verdict") == "malicious" else 0,
                        "environment": report.get("environment_description", "unknown"),
                        "analysis_id": report.get("id", "N/A"),
                        "state": report.get("state", "unknown"),
                        "total_reports": len(data.get("reports", [])),
                        "sha256s": data.get("sha256s", [])
                    }
                else:
                    return {"error": "No analysis results found"}
            else:
                log_warning(logger, "Hybrid Analysis API error: {}".format(response.status_code))
                return {"error": "API error: {}".format(response.status_code)}
                
        except Exception as e:
            log_error(logger, "Hybrid Analysis lookup failed: {}".format(e))
            return {"error": str(e)}
    
    def alienvault_lookup(self, file_hash):
        """Query AlienVault OTX for threat intelligence and indicators"""
        try:
            if not self.config.get('FEATURES', {}).get('enable_alienvault', 'true').lower() == 'true':
                log_info(logger, "AlienVault OTX disabled in config")
                return {"error": "Feature disabled"}
            
            api_key = self.config.get("API_KEYS", {}).get("alienvault_api_key")
            if not api_key or api_key == "YOUR_ALIENVAULT_API_KEY_HERE":
                log_warning(logger, "AlienVault OTX API key not configured")
                return {"error": "API key not configured"}
            
            headers = {
                "X-OTX-API-KEY": api_key
            }
            
            base_url = self.config.get("ENDPOINTS", {}).get("alienvault_base_url", "https://otx.alienvault.com/api/v1")
            url = "{}/indicators/file/{}/general".format(base_url, file_hash)
            
            log_info(logger, "Querying AlienVault OTX for hash: {}".format(file_hash))
            timeout = int(self.config.get('CONFIGURATION', {}).get('api_timeout', 30))
            response = requests.get(url, headers=headers, timeout=timeout)
            
            if response.status_code == 200:
                data = response.json()
                log_info(logger, "AlienVault OTX lookup successful")
                
                return {
                    "pulse_count": data.get("pulse_count", 0),
                    "reputation": data.get("reputation", 0),
                    "file_type": data.get("file_type", "unknown"),
                    "file_size": data.get("file_size", 0),
                    "md5": data.get("md5", ""),
                    "sha1": data.get("sha1", ""),
                    "sha256": data.get("sha256", ""),
                    "malware_families": data.get("malware_families", []),
                    "tags": data.get("tags", []),
                    "pulses": data.get("pulses", [])[:5]  # First 5 threat reports
                }
            else:
                log_warning(logger, "AlienVault OTX API error: {}".format(response.status_code))
                return {"error": "API error: {}".format(response.status_code)}
                
        except Exception as e:
            log_error(logger, "AlienVault OTX lookup failed: {}".format(e))
            return {"error": str(e)}
    
    def malware_bazaar_lookup(self, file_hash):
        """Query Malware Bazaar for enhanced malware information"""
        try:
            if not self.config.get('FEATURES', {}).get('enable_malware_bazaar', 'true').lower() == 'true':
                log_info(logger, "Malware Bazaar disabled in config")
                return {"error": "Feature disabled"}
            
            api_key = self.config.get("API_KEYS", {}).get("malware_bazaar_api_key")
            headers = {}
            if api_key and api_key != "YOUR_MALWARE_BAZAAR_API_KEY_HERE":
                headers["Auth-Key"] = api_key
            
            base_url = self.config.get("ENDPOINTS", {}).get("malware_bazaar_base_url", "https://bazaar.abuse.ch/api/v1")
            url = "{}/query/".format(base_url)
            
            data = {
                "query": "get_info",
                "hash": file_hash
            }
            
            log_info(logger, "Querying Malware Bazaar for hash: {}".format(file_hash))
            timeout = int(self.config.get('CONFIGURATION', {}).get('api_timeout', 30))
            response = requests.post(url, data=data, headers=headers, timeout=timeout)
            
            if response.status_code == 200:
                result = response.json()
                log_info(logger, "Malware Bazaar lookup successful")
                
                if result.get("query_status") == "ok" and result.get("data"):
                    # Get the first sample from the data array
                    sample = result["data"][0]
                    return {
                        "status": "found",
                        "signature": sample.get("signature", "N/A"),
                        "file_type": sample.get("file_type", "N/A"),
                        "tags": sample.get("tags", []),
                        "first_seen": sample.get("first_seen"),
                        "last_seen": sample.get("last_seen"),
                        "platform": sample.get("file_type", "N/A"),
                        "size": sample.get("file_size", 0),
                        "malware_family": sample.get("signature", "N/A"),
                        "file_name": sample.get("file_name", "N/A"),
                        "reporter": sample.get("reporter", "N/A"),
                        "origin_country": sample.get("origin_country", "N/A")
                    }
                else:
                    return {"error": "File not found in Malware Bazaar"}
            else:
                log_warning(logger, "Malware Bazaar API error: {}".format(response.status_code))
                return {"error": "API error: {}".format(response.status_code)}
            
        except Exception as e:
            log_error(logger, "Malware Bazaar lookup failed: {}".format(e))
            return {"error": str(e)}
    
    def abuseipdb_lookup(self, file_hash):
        """Query AbuseIPDB for IP reputation analysis"""
        try:
            if not self.config.get('FEATURES', {}).get('enable_abuseipdb', 'true').lower() == 'true':
                log_info(logger, "AbuseIPDB disabled in config")
                return {"error": "Feature disabled"}
            
            api_key = self.config.get("API_KEYS", {}).get("abuseipdb_api_key")
            if not api_key or api_key == "YOUR_ABUSEIPDB_API_KEY_HERE":
                log_warning(logger, "AbuseIPDB API key not configured")
                return {"error": "API key not configured"}
            
            headers = {
                "Key": api_key,
                "Accept": "application/json"
            }
            
            base_url = self.config.get("ENDPOINTS", {}).get("abuseipdb_base_url", "https://api.abuseipdb.com/api/v2")
            url = "{}/check".format(base_url)
            
            # Note: AbuseIPDB is for IP addresses, not file hashes
            # This method would need to be adapted for file analysis
            log_info(logger, "AbuseIPDB lookup - note: designed for IP addresses, not file hashes")
            return {"error": "AbuseIPDB is designed for IP address analysis, not file hash analysis"}
            
        except Exception as e:
            log_error(logger, "AbuseIPDB lookup failed: {}".format(e))
            return {"error": str(e)}
    
    def shodan_lookup(self, file_hash):
        """Query Shodan for network intelligence"""
        try:
            if not self.config.get('FEATURES', {}).get('enable_shodan', 'true').lower() == 'true':
                log_info(logger, "Shodan disabled in config")
                return {"error": "Feature disabled"}
            
            api_key = self.config.get("API_KEYS", {}).get("shodan_api_key")
            if not api_key or api_key == "YOUR_SHODAN_API_KEY_HERE":
                log_warning(logger, "Shodan API key not configured")
                return {"error": "API key not configured"}
            
            base_url = self.config.get("ENDPOINTS", {}).get("shodan_base_url", "https://api.shodan.io")
            url = "{}/shodan/host/search".format(base_url)
            
            params = {
                "key": api_key,
                "query": "hash:{}".format(file_hash)
            }
            
            log_info(logger, "Querying Shodan for hash: {}".format(file_hash))
            timeout = int(self.config.get('CONFIGURATION', {}).get('api_timeout', 30))
            response = requests.get(url, params=params, timeout=timeout)
            
            if response.status_code == 200:
                data = response.json()
                log_info(logger, "Shodan lookup successful")
                
                return {
                    "total": data.get("total", 0),
                    "matches": len(data.get("matches", [])),
                    "results": data.get("matches", [])[:5]  # First 5 results
                }
            else:
                log_warning(logger, "Shodan API error: {}".format(response.status_code))
                return {"error": "API error: {}".format(response.status_code)}
                
        except Exception as e:
            log_error(logger, "Shodan lookup failed: {}".format(e))
            return {"error": str(e)}
    
    def intezer_lookup(self, file_hash):
        """Query Intezer for genetic malware analysis"""
        try:
            if not self.config.get('FEATURES', {}).get('enable_intezer', 'true').lower() == 'true':
                log_info(logger, "Intezer disabled in config")
                return {"error": "Feature disabled"}
            
            api_key = self.config.get("API_KEYS", {}).get("intezer_api_key")
            if not api_key or api_key == "YOUR_INTEZER_API_KEY_HERE":
                log_warning(logger, "Intezer API key not configured")
                return {"error": "API key not configured"}
            
            headers = {
                "Authorization": "Bearer {}".format(api_key)
            }
            
            base_url = self.config.get("ENDPOINTS", {}).get("intezer_base_url", "https://analyze.intezer.com/api/v2")
            url = "{}/files/{}".format(base_url, file_hash)
            
            log_info(logger, "Querying Intezer for hash: {}".format(file_hash))
            timeout = int(self.config.get('CONFIGURATION', {}).get('api_timeout', 30))
            response = requests.get(url, headers=headers, timeout=timeout)
            
            if response.status_code == 200:
                data = response.json()
                log_info(logger, "Intezer lookup successful")
                
                return {
                    "verdict": data.get("verdict", "unknown"),
                    "family_name": data.get("family_name", "N/A"),
                    "sub_verdict": data.get("sub_verdict", "N/A"),
                    "threat_level": data.get("threat_level", "N/A"),
                    "analysis_time": data.get("analysis_time"),
                    "tags": data.get("tags", [])
                }
            elif response.status_code == 404:
                log_info(logger, "File not found in Intezer database")
                return {"error": "File not found in Intezer database"}
            else:
                log_warning(logger, "Intezer API error: {}".format(response.status_code))
                return {"error": "API error: {}".format(response.status_code)}
                
        except Exception as e:
            log_error(logger, "Intezer lookup failed: {}".format(e))
            return {"error": str(e)}
    
    def anyrun_lookup(self, file_hash):
        """Query Any.Run for advanced sandbox analysis"""
        try:
            if not self.config.get('FEATURES', {}).get('enable_anyrun', 'true').lower() == 'true':
                log_info(logger, "Any.Run disabled in config")
                return {"error": "Feature disabled"}
            
            api_key = self.config.get("API_KEYS", {}).get("anyrun_api_key")
            if not api_key or api_key == "YOUR_ANYRUN_API_KEY_HERE":
                log_warning(logger, "Any.Run API key not configured")
                return {"error": "API key not configured"}
            
            headers = {
                "Authorization": "Bearer {}".format(api_key)
            }
            
            base_url = self.config.get("ENDPOINTS", {}).get("anyrun_base_url", "https://api.any.run/v1")
            url = "{}/analysis/{}".format(base_url, file_hash)
            
            log_info(logger, "Querying Any.Run for hash: {}".format(file_hash))
            timeout = int(self.config.get('CONFIGURATION', {}).get('api_timeout', 30))
            response = requests.get(url, headers=headers, timeout=timeout)
            
            if response.status_code == 200:
                data = response.json()
                log_info(logger, "Any.Run lookup successful")
                
                return {
                    "verdict": data.get("verdict", "unknown"),
                    "threat_score": data.get("threat_score", 0),
                    "malware_family": data.get("malware_family", "N/A"),
                    "analysis_time": data.get("analysis_time"),
                    "network_connections": data.get("network", {}).get("connections", []),
                    "processes": data.get("processes", []),
                    "files_created": data.get("files", {}).get("created", []),
                    "registry_changes": data.get("registry", {}).get("changes", [])
                }
            elif response.status_code == 404:
                log_info(logger, "File not found in Any.Run database")
                return {"error": "File not found in Any.Run database"}
            else:
                log_warning(logger, "Any.Run API error: {}".format(response.status_code))
                return {"error": "API error: {}".format(response.status_code)}
                
        except Exception as e:
            log_error(logger, "Any.Run lookup failed: {}".format(e))
            return {"error": str(e)}
    
    def triage_lookup(self, file_hash):
        """Query Triage for malware analysis platform"""
        try:
            if not self.config.get('FEATURES', {}).get('enable_triage', 'true').lower() == 'true':
                log_info(logger, "Triage disabled in config")
                return {"error": "Feature disabled"}
            
            api_key = self.config.get("API_KEYS", {}).get("triage_api_key")
            if not api_key or api_key == "YOUR_TRIAGE_API_KEY_HERE":
                log_warning(logger, "Triage API key not configured")
                return {"error": "API key not configured"}
            
            headers = {
                "Authorization": "Bearer {}".format(api_key)
            }
            
            base_url = self.config.get("ENDPOINTS", {}).get("triage_base_url", "https://api.tria.ge/v0")
            url = "{}/samples/{}".format(base_url, file_hash)
            
            log_info(logger, "Querying Triage for hash: {}".format(file_hash))
            timeout = int(self.config.get('CONFIGURATION', {}).get('api_timeout', 30))
            response = requests.get(url, headers=headers, timeout=timeout)
            
            if response.status_code == 200:
                data = response.json()
                log_info(logger, "Triage lookup successful")
                
                return {
                    "verdict": data.get("verdict", "unknown"),
                    "threat_score": data.get("threat_score", 0),
                    "malware_family": data.get("malware_family", "N/A"),
                    "analysis_time": data.get("analysis_time"),
                    "behaviors": data.get("behaviors", []),
                    "network": data.get("network", {}),
                    "processes": data.get("processes", [])
                }
            elif response.status_code == 404:
                log_info(logger, "File not found in Triage database")
                return {"error": "File not found in Triage database"}
            else:
                log_warning(logger, "Triage API error: {}".format(response.status_code))
                return {"error": "API error: {}".format(response.status_code)}
                
        except Exception as e:
            log_error(logger, "Triage lookup failed: {}".format(e))
            return {"error": str(e)}
    
    def xforce_lookup(self, file_hash):
        """Query X-Force Exchange for IBM threat intelligence"""
        try:
            if not self.config.get('FEATURES', {}).get('enable_xforce', 'true').lower() == 'true':
                log_info(logger, "X-Force Exchange disabled in config")
                return {"error": "Feature disabled"}
            
            api_key = self.config.get("API_KEYS", {}).get("xforce_api_key")
            if not api_key or api_key == "YOUR_XFORCE_API_KEY_HERE":
                log_warning(logger, "X-Force Exchange API key not configured")
                return {"error": "API key not configured"}
            
            # X-Force uses API key and password
            api_key_parts = api_key.split(':')
            if len(api_key_parts) != 2:
                return {"error": "X-Force API key format should be 'key:password'"}
            
            key, password = api_key_parts
            
            headers = {
                "Authorization": "Basic {}".format(base64.b64encode("{}:{}".format(key, password).encode()).decode())
            }
            
            base_url = self.config.get("ENDPOINTS", {}).get("xforce_base_url", "https://api.xforce.ibmcloud.com")
            url = "{}/malware/{}".format(base_url, file_hash)
            
            log_info(logger, "Querying X-Force Exchange for hash: {}".format(file_hash))
            timeout = int(self.config.get('CONFIGURATION', {}).get('api_timeout', 30))
            response = requests.get(url, headers=headers, timeout=timeout)
            
            if response.status_code == 200:
                data = response.json()
                log_info(logger, "X-Force Exchange lookup successful")
                
                return {
                    "malware_type": data.get("malware", {}).get("type", "N/A"),
                    "risk": data.get("malware", {}).get("risk", "N/A"),
                    "family": data.get("malware", {}).get("family", []),
                    "first_seen": data.get("malware", {}).get("first_seen"),
                    "last_seen": data.get("malware", {}).get("last_seen"),
                    "tags": data.get("malware", {}).get("tags", [])
                }
            elif response.status_code == 404:
                log_info(logger, "File not found in X-Force Exchange database")
                return {"error": "File not found in X-Force Exchange database"}
            else:
                log_warning(logger, "X-Force Exchange API error: {}".format(response.status_code))
                return {"error": "API error: {}".format(response.status_code)}
                
        except Exception as e:
            log_error(logger, "X-Force Exchange lookup failed: {}".format(e))
            return {"error": str(e)}
    
    def analyze_threat_intelligence(self, file_path):
        """Analyze file using multiple threat intelligence sources"""
        try:
            log_info(logger, "Starting comprehensive threat intelligence analysis for: {}".format(file_path))
            
            # Get file hash
            file_hash = self.get_file_hash(file_path)
            if not file_hash:
                return {"error": "Could not calculate file hash"}
            
            println("[+] File Hash: {}".format(file_hash))
            println("[+] Querying multiple threat intelligence sources...")
            monitor_message("Querying VirusTotal...")
            
            # Initialize service status tracking
            service_status = {
                'virustotal': {'status': 'pending', 'details': '', 'success': False},
                'hybrid_analysis': {'status': 'pending', 'details': '', 'success': False},
                'alienvault': {'status': 'pending', 'details': '', 'success': False},
                'malware_bazaar': {'status': 'pending', 'details': '', 'success': False},
                'intezer': {'status': 'pending', 'details': '', 'success': False},
                'anyrun': {'status': 'pending', 'details': '', 'success': False},
                'triage': {'status': 'pending', 'details': '', 'success': False},
                'xforce': {'status': 'pending', 'details': '', 'success': False}
            }
            
            # Query all threat intelligence sources with rate limiting
            import time
            
            # Core malware analysis services
            monitor_message("Querying VirusTotal...")
            vt_results = self.virustotal_lookup(file_hash)
            self.results["virustotal"] = vt_results
            
            # Track VirusTotal status
            if vt_results and "error" not in vt_results:
                service_status['virustotal']['status'] = 'success'
                service_status['virustotal']['success'] = True
                service_status['virustotal']['details'] = '{} detections'.format(vt_results.get('malicious', 0))
                log_info(logger, "VirusTotal: SUCCESS - {} detections".format(vt_results.get('malicious', 0)))
            else:
                service_status['virustotal']['status'] = 'failed'
                service_status['virustotal']['details'] = vt_results.get('error', 'Unknown error') if vt_results else 'No response'
                log_warning(logger, "VirusTotal: FAILED - {}".format(service_status['virustotal']['details']))
            
            delay = int(self.config.get('CONFIGURATION', {}).get('api_rate_limit_delay', 1))
            time.sleep(delay)
            
            monitor_message("Querying Hybrid Analysis...")
            hybrid_results = self.hybrid_analysis_lookup(file_hash)
            self.results["hybrid_analysis"] = hybrid_results
            
            # Track Hybrid Analysis status
            if hybrid_results and "error" not in hybrid_results:
                service_status['hybrid_analysis']['status'] = 'success'
                service_status['hybrid_analysis']['success'] = True
                service_status['hybrid_analysis']['details'] = 'verdict: {}'.format(hybrid_results.get('verdict', 'unknown'))
                log_info(logger, "Hybrid Analysis: SUCCESS - verdict: {}".format(hybrid_results.get('verdict', 'unknown')))
            else:
                service_status['hybrid_analysis']['status'] = 'failed'
                service_status['hybrid_analysis']['details'] = hybrid_results.get('error', 'Unknown error') if hybrid_results else 'No response'
                log_warning(logger, "Hybrid Analysis: FAILED - {}".format(service_status['hybrid_analysis']['details']))
            
            time.sleep(delay)
            
            monitor_message("Querying AlienVault OTX...")
            otx_results = self.alienvault_lookup(file_hash)
            self.results["alienvault"] = otx_results
            
            # Track AlienVault status
            if otx_results and "error" not in otx_results:
                service_status['alienvault']['status'] = 'success'
                service_status['alienvault']['success'] = True
                service_status['alienvault']['details'] = '{} pulses'.format(otx_results.get('pulse_count', 0))
                log_info(logger, "AlienVault OTX: SUCCESS - {} pulses".format(otx_results.get('pulse_count', 0)))
            else:
                service_status['alienvault']['status'] = 'failed'
                service_status['alienvault']['details'] = otx_results.get('error', 'Unknown error') if otx_results else 'No response'
                log_warning(logger, "AlienVault OTX: FAILED - {}".format(service_status['alienvault']['details']))
            
            time.sleep(delay)
            
            monitor_message("Querying Malware Bazaar...")
            mb_results = self.malware_bazaar_lookup(file_hash)
            self.results["malware_bazaar"] = mb_results
            
            # Track Malware Bazaar status
            if mb_results and "error" not in mb_results:
                service_status['malware_bazaar']['status'] = 'success'
                service_status['malware_bazaar']['success'] = True
                service_status['malware_bazaar']['details'] = 'family: {}'.format(mb_results.get('signature', 'N/A'))
                log_info(logger, "Malware Bazaar: SUCCESS - family: {}".format(mb_results.get('signature', 'N/A')))
            else:
                service_status['malware_bazaar']['status'] = 'failed'
                service_status['malware_bazaar']['details'] = mb_results.get('error', 'Unknown error') if mb_results else 'No response'
                log_warning(logger, "Malware Bazaar: FAILED - {}".format(service_status['malware_bazaar']['details']))
            
            time.sleep(delay)
            
            # Additional intelligence services
            monitor_message("Querying Intezer...")
            intezer_results = self.intezer_lookup(file_hash)
            self.results["intezer"] = intezer_results
            
            # Track Intezer status
            if intezer_results and "error" not in intezer_results:
                service_status['intezer']['status'] = 'success'
                service_status['intezer']['success'] = True
                service_status['intezer']['details'] = 'family: {}'.format(intezer_results.get('family_name', 'N/A'))
                log_info(logger, "Intezer: SUCCESS - family: {}".format(intezer_results.get('family_name', 'N/A')))
            else:
                service_status['intezer']['status'] = 'failed'
                service_status['intezer']['details'] = intezer_results.get('error', 'Unknown error') if intezer_results else 'No response'
                log_warning(logger, "Intezer: FAILED - {}".format(service_status['intezer']['details']))
            
            time.sleep(delay)
            
            monitor_message("Querying Any.Run...")
            anyrun_results = self.anyrun_lookup(file_hash)
            self.results["anyrun"] = anyrun_results
            
            # Track Any.Run status
            if anyrun_results and "error" not in anyrun_results:
                service_status['anyrun']['status'] = 'success'
                service_status['anyrun']['success'] = True
                service_status['anyrun']['details'] = 'verdict: {}'.format(anyrun_results.get('verdict', 'unknown'))
                log_info(logger, "Any.Run: SUCCESS - verdict: {}".format(anyrun_results.get('verdict', 'unknown')))
            else:
                service_status['anyrun']['status'] = 'failed'
                service_status['anyrun']['details'] = anyrun_results.get('error', 'Unknown error') if anyrun_results else 'No response'
                log_warning(logger, "Any.Run: FAILED - {}".format(service_status['anyrun']['details']))
            
            time.sleep(delay)
            
            monitor_message("Querying Triage...")
            triage_results = self.triage_lookup(file_hash)
            self.results["triage"] = triage_results
            
            # Track Triage status
            if triage_results and "error" not in triage_results:
                service_status['triage']['status'] = 'success'
                service_status['triage']['success'] = True
                service_status['triage']['details'] = 'verdict: {}'.format(triage_results.get('verdict', 'unknown'))
                log_info(logger, "Triage: SUCCESS - verdict: {}".format(triage_results.get('verdict', 'unknown')))
            else:
                service_status['triage']['status'] = 'failed'
                service_status['triage']['details'] = triage_results.get('error', 'Unknown error') if triage_results else 'No response'
                log_warning(logger, "Triage: FAILED - {}".format(service_status['triage']['details']))
            
            time.sleep(delay)
            
            monitor_message("Querying X-Force Exchange...")
            xforce_results = self.xforce_lookup(file_hash)
            self.results["xforce"] = xforce_results
            
            # Track X-Force status
            if xforce_results and "error" not in xforce_results:
                service_status['xforce']['status'] = 'success'
                service_status['xforce']['success'] = True
                service_status['xforce']['details'] = 'risk: {}'.format(xforce_results.get('risk', 'unknown'))
                log_info(logger, "X-Force Exchange: SUCCESS - risk: {}".format(xforce_results.get('risk', 'unknown')))
            else:
                service_status['xforce']['status'] = 'failed'
                service_status['xforce']['details'] = xforce_results.get('error', 'Unknown error') if xforce_results else 'No response'
                log_warning(logger, "X-Force Exchange: FAILED - {}".format(service_status['xforce']['details']))
            
            # Generate comprehensive threat assessment
            threat_level = "UNKNOWN"
            detection_rate = 0
            total_engines = 0
            malicious_count = 0
            
            # VirusTotal assessment
            if vt_results and "error" not in vt_results:
                malicious_count = vt_results.get("malicious", 0)
                total_engines = vt_results.get("total_engines", 0)
                if malicious_count > 0:
                    # If total_engines is 0, use malicious_count as percentage
                    if total_engines > 0:
                        detection_rate = (malicious_count / total_engines) * 100
                    else:
                        detection_rate = 100  # If 65/0, it's 100% malicious
                    
                    # Set threat level based on malicious count
                    if malicious_count >= 50:
                        threat_level = "CRITICAL"
                    elif malicious_count >= 30:
                        threat_level = "HIGH"
                    elif malicious_count >= 15:
                        threat_level = "MEDIUM"
                    elif malicious_count >= 5:
                        threat_level = "LOW"
            
            # Hybrid Analysis assessment
            if hybrid_results and "error" not in hybrid_results:
                threat_score = hybrid_results.get("threat_score", 0)
                if threat_score >= 80:
                    threat_level = "CRITICAL"
                elif threat_score >= 60:
                    threat_level = "HIGH"
                elif threat_score >= 40:
                    threat_level = "MEDIUM"
                elif threat_score >= 20:
                    threat_level = "LOW"
            
            # AlienVault OTX assessment
            if otx_results and "error" not in otx_results:
                pulse_count = otx_results.get("pulse_count", 0)
                if pulse_count > 10:
                    threat_level = "HIGH"
                elif pulse_count > 5:
                    threat_level = "MEDIUM"
                elif pulse_count > 0:
                    threat_level = "LOW"
            
            # Malware Bazaar assessment
            if mb_results and "error" not in mb_results:
                if mb_results.get("status") == "found":
                    threat_level = "HIGH"  # If found in Malware Bazaar, it's malicious
            
            # Final threat level determination
            if threat_level == "UNKNOWN":
                if detection_rate >= 50:
                    threat_level = "HIGH"
                elif detection_rate >= 20:
                    threat_level = "MEDIUM"
                elif detection_rate >= 5:
                    threat_level = "LOW"
            
            # Create comprehensive report
            report = {
                "summary": {
                    "threat_level": threat_level,
                    "detection_rate": "{}/{}".format(malicious_count, total_engines) if total_engines > 0 else "N/A",
                    "detection_percentage": detection_rate,
                    "file_hash": file_hash,
                    "total_sources_queried": 8,
                    "sources_with_results": sum(1 for r in [vt_results, hybrid_results, otx_results, mb_results, intezer_results, anyrun_results, triage_results, xforce_results] if r and "error" not in r)
                },
                "details": {
                    "virustotal": vt_results,
                    "hybrid_analysis": hybrid_results,
                    "alienvault": otx_results,
                    "malware_bazaar": mb_results,
                    "intezer": intezer_results,
                    "anyrun": anyrun_results,
                    "triage": triage_results,
                    "xforce": xforce_results
                },
                "service_status": service_status
            }
            
            log_info(logger, "Comprehensive threat intelligence analysis completed")
            monitor_message("Threat intelligence analysis completed!")
            return report
            
        except Exception as e:
            log_error(logger, "Threat intelligence analysis failed: {}".format(e))
            return {"error": str(e)}
    
    def display_results(self, results, file_hash):
        """Display comprehensive threat intelligence results"""
        try:
            if "error" in results:
                println("[-] {}".format(results['error']))
                return
            
            summary = results.get("summary", {})
            println("\n" + "="*80)
            println("COMPREHENSIVE THREAT INTELLIGENCE ANALYSIS RESULTS")
            println("="*80)
            println("Threat Level: {}".format(summary.get('threat_level', 'UNKNOWN')))
            println("Detection Rate: {}".format(summary.get('detection_rate', 'N/A')))
            if summary.get('detection_percentage', 0) > 0:
                println("Detection Percentage: {:.1f}%".format(summary.get('detection_percentage', 0)))
            println("File Hash: {}".format(file_hash))
            println("Sources Queried: {}/{}".format(
                summary.get('sources_with_results', 0), 
                summary.get('total_sources_queried', 0)
            ))
            
            println("\n=== THREAT ASSESSMENT & RECOMMENDATIONS ===")
            threat_level = summary.get('threat_level', 'UNKNOWN')
            if threat_level in ['CRITICAL', 'HIGH']:
                println("HIGH THREAT: Sample shows malicious behavior - IMMEDIATE ACTION REQUIRED")
                println("   - Isolate the system immediately")
                println("   - Begin incident response procedures")
                println("   - Document all findings for forensics")
            elif threat_level == 'MEDIUM':
                println("MEDIUM THREAT: Sample shows suspicious behavior - FURTHER ANALYSIS REQUIRED")
                println("   - Monitor system behavior closely")
                println("   - Run additional analysis tools")
                println("   - Check for lateral movement")
            elif threat_level == 'LOW':
                println("LOW THREAT: Sample shows minimal risk - MONITOR AND VERIFY")
                println("   - Continue monitoring for changes")
                println("   - Verify with additional sources")
                println("   - Document for future reference")
            else:
                println("UNKNOWN THREAT: Insufficient data - ADDITIONAL ANALYSIS REQUIRED")
                println("   - Run additional threat intelligence tools")
                println("   - Check for behavioral indicators")
                println("   - Consider sandbox analysis")
            
            println("\n=== DETAILED THREAT INTELLIGENCE ===")
            
            # Show service status summary
            service_status = results.get("service_status", {})
            if service_status:
                println("\n[SERVICE STATUS SUMMARY]")
                successful_count = 0
                failed_count = 0
                
                for service_name, status_info in service_status.items():
                    service_display_name = service_name.replace('_', ' ').title()
                    if status_info['status'] == 'success':
                        println("  [SUCCESS] {}: {}".format(service_display_name, status_info['details']))
                        successful_count += 1
                    else:
                        println("  [FAILED] {}: {}".format(service_display_name, status_info['details']))
                        failed_count += 1
                
                println("  Summary: {}/{} services successful".format(successful_count, len(service_status)))
            
            # VirusTotal results
            vt_results = results.get("details", {}).get("virustotal", {})
            if vt_results and "error" not in vt_results:
                println("\n[VIRUSTOTAL ANALYSIS]")
                println("  Detection Rate: {}".format(vt_results.get('detection_ratio', 'N/A')))
                println("  Malicious Engines: {}".format(vt_results.get('malicious', 'N/A')))
                println("  Suspicious Engines: {}".format(vt_results.get('suspicious', 'N/A')))
                println("  Total Engines: {}".format(vt_results.get('total_engines', 'N/A')))
                println("  File Type: {}".format(vt_results.get('file_type', 'N/A')))
                println("  Reputation Score: {}".format(vt_results.get('reputation', 'N/A')))
                println("  File Size: {} bytes".format(vt_results.get('file_size', 'N/A')))
                
                # Show MALWARE FAMILY information prominently
                malware_families = vt_results.get('malware_families', [])
                if malware_families:
                    println("  [MALWARE FAMILIES] {}".format(', '.join(malware_families)))
                else:
                    println("  [MALWARE FAMILIES] No family data available via API")
                    println("    Note: Check VirusTotal website for community malware family information")
                    println("    Direct URL: https://www.virustotal.com/gui/file/{}".format(file_hash))
                    println("    Community tab may contain additional malware family details")
                
                threat_names = vt_results.get('threat_names', [])
                if threat_names:
                    println("  [THREAT NAMES] {}".format(', '.join(threat_names[:5])))
                
                popular_threat_names = vt_results.get('popular_threat_names', [])
                if popular_threat_names:
                    println("  [POPULAR THREAT NAMES] {}".format(', '.join(popular_threat_names[:5])))
                
                suggested_threat_label = vt_results.get('suggested_threat_label', '')
                if suggested_threat_label:
                    println("  [SUGGESTED THREAT LABEL] {}".format(suggested_threat_label))
                
                # Format timestamps
                first_seen = vt_results.get('first_seen')
                last_seen = vt_results.get('last_seen')
                if first_seen:
                    first_date = datetime.datetime.fromtimestamp(int(first_seen)).strftime('%Y-%m-%d %H:%M:%S UTC')
                    println("  First Seen: {}".format(first_date))
                if last_seen:
                    last_date = datetime.datetime.fromtimestamp(int(last_seen)).strftime('%Y-%m-%d %H:%M:%S UTC')
                    println("  Last Analyzed: {}".format(last_date))
                
                # Show file names if available
                names = vt_results.get('names', [])
                if names:
                    if len(names) <= 5:
                        println("  Known Names: {}".format(', '.join(names)))
                    else:
                        println("  Known Names: {}".format(', '.join(names[:5])))
                        println("  Total Names: {}".format(len(names)))
                
                # Show tags if available
                tags = vt_results.get('tags', [])
                if tags:
                    println("  Tags: {}".format(', '.join(tags[:15])))  # First 15 tags
                
                # Show capabilities tags (behavioral analysis)
                capabilities_tags = vt_results.get('capabilities_tags', [])
                if capabilities_tags:
                    println("  [CAPABILITIES] {}".format(', '.join(capabilities_tags[:10])))
                
                # Show PE info if available
                pe_info = vt_results.get('pe_info', {})
                if pe_info:
                    println("  PE Info: {} sections, {} imports".format(
                        len(vt_results.get('pe_sections', [])),
                        len(vt_results.get('imports', {}).get('pe_imports', []))
                    ))
                
                # Show additional hashes
                md5 = vt_results.get('md5', '')
                sha1 = vt_results.get('sha1', '')
                if md5:
                    println("  MD5: {}".format(md5))
                if sha1:
                    println("  SHA1: {}".format(sha1))
                
                # Show submission names (additional context)
                submission_names = vt_results.get('submission_names', [])
                if submission_names:
                    println("  Submission Names: {}".format(', '.join(submission_names[:5])))
                
                # Show community information
                community_reputation = vt_results.get('community_reputation', '')
                if community_reputation:
                    println("  Community Reputation: {}".format(community_reputation))
                
                times_submitted = vt_results.get('times_submitted', '')
                if times_submitted:
                    println("  Times Submitted: {}".format(times_submitted))
            
            # Hybrid Analysis results
            hybrid_results = results.get("details", {}).get("hybrid_analysis", {})
            if hybrid_results and "error" not in hybrid_results:
                println("\n[HYBRID ANALYSIS - SANDBOX]")
                println("  Verdict: {}".format(hybrid_results.get('verdict', 'N/A')))
                println("  Threat Score: {}/100".format(hybrid_results.get('threat_score', 'N/A')))
                println("  Environment: {}".format(hybrid_results.get('environment', 'N/A')))
                println("  Analysis ID: {}".format(hybrid_results.get('analysis_id', 'N/A')))
                println("  State: {}".format(hybrid_results.get('state', 'N/A')))
                println("  Total Reports: {}".format(hybrid_results.get('total_reports', 'N/A')))
                
                # Show SHA256 hashes if available
                sha256s = hybrid_results.get('sha256s', [])
                if sha256s:
                    println("  SHA256 Hashes: {}".format(', '.join(sha256s[:3])))  # First 3 hashes
            
            # AlienVault OTX results
            otx_results = results.get("details", {}).get("alienvault", {})
            if otx_results and "error" not in otx_results:
                println("\n[ALIENVAULT OTX THREAT INTELLIGENCE]")
                println("  Threat Pulses: {}".format(otx_results.get('pulse_count', 'N/A')))
                println("  Reputation Score: {}".format(otx_results.get('reputation', 'N/A')))
                println("  File Type: {}".format(otx_results.get('file_type', 'N/A')))
                println("  File Size: {} bytes".format(otx_results.get('file_size', 'N/A')))
                
                # Show malware families
                families = otx_results.get('malware_families', [])
                if families:
                    println("  Malware Families: {}".format(', '.join(families)))
                
                # Show threat tags
                tags = otx_results.get('tags', [])
                if tags:
                    println("  Threat Tags: {}".format(', '.join(tags[:15])))
                    
                # Show hash information
                md5 = otx_results.get('md5', '')
                sha1 = otx_results.get('sha1', '')
                if md5:
                    println("  MD5: {}".format(md5))
                if sha1:
                    println("  SHA1: {}".format(sha1))
                
                # Show threat pulses details
                pulses = otx_results.get('pulses', [])
                if pulses:
                    println("  Threat Pulses Details:")
                    for i, pulse in enumerate(pulses[:3]):  # Show first 3 pulses
                        pulse_name = pulse.get('name', 'Unknown')
                        pulse_description = pulse.get('description', 'No description')
                        pulse_tags = pulse.get('tags', [])
                        println("    {}. {}: {}".format(i+1, pulse_name, pulse_description[:100] + "..." if len(pulse_description) > 100 else pulse_description))
                        if pulse_tags:
                            println("      Tags: {}".format(', '.join(pulse_tags[:5])))
                
                # Show additional context
                context = otx_results.get('context', {})
                if context:
                    println("  Additional Context: {}".format(context))
            
            # Malware Bazaar results
            mb_results = results.get("details", {}).get("malware_bazaar", {})
            if mb_results and "error" not in mb_results:
                println("\n[MALWARE BAZAAR ANALYSIS]")
                println("  Status: {}".format(mb_results.get('status', 'N/A')))
                println("  File Type: {}".format(mb_results.get('file_type', 'N/A')))
                println("  Platform: {}".format(mb_results.get('platform', 'N/A')))
                println("  Size: {} bytes".format(mb_results.get('size', 'N/A')))
                println("  [MALWARE FAMILY] {}".format(mb_results.get('malware_family', 'N/A')))
                println("  Signature: {}".format(mb_results.get('signature', 'N/A')))
                println("  File Name: {}".format(mb_results.get('file_name', 'N/A')))
                println("  Reporter: {}".format(mb_results.get('reporter', 'N/A')))
                println("  Origin Country: {}".format(mb_results.get('origin_country', 'N/A')))
                
                # Show all available hashes
                md5 = mb_results.get('md5', '')
                sha1 = mb_results.get('sha1', '')
                if md5:
                    println("  MD5: {}".format(md5))
                if sha1:
                    println("  SHA1: {}".format(sha1))
                
                # Show additional hashes if available
                sha3_384 = mb_results.get('sha3_384_hash', '')
                if sha3_384:
                    println("  SHA3-384: {}".format(sha3_384))
                
                # Show file information
                imphash = mb_results.get('imphash', '')
                tlsh = mb_results.get('tlsh', '')
                ssdeep = mb_results.get('ssdeep', '')
                if imphash:
                    println("  Import Hash: {}".format(imphash))
                if tlsh:
                    println("  TLSH: {}".format(tlsh[:32] + "..." if len(tlsh) > 32 else tlsh))
                if ssdeep:
                    println("  SSDEEP: {}".format(ssdeep[:32] + "..." if len(ssdeep) > 32 else ssdeep))
                
                # Show tags
                tags = mb_results.get('tags', [])
                if tags:
                    println("  Tags: {}".format(', '.join(tags)))
                
                # Show timestamps
                first_seen = mb_results.get('first_seen')
                last_seen = mb_results.get('last_seen')
                if first_seen:
                    first_date = datetime.datetime.fromtimestamp(int(first_seen)).strftime('%Y-%m-%d %H:%M:%S UTC')
                    println("  First Seen: {}".format(first_date))
                if last_seen:
                    last_date = datetime.datetime.fromtimestamp(int(last_seen)).strftime('%Y-%m-%d %H:%M:%S UTC')
                    println("  Last Seen: {}".format(last_date))
                
                # Show delivery method and intelligence
                delivery = mb_results.get('delivery_method', '')
                if delivery:
                    println("  Delivery Method: {}".format(delivery))
                
                intelligence = mb_results.get('intelligence', {})
                if intelligence:
                    downloads = intelligence.get('downloads', '')
                    uploads = intelligence.get('uploads', '')
                    if downloads:
                        println("  Downloads: {}".format(downloads))
                    if uploads:
                        println("  Uploads: {}".format(uploads))
            
            # Intezer results
            intezer_results = results.get("details", {}).get("intezer", {})
            if intezer_results and "error" not in intezer_results:
                println("\n[INTEZER GENETIC ANALYSIS]")
                println("  Verdict: {}".format(intezer_results.get('verdict', 'N/A')))
                println("  [MALWARE FAMILY] {}".format(intezer_results.get('family_name', 'N/A')))
                println("  Sub-verdict: {}".format(intezer_results.get('sub_verdict', 'N/A')))
                println("  Threat Level: {}".format(intezer_results.get('threat_level', 'N/A')))
                println("  Analysis Time: {}".format(intezer_results.get('analysis_time', 'N/A')))
                
                # Show tags
                tags = intezer_results.get('tags', [])
                if tags:
                    println("  Tags: {}".format(', '.join(tags)))
                
                # Show additional genetic information if available
                family_id = intezer_results.get('family_id', '')
                if family_id:
                    println("  Family ID: {}".format(family_id))
                
                # Show analysis URL if available
                analysis_url = intezer_results.get('analysis_url', '')
                if analysis_url:
                    println("  Analysis URL: {}".format(analysis_url))
            
            # Any.Run results
            anyrun_results = results.get("details", {}).get("anyrun", {})
            if anyrun_results and "error" not in anyrun_results:
                println("\n[ANY.RUN ADVANCED SANDBOX ANALYSIS]")
                println("  Verdict: {}".format(anyrun_results.get('verdict', 'N/A')))
                println("  Threat Score: {}".format(anyrun_results.get('threat_score', 'N/A')))
                println("  Malware Family: {}".format(anyrun_results.get('malware_family', 'N/A')))
                
                network_connections = anyrun_results.get('network_connections', [])
                if network_connections:
                    println("  Network Connections: {}".format(len(network_connections)))
                
                processes = anyrun_results.get('processes', [])
                if processes:
                    println("  Processes Created: {}".format(len(processes)))
                
                files_created = anyrun_results.get('files_created', [])
                if files_created:
                    println("  Files Created: {}".format(len(files_created)))
            
            # Triage results
            triage_results = results.get("details", {}).get("triage", {})
            if triage_results and "error" not in triage_results:
                println("\n[TRIAGE MALWARE ANALYSIS PLATFORM]")
                println("  Verdict: {}".format(triage_results.get('verdict', 'N/A')))
                println("  Threat Score: {}".format(triage_results.get('threat_score', 'N/A')))
                println("  Malware Family: {}".format(triage_results.get('malware_family', 'N/A')))
                
                behaviors = triage_results.get('behaviors', [])
                if behaviors:
                    println("  Behaviors: {}".format(len(behaviors)))
                
                processes = triage_results.get('processes', [])
                if processes:
                    println("  Processes: {}".format(len(processes)))
            
            # X-Force Exchange results
            xforce_results = results.get("details", {}).get("xforce", {})
            if xforce_results and "error" not in xforce_results:
                println("\n[X-FORCE EXCHANGE IBM THREAT INTELLIGENCE]")
                println("  Malware Type: {}".format(xforce_results.get('malware_type', 'N/A')))
                println("  Risk Level: {}".format(xforce_results.get('risk', 'N/A')))
                
                family = xforce_results.get('family', [])
                if family:
                    println("  Malware Family: {}".format(', '.join(family)))
                
                tags = xforce_results.get('tags', [])
                if tags:
                    println("  Tags: {}".format(', '.join(tags)))
            
            println("\n=== COMPREHENSIVE THREAT ASSESSMENT ===")
            
            # Collect all available indicators
            all_tags = set()
            all_families = set()
            all_verdicts = set()
            all_platforms = set()
            
            # Collect from VirusTotal
            vt_tags = vt_results.get('tags', []) if vt_results and "error" not in vt_results else []
            vt_families = vt_results.get('malware_families', []) if vt_results and "error" not in vt_results else []
            vt_threat_names = vt_results.get('threat_names', []) if vt_results and "error" not in vt_results else []
            all_tags.update(vt_tags)
            all_families.update(vt_families)
            all_families.update(vt_threat_names)
            
            # Collect from MalwareBazaar
            mb_tags = mb_results.get('tags', []) if mb_results and "error" not in mb_results else []
            mb_family = mb_results.get('signature', '') if mb_results and "error" not in mb_results else ''
            if mb_family and mb_family != 'N/A':
                all_families.add(mb_family)
            all_tags.update(mb_tags)
            
            # Collect from Intezer
            intezer_family = intezer_results.get('family_name', '') if intezer_results and "error" not in intezer_results else ''
            if intezer_family and intezer_family != 'N/A':
                all_families.add(intezer_family)
            
            # Collect from Hybrid Analysis
            ha_verdict = hybrid_results.get('verdict', '') if hybrid_results and "error" not in hybrid_results else ''
            if ha_verdict and ha_verdict != 'N/A':
                all_verdicts.add(ha_verdict)
            
            # Show consolidated indicators
            if all_families:
                println("  [MALWARE FAMILIES DETECTED] {}".format(', '.join(all_families)))
                println("    [WARNING] This sample belongs to known malware families!")
            if all_verdicts:
                println("  [SANDBOX VERDICTS] {}".format(', '.join(all_verdicts)))
            if all_tags:
                println("  [THREAT TAGS] {}".format(', '.join(sorted(all_tags)[:20])))  # Top 20 tags
            
            # Show file characteristics
            file_type = vt_results.get('file_type', '') if vt_results and "error" not in vt_results else ''
            file_size = vt_results.get('file_size', '') if vt_results and "error" not in vt_results else ''
            if file_type:
                println("  File Type: {}".format(file_type))
            if file_size:
                println("  File Size: {} bytes".format(file_size))
            
            println("\n=== MALWARE ANALYST HUNTING GUIDANCE ===")
            println("  Primary Hash (SHA256): {}".format(file_hash))
            println("\n  Hunting Queries:")
            println("    * VirusTotal: https://www.virustotal.com/gui/file/{}".format(file_hash))
            println("    * Hybrid Analysis: https://www.hybrid-analysis.com/search?query={}".format(file_hash))
            println("    * AlienVault OTX: https://otx.alienvault.com/indicator/file/{}".format(file_hash))
            println("    * Malware Bazaar: https://bazaar.abuse.ch/browse.php?search=hash%3A{}".format(file_hash))
            println("    * Intezer: https://analyze.intezer.com/files/{}".format(file_hash))
            println("    * Any.Run: https://app.any.run/{}".format(file_hash))
            println("    * Triage: https://tria.ge/{}".format(file_hash))
            println("    * X-Force Exchange: https://exchange.xforce.ibmcloud.com/malware/{}".format(file_hash))
            
            log_info(logger, "Comprehensive results displayed successfully")
            
        except Exception as e:
            log_error(logger, "Error displaying results: {}".format(e))
            println("[-] Error displaying results: {}".format(e))

def main():
    """Main function for the Threat Intelligence Analyzer"""
    try:
        println("[+] Starting Threat Intelligence Analyzer...")
        
        # Get current program file path
        if not currentProgram:
            println("[-] No program loaded")
            return
        
        program_path = currentProgram.getExecutablePath()
        if not program_path:
            println("[-] Could not determine program path")
            return
        
        log_info(logger, "Analyzing program: {}".format(program_path))
        
        # Initialize analyzer
        analyzer = ThreatIntelligenceAnalyzer()
        
        # Perform analysis
        results = analyzer.analyze_threat_intelligence(program_path)
        
        # Display results
        if results and "error" not in results:
            file_hash = results.get("summary", {}).get("file_hash", "UNKNOWN")
            analyzer.display_results(results, file_hash)
            println("\n[+] Threat Intelligence Analyzer completed successfully!")
        else:
            println("[-] Threat Intelligence analysis failed")
            if results:
                println("[-] {}".format(results.get("error", "Unknown error")))
        
    except Exception as e:
        log_error(logger, "Threat Intelligence Analyzer failed: {}".format(e))
        println("[-] Threat Intelligence Analyzer script failed: {}".format(e))

if __name__ == "__main__":
    main()
