import requests
import ipaddress
import os
import time
from datetime import datetime, timedelta
import logging
from config.settings import (
    THREAT_INTEL_DIR, THREAT_INTEL_UPDATE_INTERVAL,
    ABUSEIPDB_API_KEY, ALIENVAULT_API_KEY
)

logger = logging.getLogger('ids')

class ThreatIntelligence:
    def __init__(self, use_cache_only=False):
        self.malicious_ips = set()
        self.malicious_ip_ranges = []
        self.last_update = None
        self.update_interval = timedelta(hours=THREAT_INTEL_UPDATE_INTERVAL)
        self.use_cache_only = use_cache_only

        self._load_cached_data()

        if not use_cache_only:
            self.update_if_needed()

    def _load_cached_data(self):
        ips_path = os.path.join(THREAT_INTEL_DIR, 'malicious_ips.txt')
        ranges_path = os.path.join(THREAT_INTEL_DIR, 'malicious_ranges.txt')

        if os.path.exists(ips_path):
            with open(ips_path, 'r') as f:
                self.malicious_ips = set(line.strip() for line in f if line.strip())
            mod_time = os.path.getmtime(ips_path)
            self.last_update = datetime.fromtimestamp(mod_time)

        if os.path.exists(ranges_path):
            with open(ranges_path, 'r') as f:
                self.malicious_ip_ranges = [
                    ipaddress.ip_network(line.strip())
                    for line in f if line.strip()
                ]

    def _save_cached_data(self):
        ips_path = os.path.join(THREAT_INTEL_DIR, 'malicious_ips.txt')
        ranges_path = os.path.join(THREAT_INTEL_DIR, 'malicious_ranges.txt')

        with open(ips_path, 'w') as f:
            for ip in self.malicious_ips:
                f.write(f"{ip}\n")

        with open(ranges_path, 'w') as f:
            for ip_range in self.malicious_ip_ranges:
                f.write(f"{ip_range}\n")

    def update_if_needed(self):
        if self.use_cache_only:
            logger.info("Using cached threat intelligence only.")
            return

        now = datetime.now()
        if self.last_update is None or (now - self.last_update) > self.update_interval:
            self.update_threat_intelligence()
            self.last_update = now

    def update_threat_intelligence(self):
        logger.info("Updating threat intelligence...")
        self.malicious_ips.clear()
        self.malicious_ip_ranges.clear()

        self._update_abuseipdb()
        self._update_spamhaus()
        self._update_emerging_threats()
        self._update_alienvault_otx()
        self._update_firehol()

        self._save_cached_data()

        logger.info(f"Threat intelligence updated. {len(self.malicious_ips)} individual IPs and {len(self.malicious_ip_ranges)} IP ranges loaded.")

    def _update_abuseipdb(self):
        try:
            url = "https://api.abuseipdb.com/api/v2/blacklist"
            headers = {
                "Accept": "application/json",
                "Key": ABUSEIPDB_API_KEY
            }
            params = {
                "confidenceMinimum": "90"
            }

            response = requests.get(url, headers=headers, params=params)
            if response.status_code == 200:
                data = response.json()
                for entry in data.get("data", []):
                    ip = entry.get("ipAddress")
                    if ip:
                        self.malicious_ips.add(ip)
                logger.info(f"Loaded {len(data.get('data', []))} IPs from AbuseIPDB")
            else:
                logger.warning(f"Failed to fetch AbuseIPDB data: {response.status_code}")
        except Exception as e:
            logger.error(f"Error updating AbuseIPDB: {str(e)}")

    def _update_spamhaus(self):
        try:
            url = "https://www.spamhaus.org/drop/drop.txt"
            response = requests.get(url)
            if response.status_code == 200:
                count = 0
                for line in response.text.splitlines():
                    line = line.strip()
                    if line and not line.startswith(";"):
                        cidr = line.split(";")[0].strip()
                        try:
                            self.malicious_ip_ranges.append(ipaddress.ip_network(cidr))
                            count += 1
                        except ValueError:
                            continue
                logger.info(f"Loaded {count} ranges from Spamhaus")
            else:
                logger.warning(f"Failed to fetch Spamhaus data: {response.status_code}")
        except Exception as e:
            logger.error(f"Error updating Spamhaus: {str(e)}")

    def _update_emerging_threats(self):
        try:
            url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
            response = requests.get(url)
            if response.status_code == 200:
                count = 0
                for line in response.text.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.malicious_ips.add(line)
                        count += 1
                logger.info(f"Loaded {count} IPs from Emerging Threats")
            else:
                logger.warning(f"Failed to fetch Emerging Threats data: {response.status_code}")
        except Exception as e:
            logger.error(f"Error updating Emerging Threats: {str(e)}")

    def _update_alienvault_otx(self):
        try:
            url = "https://otx.alienvault.com/api/v1/indicators/export"
            params = {
                "apikey": ALIENVAULT_API_KEY,
                "type": "IPv4"
            }

            response = requests.get(url, params=params)
            if response.status_code == 200:
                count = 0
                for line in response.text.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.malicious_ips.add(line)
                        count += 1
                logger.info(f"Loaded {count} IPs from AlienVault OTX")
            else:
                logger.warning(f"Failed to fetch AlienVault OTX data: {response.status_code}")
        except Exception as e:
            logger.error(f"Error updating AlienVault OTX: {str(e)}")

    def _update_firehol(self):
        try:
            url = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
            response = requests.get(url)
            if response.status_code == 200:
                count = 0
                for line in response.text.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        try:
                            ip_net = ipaddress.ip_network(line)
                            self.malicious_ip_ranges.append(ip_net)
                            count += 1
                        except ValueError:
                            continue
                logger.info(f"Loaded {count} IP ranges from FireHOL")
            else:
                logger.warning(f"Failed to fetch FireHOL data: {response.status_code}")
        except Exception as e:
            logger.error(f"Error updating FireHOL: {str(e)}")

    def is_malicious(self, ip_str):
        """Check if IP is malicious — now only uses loaded data"""
        if ip_str in self.malicious_ips:
            return True

        try:
            ip = ipaddress.ip_address(ip_str)
            for ip_range in self.malicious_ip_ranges:
                if ip in ip_range:
                    return True
        except ValueError:
            logger.warning(f"Invalid IP address format: {ip_str}")

        return False
