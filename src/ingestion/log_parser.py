"""
Multi-Layer Log Ingestion & Parsing Module
Supports: network logs, auth logs, application access logs, API logs.
"""

import json
import csv
from pathlib import Path
from typing import List, Dict
from loguru import logger


SUPPORTED_EXTENSIONS = {".json", ".csv", ".log"}


class LogParser:
    """
    Parses raw log files from multiple sources into a normalized event format.
    
    Supported log types:
        - network: firewall and flow logs
        - auth: login/logout events, MFA, SSO
        - app: application access and usage events
        - api: API gateway call logs
    """

    def __init__(self, log_dir: str):
        self.log_dir = Path(log_dir)

    def parse_all(self) -> List[Dict]:
        """Parse all log files in the directory."""
        all_events = []

        if not self.log_dir.exists():
            logger.warning("Log directory {} not found.", self.log_dir)
            return []

        for file_path in self.log_dir.iterdir():
            if file_path.suffix not in SUPPORTED_EXTENSIONS:
                continue
            try:
                events = self._parse_file(file_path)
                all_events.extend(events)
                logger.debug("Parsed {} events from {}", len(events), file_path.name)
            except Exception as e:
                logger.error("Failed to parse {}: {}", file_path.name, e)

        logger.info("Total events loaded: {}", len(all_events))
        return all_events

    def _parse_file(self, file_path: Path) -> List[Dict]:
        suffix = file_path.suffix
        if suffix == ".json":
            return self._parse_json(file_path)
        elif suffix == ".csv":
            return self._parse_csv(file_path)
        elif suffix == ".log":
            return self._parse_syslog(file_path)
        return []

    def _parse_json(self, path: Path) -> List[Dict]:
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, list):
            return [self._normalize(e) for e in data]
        return [self._normalize(data)]

    def _parse_csv(self, path: Path) -> List[Dict]:
        events = []
        with open(path, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                events.append(self._normalize(dict(row)))
        return events

    def _parse_syslog(self, path: Path) -> List[Dict]:
        """Basic syslog line parser — extend for real syslog formats."""
        events = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                events.append(self._normalize({"raw_log": line, "source": path.stem}))
        return events

    def _normalize(self, raw: Dict) -> Dict:
        """
        Normalize diverse log formats into a standard schema.
        Missing fields get safe defaults.
        """
        return {
            "id":                   raw.get("id", raw.get("event_id", "")),
            "timestamp":            raw.get("timestamp", raw.get("time", raw.get("ts", ""))),
            "user":                 raw.get("user", raw.get("username", raw.get("src_user", "unknown"))),
            "device":               raw.get("device", raw.get("hostname", raw.get("src_ip", "unknown"))),
            "entity_type":          raw.get("entity_type", "user"),
            "source":               raw.get("source", raw.get("log_source", "unknown")),
            "failed_logins_1h":     int(raw.get("failed_logins_1h", 0)),
            "unique_ips_accessed":  int(raw.get("unique_ips_accessed", 0)),
            "data_transferred_mb":  float(raw.get("data_transferred_mb", 0)),
            "off_hours":            bool(raw.get("off_hours", False)),
            "new_device":           bool(raw.get("new_device", False)),
            "privilege_level":      int(raw.get("privilege_level", 1)),
            "api_calls_per_min":    float(raw.get("api_calls_per_min", 0)),
            "lateral_hops":         int(raw.get("lateral_hops", 0)),
            "historical_incidents": int(raw.get("historical_incidents", 0)),
        }
