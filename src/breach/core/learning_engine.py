"""
BREACH.AI - Learning Engine

The AI that gets SMARTER with every attack.

This module:
1. Learns what works for each target type
2. Remembers successful attack patterns
3. Predicts vulnerabilities before scanning
4. Prioritizes attacks based on success history
5. Adapts techniques based on WAF/defense detection
6. Shares knowledge across all instances

"Every attack makes us smarter. Every target teaches us."
"""

import json
import os
import hashlib
import pickle
from dataclasses import dataclass, field
from typing import Optional, Any, Dict, List
from datetime import datetime
from collections import defaultdict
from pathlib import Path

from breach.utils.logger import logger


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class AttackPattern:
    """A successful attack pattern learned from history."""
    id: str
    attack_type: str
    payload: str
    target_technologies: List[str]

    # Statistics
    times_used: int = 0
    times_successful: int = 0
    success_rate: float = 0.0

    # Timing
    first_used: datetime = field(default_factory=datetime.now)
    last_used: datetime = field(default_factory=datetime.now)
    average_time_to_exploit: float = 0.0

    # Context
    waf_bypassed: List[str] = field(default_factory=list)
    encoding_used: str = ""
    http_method: str = "GET"

    # Impact
    impact_achieved: List[str] = field(default_factory=list)
    max_severity: str = "unknown"

    def update_success_rate(self):
        """Recalculate success rate."""
        if self.times_used > 0:
            self.success_rate = self.times_successful / self.times_used
        else:
            self.success_rate = 0.0


@dataclass
class TechnologyProfile:
    """Profile of vulnerabilities for a technology stack."""
    tech_stack: List[str]

    # Vulnerability statistics
    vulns_found: Dict[str, int] = field(default_factory=dict)  # vuln_type -> count
    total_scans: int = 0

    # Probabilities
    vuln_probability: Dict[str, float] = field(default_factory=dict)  # vuln_type -> probability

    # Best attacks
    best_attack_types: List[str] = field(default_factory=list)
    attack_success_rates: Dict[str, float] = field(default_factory=dict)

    # Timing
    average_scan_time: float = 0.0
    average_time_to_first_vuln: float = 0.0

    def update_probabilities(self):
        """Update vulnerability probabilities based on history."""
        if self.total_scans > 0:
            for vuln_type, count in self.vulns_found.items():
                self.vuln_probability[vuln_type] = count / self.total_scans


@dataclass
class WAFProfile:
    """Profile of bypass techniques for a WAF."""
    waf_type: str

    # Bypass techniques
    successful_payloads: List[Dict] = field(default_factory=list)
    failed_payloads: List[str] = field(default_factory=list)

    # Statistics
    bypass_attempts: int = 0
    bypass_successes: int = 0
    bypass_rate: float = 0.0

    # Best techniques
    best_encodings: List[str] = field(default_factory=list)
    best_evasion_techniques: List[str] = field(default_factory=list)

    def update_bypass_rate(self):
        """Update bypass rate."""
        if self.bypass_attempts > 0:
            self.bypass_rate = self.bypass_successes / self.bypass_attempts


@dataclass
class TargetHistory:
    """History of attacks against a specific target."""
    target: str
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)

    # Findings
    vulnerabilities: List[Dict] = field(default_factory=list)
    credentials: List[Dict] = field(default_factory=list)

    # Technology
    detected_technologies: List[str] = field(default_factory=list)
    detected_waf: str = ""

    # Statistics
    total_attacks: int = 0
    successful_attacks: int = 0

    # Timeline
    attack_timeline: List[Dict] = field(default_factory=list)


@dataclass
class LearningData:
    """Complete learning data store."""
    # Patterns
    attack_patterns: Dict[str, AttackPattern] = field(default_factory=dict)

    # Profiles
    technology_profiles: Dict[str, TechnologyProfile] = field(default_factory=dict)
    waf_profiles: Dict[str, WAFProfile] = field(default_factory=dict)

    # History
    target_history: Dict[str, TargetHistory] = field(default_factory=dict)

    # Global statistics
    total_attacks: int = 0
    successful_attacks: int = 0
    total_vulns_found: int = 0
    total_credentials_found: int = 0
    total_targets_scanned: int = 0

    # Metadata
    created_at: datetime = field(default_factory=datetime.now)
    last_updated: datetime = field(default_factory=datetime.now)
    version: str = "1.0"


# =============================================================================
# LEARNING ENGINE
# =============================================================================

class LearningEngine:
    """
    Machine learning engine that improves from attack history.

    Core capabilities:
    1. Pattern Learning - Learns which attacks work on which targets
    2. Prediction - Predicts vulnerabilities based on tech stack
    3. Prioritization - Orders attacks by likelihood of success
    4. WAF Adaptation - Learns which bypasses work for each WAF
    5. Knowledge Sharing - Exports/imports knowledge between instances

    The engine stores all data locally and can sync with a central server.
    """

    def __init__(self, data_dir: str = None):
        """Initialize learning engine."""
        self.data_dir = data_dir or os.path.expanduser("~/.breach_ai/learning")
        os.makedirs(self.data_dir, exist_ok=True)

        self.data_file = os.path.join(self.data_dir, "learning_data.pkl")
        self.json_export = os.path.join(self.data_dir, "learning_data.json")

        # Load existing data
        self.data = self._load_data()

        # In-memory caches for fast access
        self._tech_cache: Dict[str, List[str]] = {}
        self._attack_priority_cache: Dict[str, List[str]] = {}

        logger.info(f"Learning Engine initialized with {len(self.data.attack_patterns)} patterns")

    # =========================================================================
    # DATA PERSISTENCE
    # =========================================================================

    def _load_data(self) -> LearningData:
        """Load learning data from disk."""
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, 'rb') as f:
                    data = pickle.load(f)
                    logger.info(f"Loaded learning data: {data.total_attacks} attacks, {data.total_vulns_found} vulns")
                    return data
            except Exception as e:
                logger.warning(f"Failed to load learning data: {e}")

        return LearningData()

    def save(self):
        """Save learning data to disk."""
        self.data.last_updated = datetime.now()

        try:
            # Save pickle for fast loading
            with open(self.data_file, 'wb') as f:
                pickle.dump(self.data, f)

            # Also save JSON for human readability and export
            self._save_json_export()

            logger.debug("Learning data saved")
        except Exception as e:
            logger.error(f"Failed to save learning data: {e}")

    def _save_json_export(self):
        """Save human-readable JSON export."""
        export = {
            "version": self.data.version,
            "created_at": self.data.created_at.isoformat() if self.data.created_at else None,
            "last_updated": self.data.last_updated.isoformat() if self.data.last_updated else None,
            "statistics": {
                "total_attacks": self.data.total_attacks,
                "successful_attacks": self.data.successful_attacks,
                "success_rate": self.data.successful_attacks / self.data.total_attacks if self.data.total_attacks > 0 else 0,
                "total_vulns_found": self.data.total_vulns_found,
                "total_credentials_found": self.data.total_credentials_found,
                "total_targets_scanned": self.data.total_targets_scanned,
                "unique_patterns": len(self.data.attack_patterns),
                "technology_profiles": len(self.data.technology_profiles),
                "waf_profiles": len(self.data.waf_profiles),
            },
            "top_attack_patterns": self._get_top_patterns(20),
            "technology_insights": self._get_tech_insights(),
            "waf_insights": self._get_waf_insights(),
        }

        with open(self.json_export, 'w') as f:
            json.dump(export, f, indent=2, default=str)

    # =========================================================================
    # LEARNING FROM ATTACKS
    # =========================================================================

    def learn_from_attack(
        self,
        attack_type: str,
        payload: str,
        target: str,
        target_tech: List[str],
        success: bool,
        waf_type: str = "",
        time_taken: float = 0.0,
        http_method: str = "GET",
        encoding: str = "",
        impact: str = "",
        severity: str = "",
    ):
        """
        Learn from an attack attempt.

        This is called after every attack to update our knowledge base.
        """
        logger.debug(f"Learning from attack: {attack_type} -> {success}")

        # Update global stats
        self.data.total_attacks += 1
        if success:
            self.data.successful_attacks += 1

        # Create pattern ID
        pattern_id = self._create_pattern_id(attack_type, payload)

        # Update or create attack pattern
        self._update_attack_pattern(
            pattern_id=pattern_id,
            attack_type=attack_type,
            payload=payload,
            target_tech=target_tech,
            success=success,
            waf_type=waf_type,
            time_taken=time_taken,
            http_method=http_method,
            encoding=encoding,
            impact=impact,
            severity=severity,
        )

        # Update technology profile
        self._update_tech_profile(target_tech, attack_type, success)

        # Update WAF profile
        if waf_type:
            self._update_waf_profile(waf_type, payload, attack_type, success, encoding)

        # Update target history
        self._update_target_history(target, target_tech, waf_type, attack_type, success)

        # Clear caches
        self._invalidate_caches()

        # Auto-save periodically
        if self.data.total_attacks % 50 == 0:
            self.save()

    def learn_from_vulnerability(
        self,
        vuln_type: str,
        target: str,
        target_tech: List[str],
        severity: str = "",
        evidence: str = "",
        cvss_score: float = 0.0,
    ):
        """Learn from a discovered vulnerability."""
        logger.info(f"Learning from vulnerability: {vuln_type}")

        self.data.total_vulns_found += 1

        # Update technology profile with vulnerability
        tech_key = self._get_tech_key(target_tech)

        if tech_key not in self.data.technology_profiles:
            self.data.technology_profiles[tech_key] = TechnologyProfile(
                tech_stack=target_tech
            )

        profile = self.data.technology_profiles[tech_key]

        # Increment vuln count
        if vuln_type not in profile.vulns_found:
            profile.vulns_found[vuln_type] = 0
        profile.vulns_found[vuln_type] += 1

        # Update probabilities
        profile.update_probabilities()

        # Update target history
        if target in self.data.target_history:
            self.data.target_history[target].vulnerabilities.append({
                "type": vuln_type,
                "severity": severity,
                "cvss": cvss_score,
                "found_at": datetime.now().isoformat(),
            })

    def learn_from_credential(
        self,
        target: str,
        credential_type: str,
        access_level: str = "",
    ):
        """Learn from a discovered credential."""
        logger.info(f"Learning from credential: {credential_type}")

        self.data.total_credentials_found += 1

        if target in self.data.target_history:
            self.data.target_history[target].credentials.append({
                "type": credential_type,
                "access_level": access_level,
                "found_at": datetime.now().isoformat(),
            })

    # =========================================================================
    # INTERNAL UPDATE METHODS
    # =========================================================================

    def _create_pattern_id(self, attack_type: str, payload: str) -> str:
        """Create unique ID for an attack pattern."""
        # Hash attack type + normalized payload
        normalized = f"{attack_type}:{payload[:200].lower().strip()}"
        return hashlib.md5(normalized.encode()).hexdigest()[:16]

    def _get_tech_key(self, technologies: List[str]) -> str:
        """Create key for technology profile."""
        return ":".join(sorted(set(t.lower() for t in technologies)))

    def _update_attack_pattern(
        self,
        pattern_id: str,
        attack_type: str,
        payload: str,
        target_tech: List[str],
        success: bool,
        waf_type: str,
        time_taken: float,
        http_method: str,
        encoding: str,
        impact: str,
        severity: str,
    ):
        """Update or create an attack pattern."""
        if pattern_id in self.data.attack_patterns:
            pattern = self.data.attack_patterns[pattern_id]

            # Update statistics
            pattern.times_used += 1
            if success:
                pattern.times_successful += 1
            pattern.update_success_rate()

            # Update timing
            pattern.last_used = datetime.now()
            if time_taken > 0:
                # Running average
                n = pattern.times_used
                pattern.average_time_to_exploit = (
                    (pattern.average_time_to_exploit * (n - 1) + time_taken) / n
                )

            # Add new technologies
            for tech in target_tech:
                if tech not in pattern.target_technologies:
                    pattern.target_technologies.append(tech)

            # Add WAF bypass
            if success and waf_type and waf_type not in pattern.waf_bypassed:
                pattern.waf_bypassed.append(waf_type)

            # Update impact
            if impact and impact not in pattern.impact_achieved:
                pattern.impact_achieved.append(impact)

            # Update severity
            if severity:
                severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
                if severity_order.get(severity, 0) > severity_order.get(pattern.max_severity, 0):
                    pattern.max_severity = severity
        else:
            # Create new pattern
            self.data.attack_patterns[pattern_id] = AttackPattern(
                id=pattern_id,
                attack_type=attack_type,
                payload=payload[:1000],  # Truncate long payloads
                target_technologies=list(target_tech),
                times_used=1,
                times_successful=1 if success else 0,
                success_rate=1.0 if success else 0.0,
                waf_bypassed=[waf_type] if success and waf_type else [],
                encoding_used=encoding,
                http_method=http_method,
                impact_achieved=[impact] if impact else [],
                max_severity=severity or "unknown",
                average_time_to_exploit=time_taken,
            )

    def _update_tech_profile(
        self,
        technologies: List[str],
        attack_type: str,
        success: bool,
    ):
        """Update technology profile."""
        tech_key = self._get_tech_key(technologies)

        if tech_key not in self.data.technology_profiles:
            self.data.technology_profiles[tech_key] = TechnologyProfile(
                tech_stack=list(technologies)
            )

        profile = self.data.technology_profiles[tech_key]
        profile.total_scans += 1

        # Update attack success rates
        if attack_type not in profile.attack_success_rates:
            profile.attack_success_rates[attack_type] = 0.0

        # Running average
        current_rate = profile.attack_success_rates[attack_type]
        n = profile.total_scans
        new_rate = (current_rate * (n - 1) + (1.0 if success else 0.0)) / n
        profile.attack_success_rates[attack_type] = new_rate

        # Update best attacks
        sorted_attacks = sorted(
            profile.attack_success_rates.items(),
            key=lambda x: x[1],
            reverse=True
        )
        profile.best_attack_types = [a[0] for a in sorted_attacks[:10]]

    def _update_waf_profile(
        self,
        waf_type: str,
        payload: str,
        attack_type: str,
        success: bool,
        encoding: str,
    ):
        """Update WAF bypass profile."""
        if waf_type not in self.data.waf_profiles:
            self.data.waf_profiles[waf_type] = WAFProfile(waf_type=waf_type)

        profile = self.data.waf_profiles[waf_type]
        profile.bypass_attempts += 1

        if success:
            profile.bypass_successes += 1
            profile.successful_payloads.append({
                "payload": payload[:500],
                "attack_type": attack_type,
                "encoding": encoding,
                "timestamp": datetime.now().isoformat(),
            })

            # Track best encodings
            if encoding and encoding not in profile.best_encodings:
                profile.best_encodings.append(encoding)
        else:
            if payload not in profile.failed_payloads:
                profile.failed_payloads.append(payload[:500])

        profile.update_bypass_rate()

    def _update_target_history(
        self,
        target: str,
        technologies: List[str],
        waf_type: str,
        attack_type: str,
        success: bool,
    ):
        """Update target attack history."""
        if target not in self.data.target_history:
            self.data.target_history[target] = TargetHistory(target=target)
            self.data.total_targets_scanned += 1

        history = self.data.target_history[target]
        history.last_seen = datetime.now()
        history.total_attacks += 1
        if success:
            history.successful_attacks += 1

        # Update detected technologies
        for tech in technologies:
            if tech not in history.detected_technologies:
                history.detected_technologies.append(tech)

        # Update WAF
        if waf_type:
            history.detected_waf = waf_type

        # Add to timeline
        history.attack_timeline.append({
            "attack_type": attack_type,
            "success": success,
            "timestamp": datetime.now().isoformat(),
        })

        # Keep timeline manageable
        if len(history.attack_timeline) > 1000:
            history.attack_timeline = history.attack_timeline[-500:]

    def _invalidate_caches(self):
        """Clear cached computations."""
        self._tech_cache.clear()
        self._attack_priority_cache.clear()

    # =========================================================================
    # PREDICTIONS
    # =========================================================================

    def predict_vulnerabilities(
        self,
        target_tech: List[str],
        top_n: int = 10,
    ) -> List[Dict]:
        """
        Predict likely vulnerabilities for a technology stack.

        Returns list of {vulnerability, probability, confidence, based_on}
        """
        logger.info(f"Predicting vulnerabilities for {target_tech}")

        predictions = defaultdict(lambda: {"probability": 0.0, "confidence": 0, "sources": []})

        tech_set = set(t.lower() for t in target_tech)

        # Find matching profiles
        for tech_key, profile in self.data.technology_profiles.items():
            profile_tech = set(t.lower() for t in profile.tech_stack)

            # Calculate similarity
            intersection = tech_set.intersection(profile_tech)
            if not intersection:
                continue

            similarity = len(intersection) / max(len(tech_set), len(profile_tech))
            confidence = min(profile.total_scans, 100)  # More scans = more confidence

            # Add weighted probabilities
            for vuln_type, prob in profile.vuln_probability.items():
                weighted_prob = prob * similarity

                predictions[vuln_type]["probability"] = max(
                    predictions[vuln_type]["probability"],
                    weighted_prob
                )
                predictions[vuln_type]["confidence"] += confidence * similarity
                predictions[vuln_type]["sources"].append({
                    "tech_stack": profile.tech_stack,
                    "similarity": similarity,
                })

        # Convert to list and sort
        result = []
        for vuln_type, data in predictions.items():
            result.append({
                "vulnerability": vuln_type,
                "probability": round(data["probability"], 3),
                "confidence": round(data["confidence"], 1),
                "based_on": data["sources"][:3],
            })

        result.sort(key=lambda x: (x["probability"], x["confidence"]), reverse=True)

        return result[:top_n]

    def get_best_attacks(
        self,
        target_tech: List[str],
        waf_type: str = "",
        top_n: int = 20,
    ) -> List[Dict]:
        """
        Get best attacks for a target based on historical success.

        Returns list of {attack_type, success_rate, payloads, confidence}
        """
        logger.info(f"Getting best attacks for {target_tech}")

        attack_scores = defaultdict(lambda: {
            "success_rate": 0.0,
            "samples": 0,
            "payloads": [],
            "avg_time": 0.0,
        })

        tech_set = set(t.lower() for t in target_tech)

        # Score attacks based on patterns
        for pattern in self.data.attack_patterns.values():
            pattern_tech = set(t.lower() for t in pattern.target_technologies)

            # Check tech overlap
            if not tech_set.intersection(pattern_tech):
                continue

            attack_type = pattern.attack_type

            # Weight by overlap and success rate
            overlap = len(tech_set.intersection(pattern_tech)) / len(tech_set)
            weighted_success = pattern.success_rate * overlap

            # Update scores
            current = attack_scores[attack_type]
            current["samples"] += pattern.times_used
            current["success_rate"] = max(current["success_rate"], weighted_success)

            # Add successful payloads
            if pattern.success_rate > 0.5 and pattern.payload not in current["payloads"]:
                current["payloads"].append(pattern.payload)

            current["avg_time"] = pattern.average_time_to_exploit

        # Add WAF-specific bypasses
        if waf_type and waf_type in self.data.waf_profiles:
            waf_profile = self.data.waf_profiles[waf_type]

            for payload_info in waf_profile.successful_payloads[-20:]:
                attack_type = payload_info.get("attack_type", "unknown")
                if attack_type in attack_scores:
                    attack_scores[attack_type]["waf_bypass_payloads"] = [
                        p["payload"] for p in waf_profile.successful_payloads
                        if p.get("attack_type") == attack_type
                    ][:5]

        # Convert to list
        result = []
        for attack_type, data in attack_scores.items():
            result.append({
                "attack_type": attack_type,
                "success_rate": round(data["success_rate"], 3),
                "samples": data["samples"],
                "payloads": data["payloads"][:5],
                "avg_time_seconds": round(data["avg_time"], 2),
                "waf_bypass_payloads": data.get("waf_bypass_payloads", []),
            })

        result.sort(key=lambda x: (x["success_rate"], x["samples"]), reverse=True)

        return result[:top_n]

    def prioritize_attacks(
        self,
        available_attacks: List[str],
        target_tech: List[str],
        waf_type: str = "",
    ) -> List[str]:
        """
        Prioritize attacks for optimal ordering.

        Returns attacks sorted by predicted effectiveness.
        """
        cache_key = f"{':'.join(sorted(target_tech))}:{waf_type}"

        if cache_key in self._attack_priority_cache:
            cached = self._attack_priority_cache[cache_key]
            return [a for a in cached if a in available_attacks]

        # Get best attacks
        best = self.get_best_attacks(target_tech, waf_type, top_n=50)
        best_order = [a["attack_type"] for a in best]

        # Prioritize available attacks
        prioritized = []
        for attack in best_order:
            if attack in available_attacks and attack not in prioritized:
                prioritized.append(attack)

        # Add remaining attacks
        for attack in available_attacks:
            if attack not in prioritized:
                prioritized.append(attack)

        self._attack_priority_cache[cache_key] = prioritized

        return prioritized

    def get_waf_bypasses(
        self,
        waf_type: str,
        attack_type: str = "",
    ) -> List[str]:
        """Get known WAF bypass payloads."""
        if waf_type not in self.data.waf_profiles:
            return []

        profile = self.data.waf_profiles[waf_type]

        payloads = []
        for p in profile.successful_payloads:
            if attack_type and p.get("attack_type") != attack_type:
                continue
            payloads.append(p["payload"])

        return payloads[:20]

    # =========================================================================
    # STATISTICS & INSIGHTS
    # =========================================================================

    def get_statistics(self) -> Dict:
        """Get comprehensive learning statistics."""
        overall_success_rate = (
            self.data.successful_attacks / self.data.total_attacks
            if self.data.total_attacks > 0 else 0
        )

        return {
            "total_attacks": self.data.total_attacks,
            "successful_attacks": self.data.successful_attacks,
            "overall_success_rate": round(overall_success_rate, 3),
            "total_vulnerabilities_found": self.data.total_vulns_found,
            "total_credentials_found": self.data.total_credentials_found,
            "total_targets_scanned": self.data.total_targets_scanned,
            "unique_patterns": len(self.data.attack_patterns),
            "technology_profiles": len(self.data.technology_profiles),
            "waf_profiles": len(self.data.waf_profiles),
            "wafs_bypassed": list(self.data.waf_profiles.keys()),
            "top_patterns": self._get_top_patterns(10),
            "last_updated": self.data.last_updated.isoformat() if self.data.last_updated else None,
        }

    def _get_top_patterns(self, n: int) -> List[Dict]:
        """Get top performing attack patterns."""
        patterns = []

        for pattern in self.data.attack_patterns.values():
            if pattern.times_used >= 5:  # Minimum samples
                patterns.append({
                    "attack_type": pattern.attack_type,
                    "success_rate": round(pattern.success_rate, 3),
                    "times_used": pattern.times_used,
                    "technologies": pattern.target_technologies[:5],
                    "waf_bypassed": pattern.waf_bypassed,
                })

        patterns.sort(key=lambda x: (x["success_rate"], x["times_used"]), reverse=True)
        return patterns[:n]

    def _get_tech_insights(self) -> Dict:
        """Get technology-based insights."""
        insights = {}

        for tech_key, profile in self.data.technology_profiles.items():
            if profile.total_scans >= 3:
                insights[tech_key] = {
                    "tech_stack": profile.tech_stack,
                    "scans": profile.total_scans,
                    "common_vulns": dict(sorted(
                        profile.vuln_probability.items(),
                        key=lambda x: x[1],
                        reverse=True
                    )[:5]),
                    "best_attacks": profile.best_attack_types[:5],
                }

        return insights

    def _get_waf_insights(self) -> Dict:
        """Get WAF bypass insights."""
        insights = {}

        for waf_type, profile in self.data.waf_profiles.items():
            insights[waf_type] = {
                "bypass_rate": round(profile.bypass_rate, 3),
                "attempts": profile.bypass_attempts,
                "successes": profile.bypass_successes,
                "best_encodings": profile.best_encodings[:5],
                "successful_payload_count": len(profile.successful_payloads),
            }

        return insights

    # =========================================================================
    # KNOWLEDGE SHARING
    # =========================================================================

    def export_knowledge(self) -> Dict:
        """Export learned knowledge for sharing."""
        return {
            "version": self.data.version,
            "exported_at": datetime.now().isoformat(),
            "statistics": self.get_statistics(),
            "attack_patterns": [
                {
                    "id": p.id,
                    "attack_type": p.attack_type,
                    "payload": p.payload,
                    "success_rate": p.success_rate,
                    "times_used": p.times_used,
                    "target_technologies": p.target_technologies,
                    "waf_bypassed": p.waf_bypassed,
                }
                for p in self.data.attack_patterns.values()
                if p.times_used >= 3 and p.success_rate > 0.3
            ],
            "waf_bypasses": {
                waf: {
                    "bypass_rate": profile.bypass_rate,
                    "successful_payloads": profile.successful_payloads[-50:],
                    "best_encodings": profile.best_encodings,
                }
                for waf, profile in self.data.waf_profiles.items()
            },
            "technology_insights": self._get_tech_insights(),
        }

    def import_knowledge(self, knowledge: Dict):
        """Import knowledge from another instance."""
        logger.info("Importing knowledge...")

        imported_patterns = 0
        imported_waf = 0

        # Import attack patterns
        for pattern_data in knowledge.get("attack_patterns", []):
            pattern_id = pattern_data.get("id")
            if not pattern_id:
                continue

            if pattern_id in self.data.attack_patterns:
                # Merge statistics
                existing = self.data.attack_patterns[pattern_id]
                existing.times_used += pattern_data.get("times_used", 0)
                existing.times_successful += int(
                    pattern_data.get("times_used", 0) * pattern_data.get("success_rate", 0)
                )
                existing.update_success_rate()

                # Merge technologies
                for tech in pattern_data.get("target_technologies", []):
                    if tech not in existing.target_technologies:
                        existing.target_technologies.append(tech)

                # Merge WAF bypasses
                for waf in pattern_data.get("waf_bypassed", []):
                    if waf not in existing.waf_bypassed:
                        existing.waf_bypassed.append(waf)
            else:
                # Create new pattern
                self.data.attack_patterns[pattern_id] = AttackPattern(
                    id=pattern_id,
                    attack_type=pattern_data.get("attack_type", "unknown"),
                    payload=pattern_data.get("payload", ""),
                    target_technologies=pattern_data.get("target_technologies", []),
                    times_used=pattern_data.get("times_used", 0),
                    times_successful=int(
                        pattern_data.get("times_used", 0) * pattern_data.get("success_rate", 0)
                    ),
                    success_rate=pattern_data.get("success_rate", 0),
                    waf_bypassed=pattern_data.get("waf_bypassed", []),
                )
                imported_patterns += 1

        # Import WAF bypasses
        for waf, waf_data in knowledge.get("waf_bypasses", {}).items():
            if waf not in self.data.waf_profiles:
                self.data.waf_profiles[waf] = WAFProfile(waf_type=waf)

            profile = self.data.waf_profiles[waf]

            for payload_info in waf_data.get("successful_payloads", []):
                if payload_info not in profile.successful_payloads:
                    profile.successful_payloads.append(payload_info)
                    imported_waf += 1

            for encoding in waf_data.get("best_encodings", []):
                if encoding not in profile.best_encodings:
                    profile.best_encodings.append(encoding)

        self.save()
        self._invalidate_caches()

        logger.info(f"Imported {imported_patterns} patterns, {imported_waf} WAF bypasses")

    def reset(self):
        """Reset all learning data."""
        logger.warning("Resetting all learning data!")
        self.data = LearningData()
        self.save()
        self._invalidate_caches()


# =============================================================================
# GLOBAL INSTANCE
# =============================================================================

_learning_engine: Optional[LearningEngine] = None


def get_learning_engine() -> LearningEngine:
    """Get or create global learning engine instance."""
    global _learning_engine
    if _learning_engine is None:
        _learning_engine = LearningEngine()
    return _learning_engine


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def learn_attack(
    attack_type: str,
    payload: str,
    target: str,
    target_tech: List[str],
    success: bool,
    **kwargs
):
    """Learn from an attack attempt."""
    engine = get_learning_engine()
    engine.learn_from_attack(attack_type, payload, target, target_tech, success, **kwargs)


def learn_vulnerability(vuln_type: str, target: str, target_tech: List[str], **kwargs):
    """Learn from a discovered vulnerability."""
    engine = get_learning_engine()
    engine.learn_from_vulnerability(vuln_type, target, target_tech, **kwargs)


def predict_vulns(target_tech: List[str]) -> List[Dict]:
    """Predict vulnerabilities for a tech stack."""
    engine = get_learning_engine()
    return engine.predict_vulnerabilities(target_tech)


def get_best_attacks(target_tech: List[str], waf_type: str = "") -> List[Dict]:
    """Get best attacks for a target."""
    engine = get_learning_engine()
    return engine.get_best_attacks(target_tech, waf_type)


def prioritize_attacks(attacks: List[str], target_tech: List[str], waf_type: str = "") -> List[str]:
    """Prioritize attacks by predicted success."""
    engine = get_learning_engine()
    return engine.prioritize_attacks(attacks, target_tech, waf_type)


def get_waf_bypasses(waf_type: str, attack_type: str = "") -> List[str]:
    """Get WAF bypass payloads."""
    engine = get_learning_engine()
    return engine.get_waf_bypasses(waf_type, attack_type)


def get_learning_stats() -> Dict:
    """Get learning statistics."""
    engine = get_learning_engine()
    return engine.get_statistics()
