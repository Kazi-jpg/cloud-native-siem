-- Most observed MITRE ATT&CK techniques
SELECT technique, COUNT(*) as hits
FROM `cloud-native-siem.siem_data.security_events`,
UNNEST(mitre_techniques) AS technique
GROUP BY technique
ORDER BY hits DESC;

-- Phishing activity detection (T1566)
SELECT indicator_value, timestamp
FROM `cloud-native-siem.siem_data.security_events`,
UNNEST(mitre_techniques) AS technique
WHERE technique IN ("T1566", "T1566.002");

-- MITRE activity timeline
SELECT DATE(timestamp) as day, technique, COUNT(*) as activity_count
FROM `cloud-native-siem.siem_data.security_events`,
UNNEST(mitre_techniques) AS technique
GROUP BY day, technique
ORDER BY day DESC;


-- High severity MITRE activity
SELECT technique, severity, COUNT(*) as hits
FROM `cloud-native-siem.siem_data.security_events`,
UNNEST(mitre_techniques) AS technique
WHERE severity IN ("HIGH", "CRITICAL")
GROUP BY technique, severity
ORDER BY hits DESC;