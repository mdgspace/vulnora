def trim_logs_for_llm(attack_type, raw_logs, max_non_vuln=3, max_chars=500):
    def trunc(x):
        return x if not isinstance(x, str) or len(x) <= max_chars else x[:max_chars] + "...[truncated]"

    def summarise(item):
        if isinstance(item, dict):
            return {k: summarise(v) for k, v in list(item.items())[:15]}
        if isinstance(item, list):
            return [summarise(x) for x in item[:max_non_vuln]]
        return trunc(item)

    if isinstance(raw_logs, dict) and "detailed_logs" in raw_logs:
        logs = raw_logs["detailed_logs"]
        vuln = [summarise(l) for l in logs if isinstance(l, dict) and l.get("vulnerable")]
        nonv = [summarise(l) for l in logs if not (isinstance(l, dict) and l.get("vulnerable"))][:max_non_vuln]
        out = {k: summarise(v) for k, v in raw_logs.items() if k != "detailed_logs"}
        out["detailed_logs_trimmed"] = vuln + nonv
        out["detailed_logs_count"] = len(logs)
        return out

    if isinstance(raw_logs, dict):
        return {k: summarise(v) for k, v in list(raw_logs.items())[:15]}

    if isinstance(raw_logs, list):
        return [summarise(x) for x in raw_logs[:max_non_vuln]]

    return trunc(str(raw_logs))
