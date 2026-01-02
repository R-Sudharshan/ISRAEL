import statistics

def detect_beaconing(timestamps, tolerance=0.1):
    """
    Analyzes a sorted list of timestamps (datetime objects) to detect fixed-interval patterns (beaconing).
    
    Args:
    timestamps: List of datetime objects sorted ascending.
    tolerance: Allowed variance in the interval (10% default).

    Returns:
    Dict with detection details if beaconing is detected, else None.
    """
    if len(timestamps) < 4:
        return None

    intervals = []
    for i in range(1, len(timestamps)):
        delta = (timestamps[i] - timestamps[i-1]).total_seconds()
        intervals.append(delta)

    if not intervals:
        return None

    avg_interval = statistics.mean(intervals)
    if avg_interval == 0:
        return None
        
    try:
        variance = statistics.variance(intervals)
        stdev = statistics.stdev(intervals)
    except statistics.StatisticsError:
        return None

    cv = stdev / avg_interval

    if cv < tolerance:
        return {
            "type": "Beaconing Detected",
            "severity": "Low", 
            "average_interval": avg_interval,
            "variance": variance,
            "events_count": len(timestamps)
        }

    return None
