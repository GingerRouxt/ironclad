"""Offline capability state; never claims a malware-free or zero-day-free machine."""
from . import malware, sensor, protection_updates, onaccess, rule_updates


def status(state):
    limits=[]
    try:last=malware.latest(state)
    except (OSError,ValueError,TypeError,KeyError):
        last=None;limits.append('The last scan report could not be safely read; no clearance is assumed.')
    monitor=sensor.status(state)
    scanner=malware.status(state)
    return {'schema':1,'scanner':scanner,'last_scan':last,'limits':limits,'rule_updates':rule_updates.status(),
            'automatic_malware':onaccess.status(state),'updates':protection_updates.status(state),'health':{'monitoring':monitor['state'],'file_scanning':'ready' if scanner['ready'] else 'unavailable'},
            'continuous_monitoring':monitor['monitoring'],'sensor':{'state':monitor['state'],'monitoring':monitor['monitoring']},'zero_day_assurance':False}
