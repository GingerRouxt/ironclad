"""Exact reviewed repairs. No shell, generated commands, or blanket failed-state reset."""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import time
from . import actions
from .model import now
from .storage import Store, export, private_dir

UNIT = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.@:-]{0,180}\.service')
PROTECTED = re.compile(r'^(systemd-|dbus|NetworkManager|network|sshd|ssh-agent|gpg-agent|polkit|omarchy|quickshell|hyprland|uwsm|user@|display-manager|xdg-desktop-portal)', re.I)
SERVICE_PROPERTIES = 'Id,LoadState,ActiveState,SubState,Result,Type,RefuseManualStart,InvocationID'


def query(command):
    from .maintenance import capture
    return capture(command, timeout=5)


def service(unit, user=False):
    if not UNIT.fullmatch(unit) and unit != 'avahi-daemon.socket':
        raise ValueError('invalid service')
    command = ['/usr/bin/systemctl'] + (['--user'] if user else [])
    body = query(command+['show', unit, '--property='+SERVICE_PROPERTIES, '--no-pager'])
    data = dict(line.split('=', 1) for line in body.splitlines() if '=' in line)
    if data.get('Id') != unit or data.get('LoadState') != 'loaded':
        raise ValueError('service unavailable')
    return data


def failed_services(user=False):
    body = query(['/usr/bin/systemctl']+(['--user'] if user else [])+['--failed', '--no-legend', '--no-pager', '--plain'])
    units = [line.split()[0] for line in body.splitlines() if line.split()]
    return [unit for unit in units[:32] if UNIT.fullmatch(unit)]


def wildcard_listeners():
    from .collectors import sockets
    check = sockets(query(['/usr/bin/ss', '-H', '-lntu']))
    return check.status == 'attention'


def discovery_listeners():
    from .collectors import sockets
    check=sockets(query(['/usr/bin/ss','-H','-lntu']))
    rows=json.loads(check.evidence[-1].value)
    return any(row['protocol']=='udp' and row['port']==5353 and row['bind_scope']=='wildcard' for row in rows)


def aslr_value():
    value = Path('/proc/sys/kernel/randomize_va_space').read_text().strip()
    if value not in ('0', '1', '2'):
        raise ValueError('ASLR state unavailable')
    return value


def ntp_value():
    value = query(['/usr/bin/timedatectl', 'show', '--property=NTP', '--value']).strip()
    if value not in ('yes', 'no'):
        raise ValueError('clock state unavailable')
    return value


def spec(action, target=''):
    if action == 'home.remove_world_write':
        plan = actions.preview(action)
        return {'check_id':'security.home.permissions', 'action_id':action, 'target':'current account home',
                'title':'Remove other-user write access to your home folder', 'before':[str(v) for v in (plan.uid,plan.device,plan.inode,plan.ctime_ns,plan.before)],
                'commands':[], 'privileged':False, 'impact':plan.public()['impact']+' '+plan.public()['risk'],
                'undo':'Restore the previous mode with the exact-target receipt, if shared access is needed.',
                'verification':'Check that the other-write bit was removed; then repeat the scan.',
                'implementation':f'fchmod the currently owned home directory from {plan.before:04o} to {plan.after:04o}; no shell command.'}
    if action in ('service.retry-user', 'service.retry-system'):
        user = action.endswith('user')
        if not UNIT.fullmatch(target) or PROTECTED.match(target) or target not in failed_services(user):
            raise ValueError('this failed service is not eligible for generic repair')
        before = service(target,user)
        if before.get('ActiveState') != 'failed' or before.get('RefuseManualStart') == 'yes':
            raise ValueError('service changed or refuses manual start')
        command = ['/usr/bin/systemctl']+(['--user'] if user else [])+['restart', target]
        return {'check_id':'startup.units.user_failed' if user else 'startup.units.system_failed', 'action_id':action, 'target':target,
                'title':'Retry '+target, 'before':before, 'commands':[command], 'privileged':not user,
                'impact':'Retry this failed service once. It may start its application, perform configured work or briefly interrupt that application. It does not edit configuration, disable services or clear failure records. A retry may fail again if the underlying cause remains.',
                'undo':'A service retry cannot be undone. This action does not change whether the service starts at login or boot. Review the application before stopping it manually.',
                'verification':'Require a new service invocation with success and an active service (or a completed successful one-shot), then rescan remaining failures.',
                'implementation':'Retry only the selected currently failed, non-core service.'}
    if action == 'network.stop-discovery':
        states = {u:service(u) for u in ('avahi-daemon.socket','avahi-daemon.service')}
        targets = [u for u,data in states.items() if data.get('ActiveState') == 'active']
        if not targets or not discovery_listeners():
            raise ValueError('local discovery repair is not applicable')
        return {'check_id':'network.listeners','action_id':action,'target':'Avahi local device discovery',
                'title':'Turn off local device discovery for this session', 'before':states,
                'commands':[['/usr/bin/systemctl','stop',*targets]], 'privileged':True,
                'impact':'Use this only if you do not need automatic discovery of local printers, shared devices or .local names. Stops the Avahi service and its activation socket for this session. It does not block arbitrary ports or change the firewall, and discovery may return after reboot. Other applications may still listen on the network.',
                'undo':'Restore discovery with: sudo /usr/bin/systemctl start '+' '.join(reversed(targets)),
                'verification':'Check that the selected discovery units stopped and rescan the actual wildcard listeners; do not claim resolution if listeners remain.',
                'implementation':'Only the named Avahi units; never a model-generated service or port command.'}
    if action == 'security.enable-aslr':
        before = aslr_value()
        if before == '2':raise ValueError('full ASLR is already enabled')
        return {'check_id':'security.kernel.aslr','action_id':action,'target':'kernel.randomize_va_space',
                'title':'Enable full memory address randomization until reboot','before':before,
                'commands':[['/usr/bin/sysctl','-w','kernel.randomize_va_space=2']], 'privileged':True,
                'impact':'Changes this running-kernel setting only. Can affect specialized debugging or compatibility work. No persistent Omarchy files are changed; boot settings may replace this on reboot.',
                'undo':'Restore this session setting with: sudo /usr/bin/sysctl -w kernel.randomize_va_space='+before,
                'verification':'Read the setting back as 2 and rescan. This does not certify other exploit protections.',
                'implementation':'One fixed runtime sysctl; no arbitrary key or value.'}
    if action == 'clock.enable-sync':
        before = ntp_value()
        if before != 'no':raise ValueError('time synchronization is already enabled; investigate connectivity instead')
        return {'check_id':'network.clock','action_id':action,'target':'network time synchronization',
                'title':'Enable automatic time synchronization','before':before,
                'commands':[['/usr/bin/timedatectl','set-ntp','true']], 'privileged':True,
                'impact':'Enables the system-supported network time service. Network connectivity is required, and the clock may adjust. Do not use this where a different clock source is intentionally managed.',
                'undo':'Restore the prior disabled setting with: sudo /usr/bin/timedatectl set-ntp false',
                'verification':'Confirm NTP is enabled and separately check whether the clock has synchronized. Enabling alone does not prove synchronization.',
                'implementation':'Only enable the normal network time service.'}
    raise ValueError('repair is not supported')


def digest(plan):
    return hashlib.sha256(json.dumps({k:v for k,v in plan.items() if k!='digest'},sort_keys=True).encode()).hexdigest()


def make_plan(action,target=''):
    plan = dict(spec(action,target),schema=1,created=int(time.time()),nonce=secrets.token_hex(16))
    plan['digest'] = digest(plan)
    return plan


def validate(plan,approval):
    if not isinstance(plan,dict) or approval != plan.get('digest') or not isinstance(approval,str) or not re.fullmatch('[0-9a-f]{64}',approval) or digest(plan)!=approval:
        raise ValueError('approve the exact reviewed repair')
    if plan.get('schema')!=1 or not isinstance(plan.get('created'),(int,float)) or not 0 <= time.time()-plan['created'] <= 180:
        raise ValueError('repair review expired; review again')
    current = spec(plan['action_id'],plan['target'])
    if current != {k:v for k,v in plan.items() if k not in ('schema','created','nonce','digest')}:
        raise ValueError('repair conditions changed; review again')
    return plan


def options(check_id):
    mapping = {'security.home.permissions':['home.remove_world_write'], 'network.listeners':['network.stop-discovery'],
               'security.kernel.aslr':['security.enable-aslr'], 'network.clock':['clock.enable-sync']}
    choices=[]
    blocked=[]
    if check_id in ('startup.units.user_failed','startup.units.system_failed'):
        user=check_id.endswith('user_failed')
        for unit in failed_services(user)[:16]:
            try:choices.append(make_plan('service.retry-user' if user else 'service.retry-system',unit))
            except (ValueError,OSError):blocked.append(unit)
    else:
        for action in mapping.get(check_id,[]):
            try:choices.append(make_plan(action))
            except (ValueError,OSError):pass
    manual = 'No supported automatic repair matches the current state. Use the AI plan and recorded steps; Ironclad will not pretend that a generic command fixes this finding.'
    if blocked:
        manual = 'These failed units need a specific diagnosis and are excluded from generic retries: '+', '.join(blocked)+'. Boot, security and session services are not restarted or disabled by this repair flow.'
    if check_id == 'security.boot.secure_boot':
        manual = 'Secure Boot requires a compatible signed boot setup and firmware configuration. Ironclad cannot safely enable it from a generic command. Review the AI plan, prepare recovery media and follow your device/Omarchy setup steps.'
    return {'check_id':check_id,'plans':choices,'manual':manual if not choices or blocked else '',
            'note':'Review the exact change, impact and undo instructions. Apply fix performs only the selected repair; administrator authentication may be requested in a visible terminal.'}


def directory(state):
    path=Path(state)/'repairs'
    fd=private_dir(path);os.close(fd)
    return path


def read(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd) as f:
        meta=os.fstat(f.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=os.getuid() or meta.st_nlink!=1 or meta.st_size>65536:
            raise ValueError('invalid repair receipt')
        return json.loads(f.read(65537))


def ticket_path(state,ticket,suffix):
    if not isinstance(ticket,str) or not re.fullmatch('[0-9a-f]{32}',ticket):raise ValueError('invalid repair ticket')
    return directory(state)/(ticket+suffix)


def queue(state,plan,approval):
    validate(plan,approval)
    # Bounded outstanding requests/receipts. Do not silently delete audit records.
    if len(list(directory(state).iterdir()))>=128:raise ValueError('repair receipt limit reached; review local repair history')
    ticket=secrets.token_hex(16)
    export(ticket_path(state,ticket,'.request.json'),json.dumps({'plan':plan,'approval':approval}))
    return {'ticket':ticket,'digest':approval}


def authenticate(timeout=120):
    from .maintenance import trusted,environment
    p=subprocess.Popen([trusted('/usr/bin/sudo'),'-v'],env=environment(),cwd='/',start_new_session=False)
    try:
        return p.wait(timeout=timeout)
    finally:
        if p.poll() is None:
            p.terminate()
            try:p.wait(timeout=5)
            except subprocess.TimeoutExpired:p.kill();p.wait()


def run_command(command,privileged,timeout=120):
    from .maintenance import trusted,environment
    args=[trusted(command[0]),*command[1:]]
    if privileged:args=[trusted('/usr/bin/sudo'),'-n',*args]
    # Inherit the visible terminal for password entry. No password enters Python or a log.
    p=subprocess.Popen(args,env=environment(),cwd='/',start_new_session=False)
    try:
        return p.wait(timeout=timeout)
    finally:
        if p.poll() is None:
            p.terminate()
            try:p.wait(timeout=5)
            except subprocess.TimeoutExpired:p.kill();p.wait()


def verify(plan):
    action=plan['action_id']
    if action=='home.remove_world_write':
        fd=actions.open_dir(actions.account_home())
        try:return not bool(actions.identity(fd)[-1]&2),'Home-folder write access checked.'
        finally:os.close(fd)
    if action.startswith('service.retry-'):
        after=service(plan['target'],action.endswith('user'))
        invocation=after.get('InvocationID')
        healthy=after.get('ActiveState')=='active' or (after.get('Type')=='oneshot' and after.get('ActiveState')=='inactive')
        good=bool(invocation) and invocation!=plan['before'].get('InvocationID') and healthy and after.get('Result')=='success'
        return good,'Selected service retry '+('verified. Other failures may remain.' if good else 'did not recover; diagnose its error before retrying.')
    if action=='network.stop-discovery':
        stopped=all(service(unit).get('ActiveState')=='inactive' for unit in plan['before'] if plan['before'][unit].get('ActiveState')=='active')
        clear=not wildcard_listeners()
        return stopped and clear,'Discovery '+('stopped and no wildcard listeners remain.' if stopped and clear else 'change did not resolve the finding; other listeners or service activity remain.')
    if action=='security.enable-aslr':
        good=aslr_value()=='2'
        return good, 'Full address randomization read back from the running kernel.' if good else 'The running kernel did not report full address randomization. Check the setting before retrying.'
    if action=='clock.enable-sync':
        enabled=ntp_value()=='yes'
        synced=query(['/usr/bin/timedatectl','show','--property=NTPSynchronized','--value']).strip()=='yes'
        return enabled and synced,'Time synchronization '+('verified.' if enabled and synced else 'not yet verified; allow time for synchronization and rescan.')
    raise ValueError('unknown verification')


def run_ticket(state,ticket,approval):
    request=ticket_path(state,ticket,'.request.json')
    # The exclusive claim prevents replay, including concurrent launches.
    claim=ticket_path(state,ticket,'.claimed')
    fd=os.open(claim,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.close(fd)
    result={'ticket':ticket,'verified':False,'applied':False,'finished_at':now(),'message':'Repair was interrupted or did not complete. A change may have partially applied; rescan before retrying. No success is assumed.'}
    try:
        payload=read(request)
        if payload['approval']!=approval:raise ValueError('repair approval changed')
        plan=validate(payload['plan'],approval)
        result.update(action_id=plan['action_id'],check_id=plan['check_id'],undo=plan['undo'])
        if plan['privileged']:
            code=authenticate()
            if code!=0:
                result.update(exit_code=code,message='Administrator authentication was cancelled or denied. No repair command was run.')
                return result
            # Password entry may take time: recheck age and state after authentication.
            validate(plan,approval)

        print(plan['title']+'\n\n'+plan['impact']+'\n\nUndo: '+plan['undo'],flush=True)
        if plan['action_id']=='home.remove_world_write':
            inner=actions.preview(actions.ACTION_ID)
            if [str(v) for v in (inner.uid,inner.device,inner.inode,inner.ctime_ns,inner.before)]!=plan['before']:raise ValueError('home folder changed')
            store=Store(state)
            try:result['undo_receipt']=actions.apply(store,inner,inner.digest())
            finally:store.close()
        else:
            for command in plan['commands']:
                print('\nCommand: '+('sudo ' if plan['privileged'] else '')+' '.join(command),flush=True)
                code=run_command(command,plan['privileged'])
                if code!=0:
                    result.update(exit_code=code,message='Repair command failed or authentication was cancelled. Check the terminal output; no success is assumed.')
                    return result
        result['applied']=True
        result['verified'],result['message']=verify(plan)
        return result
    except (OSError,ValueError,KeyError,TypeError,subprocess.TimeoutExpired):
        result['message']='Repair was refused, timed out or could not be verified. Its conditions may have changed; review it again.'
        return result
    finally:
        result['finished_at']=now()
        export(ticket_path(state,ticket,'.result.json'),json.dumps(result))


def result(state,ticket):
    path=ticket_path(state,ticket,'.result.json')
    if not path.exists():return {'ticket':ticket,'verified':False,'applied':False,'message':'Repair was interrupted or the terminal closed before a result was recorded. Rescan; do not assume it worked.'}
    return read(path)
