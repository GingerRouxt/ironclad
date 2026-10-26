#!/usr/bin/env python3
"""Production protection UI + scan adapter; harmless files and fixture engine only."""
import json
import os
from pathlib import Path
import sys
import shutil
import tempfile

os.environ['QT_QPA_PLATFORM']='offscreen'
os.environ['QT_QUICK_BACKEND']='software'
from PySide6.QtCore import Q_ARG, QMetaObject, QObject, QPointF, Qt, QUrl
from PySide6.QtGui import QGuiApplication
from PySide6.QtQuick import QQuickView
from PySide6.QtQuickControls2 import QQuickStyle
from PySide6.QtTest import QTest
from preview_ui import stubs
from verify_update_ui import Runtime, wait, click, find_item

ROOT=Path(__file__).resolve().parents[1]


def run_tests():
    QQuickStyle.setStyle('Fusion');app=QGuiApplication([]);passed=[]
    with tempfile.TemporaryDirectory(prefix='ironclad-protection-ui-') as temporary:
        base=Path(temporary);stubs(base,'dark')
        (base/'Quickshell/Io/Process.qml').write_text('''import QtQuick
QtObject {
 id: process
 property var command: []
 property bool running: false
 property var stdout: null
 property bool stdinEnabled: false
 signal started()
 signal exited(int exitCode, int exitStatus)
 function write(data) { fixtureRuntime.write(process,data) }
 onRunningChanged: { if (running) fixtureRuntime.start(process,command); else fixtureRuntime.stop(process) }
}''')
        plugin=base/'plugin';plugin.mkdir();shutil.copytree(ROOT/'ui0236',plugin/'ui0236');shutil.copy(ROOT/'Panel.qml',plugin/'Panel.qml')
        mode=base/'mode';mode.write_text('missing')
        target=base/'download.bin';target.write_bytes(b'harmless fixture')
        sys.path.insert(0,str(ROOT))
        from ironclad import sensor_policy, sensor_service, sensor
        monitor_file=base/'monitor.json';sensor_mode=base/'sensor-mode';sensor_mode.write_text('ok')
        monitor={'schema':1,'installed':False,'compatible':True,'state':'not_installed','monitoring':False,'message':'Not enabled.','engine':'Falco fixture','policy_version':'0.2.18','rules_count':5,'alerts':[],'unreviewed':0,'metrics':None,'owner_match':True,'limits':[]}
        monitor_file.write_text(json.dumps(monitor))
        event=sensor_service.sanitize_event({'rule':'ZDS Runtime preload changed','time':'2026-10-22T12:00:00Z','output_fields':{'proc.name':'demo','evt.type':'openat','proc.cmdline':'DO NOT SHARE'}},sensor_policy.RULES,'a'*16+':1')
        alert=sensor.parse_feed({'schema':1,'events':[event]})[0];alert['reviewed']=False
        marker=base/'engine-ran'
        scanner=base/'clamscan'
        scanner.write_text(f'''#!/usr/bin/python3
from pathlib import Path
import sys,time
Path({str(marker)!r}).write_text('ran')
mode=Path({str(mode)!r}).read_text()
body=sys.stdin.buffer.read()
if mode=='slow':time.sleep(10)
if mode=='detected':print('stdin: Synthetic.Test.Signature FOUND');raise SystemExit(1)
if mode=='encrypted':print('stdin: Heuristics.Encrypted.Zip FOUND');raise SystemExit(1)
if mode=='error':print('stdin: fixture failure ERROR');raise SystemExit(2)
print('stdin: OK')
''');scanner.chmod(0o700)
        helper=base/'fixture.py'
        helper.write_text(f'''from pathlib import Path
import time
MODE=Path({str(mode)!r})
DB={{'path':{str(base/'db')!r},'identity':[['daily','1','2','3','4']],'modified':1.0}}
def readiness(state):
 missing=MODE.read_text()=='missing'
 return {{'installed':not missing,'ready':not missing and MODE.read_text()!='sandbox-missing','sandbox_available':MODE.read_text()!='sandbox-missing','signatures_at':'2026-10-22T00:00:00+00:00','signatures_age_hours':1.0,'message':'Install scanner.' if missing else 'Ready for selected-file scan.','coverage':'One selected file only; fixture engine.'}}
''')
        helper.write_text(helper.read_text()+'''\nimport json
MONITOR=Path('''+repr(str(monitor_file))+''')
SENSOR_MODE=Path('''+repr(str(sensor_mode))+''')
def monitor_status(state):return json.loads(MONITOR.read_text())
def change_sensor(command,timeout=180):
 if SENSOR_MODE.read_text()=='cancel':return 126
 value=monitor_status(None)
 if command[0].endswith('sensor-helper'):
  enabled=command[-1]=='enable'
  value.update(installed=True,state='monitoring' if enabled else 'stopped',monitoring=enabled,message='Fresh fixture kernel metrics received.' if enabled else 'Stopped.',metrics=dict(events='100',kernel_drops='0',output_drops='0',async_reader='1',async_events='3',async_errors='0',async_emitted='3',async_pending='0') if enabled else None)
 if '-R' in command:value.update(installed=False,state='not_installed',monitoring=False,message='Removed.')
 MONITOR.write_text(json.dumps(value));return 0
def acknowledge(state,identifier):
 value=monitor_status(state)
 for row in value['alerts']:
  if row['id']==identifier:row['reviewed']=True
 value['unreviewed']=sum(not row['reviewed'] for row in value['alerts']);MONITOR.write_text(json.dumps(value));return value
''')
        automatic=base/'automatic_fixture.py'
        automatic.write_text("""from pathlib import Path
import hashlib,json,time
MODE=Path(__MODE__)
def status(state):
 mode=MODE.read_text() if MODE.exists() else 'off'
 active=mode in ('notify','prevent')
 return dict(schema=1,installed=mode!='off',state='scanning' if mode=='notify' else 'protecting' if mode=='prevent' else 'stopped',active=active,mode=mode if active else None,scope='Downloads',message='Synthetic automatic scanner status.',coverage='Synthetic Downloads only; no host service.',events=[],scanned=2 if active else 0,errors=0,signatures_age_hours=1.0,automatic_signatures=active)
def plan(state,action):
 return dict(schema=1,action=action,scope='Downloads',digest='a'*64,title='Synthetic exact automatic scan review',impact='No actual OS change; fixture only.')
def apply(state,review,approval):
 assert approval==review['digest']
 if MODE.exists() and MODE.read_text()=='fail':raise ValueError('fixture authentication cancelled')
 MODE.write_text('off' if review['action']=='disable' else review['action'])
 return dict(verified=True,status=status(state),message='Synthetic change verified.')
""".replace('__MODE__',repr(str(base/'automatic-mode'))))
        companion=plugin/'companion.py'
        companion.write_text(f'''import sys,signal
def stop(signum,frame):raise SystemExit(130)
signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGHUP,stop)
from pathlib import Path
sys.path.insert(0,{str(ROOT)!r});sys.path.insert(0,{str(base)!r})
from ironclad import malware,maintenance,sensor,sensor_package,protection_updates,onaccess,rule_updates
import fixture,json
import automatic_fixture
onaccess.status=automatic_fixture.status
onaccess.plan=automatic_fixture.plan
onaccess.apply=automatic_fixture.apply
UPDATE_FLAG=Path({str(base/'auto-updates')!r})
def fixture_configure(enabled):UPDATE_FLAG.write_text('on' if enabled else 'off')
def fixture_updates(state):return {{'automatic':UPDATE_FLAG.exists() and UPDATE_FLAG.read_text()=='on','issues':['Synthetic update warning'],'last_success':None,'engines':[],'policy_version':'fixture','plugin_update':'Fixture release channel.'}}
protection_updates.configure=fixture_configure
protection_updates.status=fixture_updates
protection_updates.maintain=lambda state,allow_network:dict(outcome='ok')
RULE_FLAG=Path({str(base/'rule-updates')!r})
def fixture_rules_configure(enabled,allow_network=False):
    if enabled and not allow_network:raise ValueError('missing rule consent')
    RULE_FLAG.write_text('on' if enabled else 'off')
rule_updates.configure=fixture_rules_configure
rule_updates.status=lambda:dict(installed=True,available=True,enabled=RULE_FLAG.exists() and RULE_FLAG.read_text()=='on',state='not_checked',rules=0,message='Synthetic rule health')
sensor.status=fixture.monitor_status
sensor.run_privileged=fixture.change_sensor
sensor.acknowledge=fixture.acknowledge
sensor_package.build=lambda state,allow_network=False:dict(path='/fixture/package',sha256='b'*64 if fixture.SENSOR_MODE.read_text()=='changed' else 'a'*64)
if sys.argv[1]=='agent-status':print(json.dumps({{'available':True,'agent':'Fixture agent'}}));raise SystemExit(0)
if sys.argv[1]=='brief':sys.stdin.readline();print(json.dumps({{'brief':'Question: Synthetic software priority brief'}}));raise SystemExit(0)
if sys.argv[1]=='ask':sys.stdin.readline();print(json.dumps({{'answer':'Synthetic priority advice; no changes applied.','provider':'Fixture agent'}}));raise SystemExit(0)
malware.Path.home=lambda:Path({str(base)!r})
# GUI fixtures expose host-side marker files to observe process cancellation.
# Sandbox enforcement is tested separately with real bwrap and native EICAR.
malware.sandbox_command=lambda command,db:command
malware.database=lambda state:fixture.DB
malware.status=fixture.readiness
def fixture_install(state):raise ValueError('fixture OS authentication cancelled')
malware.install_scanner=fixture_install
malware.update_signatures=lambda state,allow_network:fixture.readiness(state) if allow_network else (_ for _ in ()).throw(ValueError('network approval required'))
maintenance.refresh=lambda state:fixture.INVENTORY
maintenance.patch_plan=lambda state,target:dict(schema=2,operation='user-application-update',digest='a'*64,name='demo',source='mise',target='mise:demo',installed='1.0',available='1.1',scope='Synthetic tool only',impact='Fixture review; no installation',recovery='Fixture recovery',command=['/usr/bin/mise','--yes','upgrade','--global','demo@1.1'])
maintenance.trusted=lambda path:{str(scanner)!r} if path=='/usr/bin/clamscan' else path
raise SystemExit(maintenance.main(['--state',{str(base/'state')!r},*sys.argv[1:]]))
''')
        engine=plugin/'engine.py'
        inventory={'schema':2,'items':[{'name':'demo','installed':'1.0','available':'1.1','source':'mise','active':True,'status':'security review','advisory_coverage':'supported','advisories':[{'id':'GHSA-demo-1234','severity':'high','issues':['CVE-2026-12345'],'known_exploited':True,'summary':'Synthetic advisory for button-flow testing.'}]}],'fresh':True,'observed_at':'2026-10-22T00:00:00Z','checked_at':'2026-10-22T00:00:00Z','advisory_status':'available','kev_status':'available','limits':[]}
        helper.write_text(helper.read_text()+'\nINVENTORY='+repr(inventory)+'\n')
        engine.write_text('import json\nprint(json.dumps('+repr(inventory)+'))\n')
        runtime=Runtime({str(companion),str(engine)})
        view=QQuickView();runtime.view=view;view.engine().addImportPath(str(base));view.rootContext().setContextProperty('fixtureRuntime',runtime)
        view.setResizeMode(QQuickView.SizeRootObjectToView);view.resize(1020,700);view.setSource(QUrl.fromLocalFile(str(plugin/'Panel.qml')))
        assert view.status()!=QQuickView.Error
        root=view.rootObject();QMetaObject.invokeMethod(root,'open');view.show()
        QMetaObject.invokeMethod(root,'navigate',Qt.DirectConnection,Q_ARG('QVariant','Protection'))
        wait(app,lambda:not root.property('busy') and root.property('protectionData') is not None,'protection readiness')
        def press(name):
            QTest.qWait(100)  # Let newly populated alert/help rows finish layout before scrolling.
            item=find_item(view,name);assert item is not None,name
            page=find_item(view,'protectionView');flick=page.property('contentItem')
            top=page.mapToScene(QPointF(0,0)).y();point=item.mapToScene(QPointF(item.width()/2,item.height()/2))
            y=point.y()-top
            if y<20 or y>page.height()-25:
                desired=float(flick.property('contentY'))+y-page.height()/2
                maximum=max(0,float(flick.property('contentHeight'))-flick.height())
                flick.setProperty('contentY',max(0,min(desired,maximum)));QTest.qWait(75)
            click(view,root,name)
        wait(app,lambda:root.property('monitorData') is not None,'embedded monitor status')
        press('enableMonitorButton')
        wait(app,lambda:root.property('monitorStage')=='review' and not root.property('busy'),'monitor exact review')
        # Tab into an approval below the viewport without the mouse helper scrolling it.
        page=find_item(view,'protectionView');flick=page.property('contentItem')
        flick.setProperty('contentY',0)
        previous=find_item(view,'falcoHelpButton');previous.forceActiveFocus(Qt.TabFocusReason)
        QTest.qWait(100);QTest.keyClick(view,Qt.Key_Tab)
        approve=find_item(view,'approveMonitorButton')
        wait(app,lambda:approve.hasActiveFocus(),'keyboard approval focus')
        QTest.qWait(100)
        point=approve.mapToItem(page,QPointF(0,0))
        assert point.y()>=0 and point.y()+approve.height()<=page.height(), (point.y(),approve.height(),page.height())
        assert root.property('monitorStage')=='review' and not json.loads(monitor_file.read_text())['monitoring']
        passed.append('keyboard-tab-reveals-monitor-approval-without-applying')
        press('dismissMonitorButton');assert not json.loads(monitor_file.read_text())['monitoring']
        passed.append('embedded-monitor-review-decline-no-service-change')
        for scenario in ('cancel','changed','ok'):
            sensor_mode.write_text('ok');press('enableMonitorButton')
            wait(app,lambda:root.property('monitorStage')=='review' and not root.property('busy'),'monitor review '+scenario)
            sensor_mode.write_text(scenario);press('approveMonitorButton')
            wait(app,lambda:root.property('monitorStage') in ('done','error') and not root.property('busy'),'monitor apply '+scenario)
            assert root.property('monitorStage')==('done' if scenario=='ok' else 'error')
            assert not root.property('opened'),'monitor approval must release panel focus'
            QMetaObject.invokeMethod(root,'open')
            press('dismissMonitorButton');passed.append('embedded-monitor-'+scenario)
        value=json.loads(monitor_file.read_text());value['alerts']=[alert];value['unreviewed']=1;monitor_file.write_text(json.dumps(value))
        QMetaObject.invokeMethod(root,'loadMonitor');wait(app,lambda:root.property('monitorData').toVariant()['unreviewed']==1,'new alert')
        press('reviewMonitor_'+alert['id']);wait(app,lambda:not root.property('busy') and root.property('monitorData').toVariant()['unreviewed']==0,'review alert')
        assert json.loads(monitor_file.read_text())['alerts'][0]['reviewed']
        passed.append('embedded-alert-plain-remediation-and-mark-reviewed')
        for action,button in [('disable','stopMonitorButton'),('remove','removeMonitorButton')]:
            press(button);wait(app,lambda:root.property('monitorStage')=='review' and not root.property('busy'),'review '+action)
            press('approveMonitorButton');wait(app,lambda:root.property('monitorStage')=='done' and not root.property('busy'),'apply '+action)
            assert not root.property('opened')
            QMetaObject.invokeMethod(root,'open')
            press('dismissMonitorButton');passed.append('embedded-monitor-'+action)
        press('protectionTab_3')
        press('checkProtectionButton')
        wait(app,lambda:not root.property('busy'),'protection metadata refresh')
        assert any('refresh' in command and '--allow-network' in command for command in runtime.started_commands)
        assert root.property('softwareData').toVariant()['items'][0]['advisories'][0]['known_exploited']
        passed.append('software-risk-button-refreshes-through-explicit-network-fixture')
        press('riskUpdate_demo')
        wait(app,lambda:root.property('updateStage')=='review' and not root.property('busy'),'risk update review')
        assert root.property('selected')=='Software' and not marker.exists()
        click(view,root,'cancelUpdateButton')
        assert root.property('updateStage')=='idle' and not marker.exists()
        QMetaObject.invokeMethod(root,'navigate',Qt.DirectConnection,Q_ARG('QVariant','Protection'))
        wait(app,lambda:not root.property('busy'),'return to protection')
        passed.append('risk-update-opens-existing-exact-review-and-declines-without-install')
        press('protectionAdviceButton')
        wait(app,lambda:not root.property('aiBusy') and 'Synthetic priority advice' in root.property('aiAnswer'),'protection signed-in-agent handoff')
        assert root.property('selected')=='AI'
        assert 'software advisories' in root.property('aiQuestion')
        assert not marker.exists()
        QMetaObject.invokeMethod(root,'navigate',Qt.DirectConnection,Q_ARG('QVariant','Protection'))
        wait(app,lambda:not root.property('busy'),'return after AI advice')
        passed.append('protection-ai-button-prepares-and-asks-without-action-authority')
        press('protectionTab_1')
        press('setupScannerButton')
        assert root.property('malwareStage')=='install-review' and not marker.exists()
        click(view,root,'closeMalwareButton');assert not getattr(runtime,'scanner_handoffs',[])
        passed.append('scanner-setup-review-decline-no-install')
        press('setupScannerButton');click(view,root,'approveScannerSetupButton')
        wait(app,lambda:not root.property('busy'),'installer handoff cancellation')
        assert not root.property('opened'),'scanner install must release focus'
        QMetaObject.invokeMethod(root,'open')
        assert any(command[-2:]==['scanner-install','--json'] for command in runtime.started_commands)
        assert root.property('malwareStage')=='error'
        click(view,root,'closeMalwareButton')
        assert not root.property('protectionData').toVariant()['scanner']['ready']
        passed.append('embedded-installer-auth-cancellation-no-host-install')
        mode.write_text('sandbox-missing');QMetaObject.invokeMethod(root,'loadProtection');wait(app,lambda:not root.property('busy'),'missing sandbox fixture')
        assert find_item(view,'setupScannerButton').property('visible')
        assert not find_item(view,'chooseMalwareFileButton').property('enabled')
        assert find_item(view,'scannerReadiness').property('text')=='SETUP NEEDED'
        passed.append('missing-sandbox-offers-setup-and-refuses-file-selection')
        mode.write_text('clean');QMetaObject.invokeMethod(root,'loadProtection');wait(app,lambda:not root.property('busy'),'ready scanner fixture')
        # Exercise the real Choose file button and dialog signals. Fixture shell
        # visibility represents release of the native overlay/grab; live acceptance
        # separately verifies the OS picker is usable on this desktop.
        dialog=root.findChild(QObject,'malwareFileDialog')
        assert dialog is not None
        press('chooseMalwareFileButton')
        wait(app,lambda:not root.property('opened') and dialog.property('visible'),'file chooser releases panel')
        QMetaObject.invokeMethod(dialog,'reject')
        wait(app,lambda:root.property('opened') and not root.property('pendingNativeDialog'),'file chooser cancellation restores panel')
        assert root.property('malwareStage')=='idle' and not marker.exists()
        passed.append('native-file-dialog-cancel-releases-and-restores-panel')
        press('chooseMalwareFileButton')
        wait(app,lambda:not root.property('opened') and dialog.property('visible'),'file chooser opens after release')
        assert dialog.setProperty('selectedFile',QUrl.fromLocalFile(str(target)))
        # Inject the acceptance signal with a known fixture selection; native
        # picker interaction is verified separately in the installed desktop.
        QMetaObject.invokeMethod(dialog,'accepted')
        dialog.setProperty('visible',False)
        wait(app,lambda:root.property('opened') and root.property('malwareStage') in ('review','error') and not root.property('busy'),'selected file returns to exact review')
        assert root.property('malwareStage')=='review',(root.property('malwareMessage'),dialog.property('selectedFile'))
        assert not marker.exists(),'File selection must not scan before approval'
        click(view,root,'closeMalwareButton')
        passed.append('native-file-dialog-selection-restores-exact-review-without-scanning')
        export_dialog=root.findChild(QObject,'exportDialog')
        assert export_dialog is not None
        started=len(runtime.started_commands)
        QMetaObject.invokeMethod(root,'chooseReport')
        wait(app,lambda:not root.property('opened') and export_dialog.property('visible'),'export dialog releases panel')
        QMetaObject.invokeMethod(export_dialog,'reject')
        wait(app,lambda:root.property('opened') and not root.property('pendingNativeDialog'),'export cancellation restores panel')
        assert not any('report' in command for command in runtime.started_commands[started:])
        passed.append('native-report-dialog-cancel-releases-restores-without-export')
        press('updateSignaturesButton');assert root.property('malwareStage')=='signatures-review'
        click(view,root,'approveScannerSetupButton');wait(app,lambda:root.property('opened') and not root.property('busy'),'signature handoff')
        assert any(command[-3:]==['scanner-signatures','--json','--allow-network'] for command in runtime.started_commands)
        assert root.property('malwareStage')=='setup-done'
        assert not getattr(runtime,'scanner_handoffs',[])
        click(view,root,'closeMalwareButton')
        passed.append('embedded-signature-update-explicit-network-no-terminal')
        press('protectionTab_2')
        for enabled in (True,False):
            press('automaticUpdatesButton')
            wait(app,lambda:root.property('malwareStage')=='setup-done' and not root.property('busy'),'automatic update toggle')
            click(view,root,'closeMalwareButton')
            wait(app,lambda:root.property('protectionData').toVariant()['updates']['automatic']==enabled,'automatic update health')
            assert (base/'auto-updates').read_text()==('on' if enabled else 'off')
        passed.append('automatic-update-enable-disable-with-health-refresh')
        assert not (base/'rule-updates').exists(), 'signature consent enabled rule updates'
        assert not any('falco-rules-enable' in command for command in runtime.started_commands)
        for enabled in (True,False):
            press('falcoRuleUpdatesButton')
            wait(app,lambda:root.property('malwareStage')=='setup-done' and not root.property('busy'),'rule update toggle')
            assert find_item(view,'malwareHeading').property('text')=='Falco rule updates'
            wait(app,lambda:root.property('opened'),'rule authentication restores panel')
            click(view,root,'closeMalwareButton')
            wait(app,lambda:root.property('protectionData').toVariant()['rule_updates']['enabled']==enabled,'rule update health')
            assert (base/'rule-updates').read_text()==('on' if enabled else 'off')
        assert any('falco-rules-enable' in command and '--allow-network' in command for command in runtime.started_commands)
        passed.append('falco-rules-off-by-default-separate-explicit-consent-and-disable')
        press('maintainProtectionButton')
        wait(app,lambda:root.property('malwareStage')=='setup-done' and not root.property('busy'),'maintenance now')
        assert find_item(view,'malwareHeading').property('text')=='Scanner setup'
        click(view,root,'closeMalwareButton')
        assert any('protection-maintain' in command and '--allow-network' in command for command in runtime.started_commands)
        passed.append('protection-maintenance-now-explicit-network-no-engine-install')

        press('protectionTab_1')
        for scenario in ('decline','clean','detected','encrypted','error','changed','cancel'):
            QTest.qWait(100)
            wait(app,lambda:not root.property('busy'),'settle scan/status callbacks')
            mode.write_text('slow' if scenario=='cancel' else scenario)
            marker.unlink(missing_ok=True);target.write_bytes(b'harmless selected fixture')
            QMetaObject.invokeMethod(root,'reviewMalwareFile',Qt.DirectConnection,Q_ARG('QVariant',str(target)))
            wait(app,lambda:root.property('malwareStage') in ('review','error') and not root.property('busy'),'exact file review '+scenario)
            assert root.property('malwareStage')=='review',(scenario,root.property('malwareMessage'),[bytes(p.readAllStandardError()).decode() for p in runtime.children.values()])
            assert not marker.exists(),'Scanner started before explicit approval'
            if scenario=='decline':
                click(view,root,'closeMalwareButton');assert not marker.exists()
            else:
                if scenario=='changed':target.write_bytes(b'changed after review')
                click(view,root,'approveMalwareButton')
                if scenario=='cancel':
                    wait(app,marker.exists,'fixture scanner starts');click(view,root,'cancelMalwareButton')
                    wait(app,lambda:not root.property('busy'),'cancel file scan')
                    assert root.property('malwareStage')=='cancelled'
                else:
                    wait(app,lambda:root.property('malwareStage') in ('done','error') and not root.property('busy'),'scan result')
                    if scenario=='changed':assert not marker.exists() and root.property('malwareStage')=='error'
                    else:
                        assert root.property('malwareStage')=='done',(scenario,root.property('malwareMessage'))
                        result=root.property('malwareResult').toVariant()
                        assert result['outcome']=={'clean':'no_detection','detected':'detected','encrypted':'incomplete','error':'incomplete'}[scenario],result
                        assert target.exists(),'Scan removed selected file'
                click(view,root,'closeMalwareButton')
            passed.append('selected-file-'+scenario)
        # Actual new controls, real fixture child processes; no host/root mutation.
        press('protectionTab_5')
        press('automaticMalwareNotifyButton')
        wait(app,lambda:root.property('automaticStage')=='review' and not root.property('busy'),'automatic review')
        assert not (base/'automatic-mode').exists()
        press('dismissAutomaticMalwareButton')
        assert root.property('automaticStage')=='idle' and not (base/'automatic-mode').exists()
        passed.append('automatic-malware-decline-no-service-change')
        for action,button in [('notify','automaticMalwareNotifyButton'),('prevent','automaticMalwarePreventButton'),('disable','automaticMalwareStopButton')]:
            press(button)
            wait(app,lambda:root.property('automaticStage')=='review' and not root.property('busy'),'automatic exact review '+action)
            press('approveAutomaticMalwareButton')
            wait(app,lambda:root.property('automaticStage') in ('done','error') and not root.property('busy'),'automatic apply '+action)
            assert root.property('automaticStage')=='done',root.property('automaticMessage')
            assert not root.property('opened'),'automatic OS authentication must release overlay focus'
            QMetaObject.invokeMethod(root,'open')
            value=root.property('protectionData').toVariant()['automatic_malware']
            assert value['active']==(action!='disable')
            if action!='disable':assert value['mode']==action
            passed.append('automatic-malware-'+action+'-verified-fixture')
        (base/'automatic-mode').write_text('fail')
        press('automaticMalwareNotifyButton')
        wait(app,lambda:root.property('automaticStage')=='review' and not root.property('busy'),'automatic failed auth review')
        press('approveAutomaticMalwareButton')
        wait(app,lambda:root.property('automaticStage')=='error' and not root.property('busy'),'automatic failed authentication')
        QMetaObject.invokeMethod(root,'open')
        assert not root.property('protectionData').toVariant()['automatic_malware']['active']
        press('dismissAutomaticMalwareButton')
        passed.append('automatic-malware-auth-failure-no-active-claim')
        mode.write_text('clean');QMetaObject.invokeMethod(root,'loadProtection');wait(app,lambda:not root.property('busy'),'latest report')
        page=find_item(view,'protectionView');page.property('contentItem').setProperty('contentY',0);QTest.qWait(75)
        view.grabWindow().save(str(ROOT/'.local-evidence/protection-fixture-0218.png'))
        assert not runtime.errors,runtime.errors
        print(json.dumps({'passed':passed,'real_child_processes':len(runtime.started_commands),'actual_host_files_scanned':False,'actual_engine_installed':False,'fixture_scans_only':True}))
        view.setSource(QUrl());app.processEvents()
    return 0


def main():
    try:
        return run_tests()
    finally:
        for runtime in Runtime.instances:
            runtime.shutdown()
        Runtime.instances.clear()


if __name__=='__main__':raise SystemExit(main())
