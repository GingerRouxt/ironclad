#!/usr/bin/env python3
"""Click production QML controls through real child processes; mutate only temp fixtures."""
import json
import os
import resource
from pathlib import Path
import shutil
import sys
import tempfile
import time

os.environ['QT_QPA_PLATFORM'] = 'offscreen'
os.environ['QT_QUICK_BACKEND'] = 'software'
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
from PySide6.QtCore import QObject, QTimer, Slot, QProcess, QMetaObject, Q_ARG, Q_RETURN_ARG, Qt, QUrl, QPoint, QPointF
from PySide6.QtGui import QGuiApplication
from PySide6.QtQuick import QQuickView
from PySide6.QtQuickControls2 import QQuickStyle
from PySide6.QtTest import QTest
from shiboken6 import isValid
from preview_ui import stubs, fixture

ROOT = Path(__file__).resolve().parents[1]


class Runtime(QObject):
    instances = []

    def __init__(self, allowed):
        super().__init__()
        self.allowed = allowed
        self.children = {}
        self.all_children = []
        self.started_commands = []
        self.errors = []
        self.app = QGuiApplication.instance()
        self.view = None
        self.instances.append(self)

    def shutdown(self):
        for child in self.all_children:
            if not isValid(child):
                continue
            child.finished.disconnect()
            child.readyReadStandardOutput.disconnect()
            if child.state() != QProcess.NotRunning:
                child.terminate()
                if not child.waitForFinished(2000):
                    child.kill()
                    child.waitForFinished(2000)
        if self.view is not None and isValid(self.view):
            self.view.setSource(QUrl())
            self.app.processEvents()
        self.children.clear()
        self.all_children.clear()
        self.view = None

    @Slot(QObject, 'QVariant')
    def start(self, owner, command):
        args = command.toVariant() if hasattr(command, 'toVariant') else list(command)
        if 'monitor-apply' in args or 'scanner-install' in args or 'automatic-malware-apply' in args:
            if self.view.rootObject().property('opened'):
                self.errors.append('authentication started before panel released focus')
        if args and args[0] == '/usr/bin/foot':
            if args[1:3] == ['--app-id=com.zerodaysecurity.ironclad.scanner', '--title=Ironclad · Scanner setup']:
                assert args[3:6] == ['/usr/bin/python3','-I','-B'] and args[6] in self.allowed
                assert args[7:] in (['scanner-install','--hold'],['scanner-signatures','--allow-network','--hold'])
                self.scanner_handoffs = getattr(self,'scanner_handoffs',[]) + [args]
                def scanner_closed():
                    owner.setProperty('running',False)
                    QMetaObject.invokeMethod(owner,'exited',Qt.DirectConnection,Q_ARG(int,1),Q_ARG(int,0))
                QTimer.singleShot(0,scanner_closed)
                return
            if args[1:3] == ['--app-id=com.zerodaysecurity.ironclad.fix', '--title=Ironclad · Apply reviewed fix']:
                self.repair_handoff=args
                self.start(owner,args[3:])
                return
            if args == ['/usr/bin/foot', '--app-id=com.zerodaysecurity.ironclad.inspect', '--title=Ironclad · Inspect finding', '--hold', '/usr/bin/ss', '--listening', '--numeric', '--tcp', '--udp']:
                self.inspection_handoff = args
                def inspected():
                    owner.setProperty('running', False)
                    QMetaObject.invokeMethod(owner, 'exited', Qt.DirectConnection, Q_ARG(int, 0), Q_ARG(int, 0))
                QTimer.singleShot(0, inspected)
                return
            expected = ['/usr/bin/foot', '--app-id=com.zerodaysecurity.ironclad.omarchy-update', '--title=Omarchy · Build and system update', '/usr/bin/omarchy', 'update']
            assert args == expected, args
            self.omarchy_handoff = args
            def cancelled():
                owner.setProperty('running', False)
                QMetaObject.invokeMethod(owner, 'exited', Qt.DirectConnection, Q_ARG(int, 1), Q_ARG(int, 0))
            QTimer.singleShot(0, cancelled)
            return
        if len(args) < 4 or args[:3] != ['/usr/bin/python3', '-I', '-B'] or args[3] not in self.allowed:
            self.errors.append('UI attempted a non-fixture command')
            owner.setProperty('running', False)
            return
        child = QProcess(self)
        self.all_children.append(child)
        self.children[id(owner)] = child
        self.started_commands.append(args)
        output = bytearray()
        child.readyReadStandardOutput.connect(lambda: output.extend(bytes(child.readAllStandardOutput())))
        child.started.connect(lambda: QMetaObject.invokeMethod(owner, 'started', Qt.DirectConnection))
        def finished(code, status):
            if not isValid(owner) or not isValid(child):
                return
            output.extend(bytes(child.readAllStandardOutput()))
            if output:
                parser = owner.property('stdout')
                if parser is not None:
                    for line in output.decode().splitlines():
                        QMetaObject.invokeMethod(parser, 'read', Qt.DirectConnection, Q_ARG(str, line))
            owner.setProperty('running', False)
            QMetaObject.invokeMethod(owner, 'exited', Qt.DirectConnection, Q_ARG(int, code), Q_ARG(int, 0 if status == QProcess.NormalExit else 1))
        child.finished.connect(finished)
        child.start(args[0], args[1:])

    @Slot(QObject)
    def stop(self, owner):
        child=self.children.get(id(owner))
        if child is not None and child.state()!=QProcess.NotRunning:child.terminate()

    @Slot(QObject, str)
    def write(self, owner, data):
        self.children[id(owner)].write(data.encode())


def wait(app, condition, label, timeout=10):
    end = time.monotonic()+timeout
    while time.monotonic() < end:
        app.processEvents()
        if condition():
            return
        QTest.qWait(10)
    raise AssertionError('Timed out: '+label)


def find_item(view, name):
    # Traverse in QML: wrapping every delegate in Python needlessly exposes
    # short-lived Qt-owned items to binding ownership/destruction edge cases.
    result = QMetaObject.invokeMethod(view.rootObject(), 'fixtureFindItem',
                                     Q_RETURN_ARG('QVariant'), Q_ARG('QVariant', name))
    return result.toQObject() if hasattr(result, 'toQObject') else result


def click(view, root, name):
    QTest.qWait(50)
    def available():
        candidate = find_item(view, name)
        return candidate is not None and candidate.property('visible') and candidate.property('enabled')
    wait(QGuiApplication.instance(), available, 'available control: '+name)
    item = find_item(view, name)
    assert item is not None, 'Missing control: '+name
    assert item.property('visible') and item.property('enabled'), 'Control unavailable: '+name
    # Resolve visual coordinates in QML: dynamic QML types may arrive in Python
    # as QObject wrappers, so do not depend on a QQuickItem Python subclass.
    for _ in range(3):
        QMetaObject.invokeMethod(root,'fixtureItemCenter',Q_RETURN_ARG('QVariant'),Q_ARG('QVariant',name),Q_ARG('QVariant',True))
        QTest.qWait(50)
        center=QMetaObject.invokeMethod(root,'fixtureItemCenter',Q_RETURN_ARG('QVariant'),Q_ARG('QVariant',name),Q_ARG('QVariant',False))
        center=center.toVariant() if hasattr(center,'toVariant') else center
        if 0 <= center['x'] < view.width() and 0 <= center['y'] < view.height():
            break
    assert 0 <= center['x'] < view.width() and 0 <= center['y'] < view.height(), f'{name} is outside the viewport after scrolling: {center}'
    if name in ('approveUpdateButton', 'cancelUpdateButton'):
        half_height=float(item.property('height'))/2
        assert 0 <= center['y']-half_height and center['y']+half_height <= view.height(), f'{name} is partly clipped by the viewport'
    point=QPointF(center['x'],center['y'])
    QTest.mouseClick(view, Qt.LeftButton, Qt.NoModifier, QPoint(round(point.x()), round(point.y())))


def run_tests():
    QQuickStyle.setStyle('Fusion')
    app = QGuiApplication([])
    results = []
    with tempfile.TemporaryDirectory(prefix='ironclad-update-ui-') as directory:
        base = Path(directory)
        stubs(base, 'dark')
        (base/'Quickshell/Io/Process.qml').write_text('''import QtQuick
QtObject {
 id: process
 property var command: []
 property bool running: false
 property var stdout: null
 property bool stdinEnabled: false
 signal started()
 signal exited(int exitCode, int exitStatus)
 function write(data) { fixtureRuntime.write(process, data) }
 onRunningChanged: if (running) fixtureRuntime.start(process, command)
}''')
        plugin = base/'plugin'
        plugin.mkdir()
        shutil.copytree(ROOT/'ui0236', plugin/'ui0236')
        shutil.copyfile(ROOT/'Panel.qml', plugin/'Panel.qml')
        version = base/'version'
        second = base/'second-version'
        second.write_text('1.0')
        mode = base/'mode'
        marker = base/'manager-ran'
        repair_value = base/'aslr'
        repair_value.write_text('0')
        repair_home = base/'home'
        repair_home.mkdir()
        repair_home.chmod(0o702)
        repair_marker = base/'repair-ran'
        repair_manager = base/'repair-manager.py'
        helper = base/'data.py'
        helper.write_text(f'''import json,sys
from pathlib import Path
sys.path.insert(0,{str(ROOT)!r})
from ironclad.software import fingerprint
VERSION=Path({str(version)!r})
MODE=Path({str(mode)!r})
SECOND=Path({str(second)!r})
REPAIR=Path({str(repair_value)!r})
REPAIR_HOME=Path({str(repair_home)!r})
def inventory(state=None):
 if MODE.read_text()=='security-retained':return json.loads((MODE.parent/'security-inventory.json').read_text())
 v=VERSION.read_text()
 kind=MODE.read_text()
 source='uv tool' if kind=='uv-success' else 'Flatpak user' if kind=='flatpak-success' else 'mise'
 name='org.example.Demo' if source=='Flatpak user' else 'demo'
 available='1.1' if v!='1.1' and source=='mise' else None
 result = {{'schema':2,'observed_at':'2026-10-22T00:00:00Z','checked_at':'2026-10-22T00:00:00Z','fresh':True,'inventory_hash':fingerprint({{'demo':v}}),'channels':{{'mise':'available'}},'update_channels':{{'mise':'available'}},'advisory_status':'available','limits':[],'items':[{{'source':source,'name':name,'installed':v,'available':available,'active':True,'requested':'1','advisories':[],'status':'update available' if available else 'no listed update','next_step':'Synthetic test tool only.'}}],'update_count':int(bool(available)),'security_count':0}}
 if kind.startswith('batch'):
  other=SECOND.read_text()
  result['items'].append(dict(result['items'][0],name='other',installed=other,available='1.1' if other!='1.1' else None))
  result['inventory_hash']=fingerprint({{'demo':v,'other':other}})
  result['update_count']=sum(bool(i['available']) for i in result['items'])
 return result
def scan():
 from ironclad.model import Check,Evidence
 good=REPAIR.read_text()=='2'
 check=Check('security.kernel.aslr','pass' if good else 'attention','info' if good else 'medium','ASLR enabled' if good else 'Address randomization is reduced',[Evidence('Synthetic runtime setting',REPAIR.read_text())])
 if MODE.read_text().startswith('fix-home'):
  mode=REPAIR_HOME.stat().st_mode&0o777
  check=Check('security.home.permissions','attention' if mode&2 else 'pass','medium' if mode&2 else 'info','Synthetic home folder permissions',[Evidence('Synthetic home mode',str(mode))],remediation_action_ids=['home.remove_world_write'] if mode&2 else [])
 if good and MODE.read_text()=='fix-success-remaining':check.status='attention'
 if good and MODE.read_text()=='fix-success-unknown':check.status='unavailable'
 result={fixture()!r}
 result['host']={{}}
 result['checks']=[check.dict()]
 return result
''')
        repair_manager.write_text(f'''from pathlib import Path
import time
Path({str(repair_marker)!r}).write_text('ran')
time.sleep(.1)
mode=Path({str(mode)!r}).read_text()
if mode=='fix-failure':raise SystemExit(7)
if mode!='fix-unverified':Path({str(repair_value)!r}).write_text('2')
''')
        manager = base/'manager.py'
        manager.write_text(f'''from pathlib import Path
import sys,time
Path({str(marker)!r}).write_text('ran')
time.sleep(.15)
mode=Path({str(mode)!r}).read_text()
if mode=='failure' or (mode=='batch-failure' and sys.argv[1].startswith('demo@')):raise SystemExit(7)
if mode=='timeout':time.sleep(10)
if mode!='wrong-version':Path({str(second)!r} if len(sys.argv)>1 and sys.argv[1].startswith('other@') else {str(version)!r}).write_text('1.1')
''')
        companion = plugin/'companion.py'
        companion.write_text(f'''import sys
sys.path.insert(0,{str(base)!r})
import data
from ironclad import maintenance,advisor,remediation
advisor.detect_agent=lambda:('codex','/fixture/codex')
advisor.ask=lambda *args,**kwargs:{{'provider':'Fixture agent','answer':'Synthetic fix plan. Review the proposed setting, undo path and verification before approving a change.'}}
maintenance.scan_snapshot=data.scan
import time
def explain_fixture(snapshot):
 if data.MODE.read_text()=='slow-ai':
  (data.MODE.parent/'explanation-started').write_text('started')
  time.sleep(10)
 return {{'scan_id':snapshot['scan_id'],'provider':'Fixture agent','explanations':[{{'check_id':c['check_id'],'meaning':'Synthetic observation.','action':'Review the supported repair.','verification':'Repeat the check.'}} for c in snapshot['checks']]}}
from ironclad import scan_archives
archive_actual=scan_archives.archive
def archive_fixture(state,snapshot,explanations=None):
 if data.MODE.read_text()=='archive-delay':time.sleep(.3)
 if data.MODE.read_text()=='archive-failure':raise ValueError('Synthetic archive failure')
 return archive_actual(state,snapshot,explanations)
scan_archives.archive=archive_fixture
advisor._explain_group=explain_fixture
remediation.actions.account_home=lambda:data.REPAIR_HOME
remediation.aslr_value=lambda:data.REPAIR.read_text()
remediation.authenticate=lambda:1 if data.MODE.read_text()=='fix-auth-cancel' else 0
remediation.failed_services=lambda user=False:['systemd-pcrproduct.service']
repair_run=maintenance.run_update
remediation.run_command=lambda command,privileged:repair_run(['/usr/bin/python3','-I','-B',{str(repair_manager)!r}],timeout=2)['returncode']
maintenance.software_snapshot=data.inventory
maintenance.inventory=data.inventory
maintenance.trusted=lambda path:path
run=maintenance.run_update
maintenance.run_update=lambda command:run(['/usr/bin/python3','-I','-B',{str(manager)!r},command[-1]],timeout=.25 if data.MODE.read_text()=='timeout' else 900)
raise SystemExit(maintenance.main(['--state',{str(base/'state')!r},*sys.argv[1:]]))
''')
        engine = plugin/'engine.py'
        engine.write_text(f'''import sys,json
sys.path.insert(0,{str(base)!r})
import data
from ironclad.activity import history
print(json.dumps(dict(scans=[],actions=[],activity=history({str(base/'state')!r})) if 'history' in sys.argv else data.scan() if 'check' in sys.argv else data.inventory()))
''')
        runtime = Runtime({str(companion), str(engine)})
        view = QQuickView()
        runtime.view = view
        view.engine().addImportPath(str(base))
        view.rootContext().setContextProperty('fixtureRuntime', runtime)
        view.setResizeMode(QQuickView.SizeRootObjectToView)
        view.resize(1020,700)
        view.setSource(QUrl.fromLocalFile(str(plugin/'Panel.qml')))
        assert view.status() != QQuickView.Error
        root = view.rootObject()
        QMetaObject.invokeMethod(root,'open')
        root.setProperty('selected','Software')
        root.setProperty('softwareMode','Installed')
        view.show()
        sys.path.insert(0,str(base))
        import data
        for scenario in ('decline','success','uv-success','flatpak-success','failure','changed-plan','wrong-version','timeout'):
            version.write_text('1.0')
            mode.write_text(scenario)
            marker.unlink(missing_ok=True)
            tool_name = 'org.example.Demo' if scenario=='flatpak-success' else 'demo'
            QMetaObject.invokeMethod(root,'dismissUpdate')
            root.setProperty('operation','software')
            root.setProperty('expandedSoftware','')
            QMetaObject.invokeMethod(root,'receive',Qt.DirectConnection,Q_ARG('QVariant',json.dumps(data.inventory())))
            app.processEvents()
            app.processEvents()
            view.grabWindow().save(str(ROOT/'.local-evidence/update-fixture-debug.png'))
            wait(app,lambda: find_item(view,'softwareDetails_'+tool_name) is not None,'software row')
            if scenario=='decline':
                click(view,root,'softwareDetails_'+tool_name)
                app.processEvents()
            click(view,root,'updateTool_'+tool_name)
            wait(app,lambda: root.property('updateStage') in ('review','error'),'review plan')
            assert root.property('updateStage')=='review',root.property('updateMessage')
            assert not marker.exists(), 'Review executed the manager before approval'
            assert root.property('opened'), 'Review closed Ironclad'
            if scenario=='decline':
                click(view,root,'cancelUpdateButton')
                assert root.property('updateStage')=='idle' and not marker.exists()
            else:
                if scenario=='changed-plan':version.write_text('1.0.1')
                view.grabWindow().save(str(ROOT/'.local-evidence/update-review-fixture.png'))
                click(view,root,'approveUpdateButton')
                assert root.property('updateStage')=='applying', 'Approval button did not launch update'
                wait(app,lambda: root.property('updateStage') in ('done','error') and not root.property('busy'),'update result')
                expected='done' if scenario in ('success','uv-success','flatpak-success') else 'error'
                assert root.property('updateStage')==expected,root.property('updateMessage')
                QTest.qWait(75)
                wait(app,lambda: not root.property('busy'),'inventory refresh')
                if scenario in ('success','uv-success','flatpak-success'):
                    wait(app,lambda: root.property('softwareUpdates')==0,'updated inventory')
                    assert version.read_text()=='1.1'
                    assert root.property('softwareUpdates')==0,'Inventory did not reflect the new version'
                if scenario=='changed-plan':assert not marker.exists(),'Changed plan ran the manager'
                if scenario=='failure':assert version.read_text()=='1.0' and '7' in root.property('updateMessage')
                if scenario=='timeout':assert 'timeout' in root.property('updateMessage')
                if scenario=='wrong-version':assert 'version_not_verified' in root.property('updateMessage')
            results.append(scenario)
        root.setProperty('softwareMode','Updates')
        for scenario in ('batch-decline','batch-success','batch-failure','batch-changed'):
            QMetaObject.invokeMethod(root,'dismissUpdate')
            root.setProperty('selectedTools',[])
            version.write_text('1.0')
            second.write_text('1.0')
            mode.write_text(scenario)
            marker.unlink(missing_ok=True)
            root.setProperty('operation','software')
            QMetaObject.invokeMethod(root,'receive',Qt.DirectConnection,Q_ARG('QVariant',json.dumps(data.inventory())))
            app.processEvents()
            click(view,root,'selectTool_demo')
            click(view,root,'selectTool_other')
            assert len(root.property('selectedTools').toVariant())==2
            click(view,root,'clearSelectionButton')
            assert len(root.property('selectedTools').toVariant())==0
            click(view,root,'selectListedUpdatesButton')
            assert len(root.property('selectedTools').toVariant())==2
            click(view,root,'updateSelectedButton')
            wait(app,lambda: root.property('updateStage')=='review' and not root.property('busy'),'batch review')
            assert find_item(view,'approveUpdateButton').property('text')=='Install 2 updates'
            assert not find_item(view,'updateSelectedButton').property('visible'),'Review must only show the actual installation action'
            assert not marker.exists(),'Batch ran before approval'
            if scenario=='batch-decline':
                click(view,root,'cancelUpdateButton')
                assert root.property('updateStage')=='idle' and not marker.exists()
            else:
                if scenario=='batch-changed':second.write_text('9.0')
                click(view,root,'approveUpdateButton')
                wait(app,lambda: root.property('updateStage') in ('done','error') and not root.property('busy'),'batch result')
                QTest.qWait(75)
                wait(app,lambda: not root.property('busy'),'batch inventory reload')
                if scenario=='batch-success':
                    assert root.property('updateStage')=='done',root.property('updateMessage')
                    assert version.read_text()==second.read_text()=='1.1'
                    assert root.property('softwareUpdates')==0
                    assert find_item(view,'softwareList').property('count')==0,'Completed apps remained in Updates'
                    assert find_item(view,'softwareEmptyState').property('visible')
                else:
                    assert root.property('updateStage')=='error'
                    assert version.read_text()=='1.0'
                    if scenario=='batch-failure':
                        assert second.read_text()=='1.0'
                        assert 'Not run: mise:other' in root.property('updateMessage')
                    else:assert not marker.exists()
            results.append(scenario)
        QMetaObject.invokeMethod(root,'dismissUpdate')
        root.setProperty('selectedTools',[])
        long_inventory = data.inventory()
        example = long_inventory['items'][0]
        long_inventory['items'] = [dict(example,name='tool%02d'%n,installed='1.0',available='1.1') for n in range(40)]
        root.setProperty('operation','software')
        QMetaObject.invokeMethod(root,'receive',Qt.DirectConnection,Q_ARG('QVariant',json.dumps(long_inventory)))
        QTest.qWait(100)
        click(view,root,'selectTool_tool00')
        scrollbar = find_item(view,'softwareScrollbar')
        listing = find_item(view,'softwareList')
        assert scrollbar.property('visible') and scrollbar.property('size') < 1
        start = scrollbar.mapToScene(QPointF(scrollbar.width()/2,scrollbar.height()*scrollbar.property('visualSize')/2))
        finish = scrollbar.mapToScene(QPointF(scrollbar.width()/2,scrollbar.height()-2))
        QTest.mousePress(view,Qt.LeftButton,Qt.NoModifier,QPoint(round(start.x()),round(start.y())))
        QTest.mouseMove(view,QPoint(round(finish.x()),round(finish.y())),100)
        QTest.mouseRelease(view,Qt.LeftButton,Qt.NoModifier,QPoint(round(finish.x()),round(finish.y())))
        wait(app,lambda: listing.property('atYEnd'),'scrollbar reaches final software row')
        click(view,root,'selectTool_tool39')
        assert len(root.property('selectedTools').toVariant())==2
        update_button = find_item(view,'updateSelectedButton')
        point = update_button.mapToScene(QPointF(update_button.width()/2,update_button.height()/2))
        assert update_button.property('enabled') and 0 < point.y() < view.height()
        assert point.y() > listing.mapToScene(QPointF(0,listing.height())).y(),'Bulk update button must stay beneath the scrolling viewport'
        results.append('scrollbar-last-row-and-fixed-bulk-update-button')
        click(view,root,'updateOmarchyButton')
        assert runtime.omarchy_handoff[-2:] == ['/usr/bin/omarchy','update']
        wait(app,lambda: 'cancelled or incomplete' in root.property('message'),'Omarchy updater cancellation')
        results.append('omarchy-button-handoff-no-system-update')
        root.setProperty('operation','scan')
        QMetaObject.invokeMethod(root,'receive',Qt.DirectConnection,Q_ARG('QVariant',json.dumps(fixture())))
        root.setProperty('selected','Diagnostics')
        root.setProperty('diagnosticGroup','Network')
        app.processEvents()
        click(view,root,'reviewFinding_network.listeners')
        click(view,root,'inspectFinding_network.listeners')
        wait(app,lambda: root.property('opened'),'panel restored after inspection')
        assert runtime.inspection_handoff[-5:]==['/usr/bin/ss','--listening','--numeric','--tcp','--udp']
        assert root.property('expandedCheckId')=='network.listeners'
        click(view,root,'planFix_network.listeners')
        assert root.property('selected')=='AI'
        assert 'network.listeners' in root.property('aiQuestion')
        assert 'Do not apply changes or assume approval' in root.property('aiQuestion')
        wait(app,lambda: not root.property('aiBusy') and 'Synthetic fix plan' in root.property('aiAnswer'),'specific finding fix plan')
        results.append('finding-inspection-steps-and-ai-plan-no-mutation')

        wait(app,lambda: not root.property('busy') and not root.property('aiBusy'),'settle before long finding layout')
        snapshot=fixture()
        check=next(row for row in snapshot['checks'] if row['check_id']=='network.listeners')
        root.setProperty('selected','Overview')
        priorities=[dict(check,check_id='hardware.fixture',severity='high'),dict(check,check_id='performance.fixture',severity='critical'),dict(check,check_id='security.fixture',severity='medium'),check]
        root.setProperty('results',priorities);root.setProperty('ignoredFindings',[])
        root.setProperty('query','a stale search that matches nothing')
        QTest.qWait(100)
        overview=find_item(view,'overviewView')
        assert overview.property('visible')
        rows=overview.property('priorities').toVariant()
        assert len(rows)==3 and rows[0]['check_id']=='performance.fixture'
        assert not find_item(view,'findingsList').property('visible')
        view.grabWindow().save(str(ROOT/'.local-evidence/overview-summary.png'))
        # Priority links clear old filters and open the exact evidence in Diagnostics.
        click(view,root,'overviewReview_performance.fixture')
        assert root.property('selected')=='Diagnostics' and root.property('expandedCheckId')=='performance.fixture'
        assert root.property('query')==''
        root.setProperty('results',[check])
        results.append('overview-distinct-summary-top-three-and-diagnostic-handoff')
        root.setProperty('findingExplanations',{'network.listeners':{'meaning':'A long finding explanation with useful context. '*28,'action':'Review the owning application before changing network access. '*12,'verification':'Repeat the listener check and verify intended access.'}})
        QTest.qWait(100)
        listing=find_item(view,'findingsList');scrollbar=find_item(view,'findingsScrollbar')
        listing.setProperty('contentY',0);QTest.qWait(50)
        top=listing.mapToScene(QPointF(0,0)).y();bottom=top+listing.height()
        click(view,root,'reviewFinding_network.listeners')
        wait(app,lambda: scrollbar.property('size')<1,'expanded finding layout')
        for name in ('reviewFix_network.listeners','inspectFinding_network.listeners','planFix_network.listeners'):
            button=find_item(view,name);point=button.mapToScene(QPointF(0,0))
            assert button.property('visible') and top<=point.y() and point.y()+button.height()<=bottom, name+' clipped by long explanation'
        assert scrollbar.property('visible') and scrollbar.property('size')<1
        view.grabWindow().save(str(ROOT/'.local-evidence/overview-long-finding-actions.png'))
        start=scrollbar.mapToScene(QPointF(scrollbar.width()/2,scrollbar.height()*scrollbar.property('visualSize')/2))
        finish=scrollbar.mapToScene(QPointF(scrollbar.width()/2,scrollbar.height()-2))
        QTest.mousePress(view,Qt.LeftButton,Qt.NoModifier,QPoint(round(start.x()),round(start.y())))
        QTest.mouseMove(view,QPoint(round(finish.x()),round(finish.y())),100)
        QTest.mouseRelease(view,Qt.LeftButton,Qt.NoModifier,QPoint(round(finish.x()),round(finish.y())))
        wait(app,lambda: listing.property('atYEnd'),'scroll long finding to verification')
        verification=find_item(view,'findingVerification_network.listeners')
        assert verification.mapToScene(QPointF(0,verification.height())).y()<=bottom
        view.grabWindow().save(str(ROOT/'.local-evidence/overview-long-finding-scrolled.png'))
        results.append('long-finding-actions-visible-and-verification-scrollable')

        wait(app,lambda: not root.property('busy') and not root.property('aiBusy'),'settle before ignore test')
        tpm=dict(check,check_id='startup.units.system_failed',summary='TPM platform service failed',severity='medium',evidence=[{'source':'systemctl --failed','value':'systemd-pcrproduct.service','observed_at':'2026-10-22T00:00:00+00:00'}])
        root.setProperty('selected','Diagnostics')
        root.setProperty('results',[tpm,check]);root.setProperty('findingExplanations',{})
        root.setProperty('expandedCheckId','');root.setProperty('showIgnoredFindings',False)
        QMetaObject.invokeMethod(root,'loadFindingPreferences')
        listing.setProperty('contentY',0);QTest.qWait(100)
        assert root.property('attentionCount')==2
        view.grabWindow().save(str(ROOT/'.local-evidence/ignore-fixture-before-click.png'))
        click(view,root,'rowIgnore_startup.units.system_failed')
        wait(app,lambda: root.property('attentionCount')==1 and root.property('ignoredFindingCount')==1,'ignore TPM without repair')
        assert find_item(view,'undoIgnoreButton').property('visible')
        click(view,root,'undoIgnoreButton')
        wait(app,lambda: root.property('ignoredFindingCount')==0,'undo ignored TPM without repair')
        click(view,root,'rowIgnore_startup.units.system_failed')
        wait(app,lambda: root.property('ignoredFindingCount')==1,'ignore again for persistence coverage')
        rows=root.property('results')
        rows=rows.toVariant() if hasattr(rows,'toVariant') else rows
        assert len(rows)==2 and rows[0]['status']=='attention'
        saved=json.loads((base/'state/ignored-findings.json').read_text())
        assert saved['ignored'].get('startup.units.system_failed')
        root.setProperty('ignoredFindings',[])
        QMetaObject.invokeMethod(root,'loadFindingPreferences')
        wait(app,lambda: root.property('ignoredFindingCount')==1,'ignore survives preference reload')
        click(view,root,'toggleIgnoredFindings')
        wait(app,lambda: find_item(view,'rowIgnore_startup.units.system_failed') is not None,'show ignored TPM finding')
        listing.setProperty('contentY',0);QTest.qWait(75)
        assert find_item(view,'rowIgnore_startup.units.system_failed').property('text')=='Restore'
        click(view,root,'rowIgnore_startup.units.system_failed')
        wait(app,lambda: root.property('ignoredFindingCount')==0 and root.property('attentionCount')==2,'restore ignored finding')
        root.setProperty('showIgnoredFindings',False)
        root.setProperty('selected','Diagnostics');root.setProperty('diagnosticGroup','Diagnostics')
        root.setProperty('results',[dict(tpm,status='pass',severity='info')])
        listing.setProperty('contentY',0);QTest.qWait(100)
        click(view,root,'rowIgnore_startup.units.system_failed')
        wait(app,lambda: root.property('ignoredFindingCount')==1,'ignore informational finding')
        assert root.property('totals').toVariant()['observed']==1
        click(view,root,'toggleIgnoredFindings')
        listing.setProperty('contentY',0);QTest.qWait(75)
        click(view,root,'rowIgnore_startup.units.system_failed')
        wait(app,lambda: root.property('ignoredFindingCount')==0,'restore informational finding')
        root.setProperty('showIgnoredFindings',False)
        results.append('ignore-all-findings-persistent-reversible-not-a-repair')

        for scenario in ('fix-decline','fix-success','fix-success-remaining','fix-success-unknown','fix-failure','fix-auth-cancel','fix-unverified','fix-changed'):
            wait(app,lambda: not root.property('busy') and not root.property('aiBusy'),'previous requests settled')
            mode.write_text(scenario)
            repair_value.write_text('0')
            repair_marker.unlink(missing_ok=True)
            root.setProperty('operation','scan')
            QMetaObject.invokeMethod(root,'receive',Qt.DirectConnection,Q_ARG('QVariant',json.dumps(data.scan())))
            root.setProperty('selected','Diagnostics')
            root.setProperty('expandedCheckId','')
            QTest.qWait(75)
            click(view,root,'reviewFinding_security.kernel.aslr')
            click(view,root,'reviewFix_security.kernel.aslr')
            wait(app,lambda: root.property('fixStage')=='review' and not root.property('busy'),'repair review')
            assert not repair_marker.exists(),'Repair executed before final approval'
            assert '/usr/bin/sysctl -w kernel.randomize_va_space=2' in find_item(view,'fixCommands').property('text')
            assert 'running-kernel setting only' in find_item(view,'fixImpact').property('text')
            if scenario=='fix-decline':
                click(view,root,'closeFixButton')
                assert root.property('fixStage')=='idle' and not repair_marker.exists()
            else:
                if scenario=='fix-changed':repair_value.write_text('1')
                click(view,root,'applyFixButton')
                wait(app,lambda: root.property('fixStage') in ('done','error') and not root.property('busy') and not root.property('aiBusy'),'repair result and fresh scan')
                QTest.qWait(75)
                wait(app,lambda: not root.property('busy') and not root.property('aiBusy'),'repair rescan settled')
                if scenario in ('fix-success-remaining','fix-success-unknown'):
                    expected='remaining' if scenario.endswith('remaining') else 'unknown'
                    assert root.property('repairScanState')==expected,root.property('fixMessage')
                    assert root.property('fixResult').toVariant()['verified'] is True
                    assert root.property('fixStage')=='error'
                    assert repair_value.read_text()=='2'
                elif scenario=='fix-success':
                    assert root.property('repairScanState')=='resolved',root.property('fixMessage')
                    wait(app,lambda: bool(root.property('results').toVariant()) and root.property('results').toVariant()[0]['status']=='pass','new scan confirms repair')
                    assert root.property('fixStage')=='done',root.property('fixMessage')
                    assert repair_value.read_text()=='2'
                    assert root.property('results').toVariant()[0]['status']=='pass','Repair did not trigger a fresh scan'
                    assert root.property('opened')
                else:
                    assert root.property('fixStage')=='error'
                    if scenario in ('fix-changed','fix-auth-cancel'):assert not repair_marker.exists()
                    else:assert repair_value.read_text()=='0'
                click(view,root,'closeFixButton')
            results.append(scenario)
        mode.write_text('fix-home-success')
        repair_home.chmod(0o702)
        root.setProperty('operation','scan')
        QMetaObject.invokeMethod(root,'receive',Qt.DirectConnection,Q_ARG('QVariant',json.dumps(data.scan())))
        click(view,root,'reviewFinding_security.home.permissions')
        click(view,root,'reviewFix_security.home.permissions')
        wait(app,lambda: root.property('fixStage')=='review' and not root.property('busy'),'home permission review')
        assert '0702 to 0700' in find_item(view,'fixCommands').property('text')
        assert all(isinstance(value,str) for value in root.property('fixPlan').toVariant()['before']),'Filesystem identity must survive JavaScript JSON without rounding'
        click(view,root,'applyFixButton')
        wait(app,lambda: root.property('fixStage') in ('done','error') and not root.property('busy'),'home repair result')
        assert root.property('fixStage')=='done',root.property('fixMessage')
        assert repair_home.stat().st_mode&0o777==0o700
        wait(app,lambda: bool(root.property('results').toVariant()) and root.property('results').toVariant()[0]['status']=='pass' and not root.property('busy') and not root.property('aiBusy'),'home permission repair rescan')
        assert root.property('repairScanState')=='resolved',root.property('fixMessage')
        assert root.property('fixResult').toVariant()['undo_receipt']
        click(view,root,'closeFixButton')
        results.append('fix-home-permission-json-precision-and-rescan')
        QTest.qWait(100)
        wait(app,lambda: not root.property('busy') and not root.property('aiBusy'),'settle post-repair software and explanation refresh')
        mode.write_text('fix-manual')
        root.setProperty('operation','scan')
        manual_scan=data.scan()
        manual_scan['checks'][0]['check_id']='startup.units.system_failed'
        manual_scan['checks'][0]['status']='attention'
        QMetaObject.invokeMethod(root,'receive',Qt.DirectConnection,Q_ARG('QVariant',json.dumps(manual_scan)))
        wait(app,lambda: not root.property('busy') and not root.property('aiBusy'),'manual finding controls ready')
        click(view,root,'reviewFinding_startup.units.system_failed')
        click(view,root,'reviewFix_startup.units.system_failed')
        wait(app,lambda: root.property('fixStage')=='manual' and not root.property('busy'),'protected-service manual repair')
        assert not find_item(view,'applyFixButton').property('visible'),'Protected boot service offered a generic Apply fix'
        assert 'systemd-pcrproduct.service' in root.property('fixManual')
        click(view,root,'closeFixButton')
        results.append('fix-protected-service-manual-no-fake-apply')
        unsupported=data.scan()
        unsupported['checks'][0]['check_id']='security.boot.secure_boot'
        unsupported['checks'][0]['status']='attention'
        root.setProperty('operation','scan')
        QMetaObject.invokeMethod(root,'receive',Qt.DirectConnection,Q_ARG('QVariant',json.dumps(unsupported)))
        QTest.qWait(75)
        before=len(runtime.started_commands)
        assert find_item(view,'reviewFix_security.boot.secure_boot').property('text')=='How to fix'
        click(view,root,'reviewFinding_security.boot.secure_boot')
        click(view,root,'reviewFix_security.boot.secure_boot')
        assert root.property('expandedCheckId')=='security.boot.secure_boot'
        assert root.property('fixStage')=='idle'
        assert len(runtime.started_commands)==before,'Unsupported instruction button launched a repair process'
        results.append('unsupported-firmware-button-opens-steps-without-execution')
        # History is loaded from real production receipts without saved scans.
        QMetaObject.invokeMethod(root,'navigate',Qt.DirectConnection,Q_ARG('QVariant','Activity'))
        wait(app,lambda: not root.property('busy') and len(root.property('activityData').toVariant()['entries']) > 0,'local repair/update history')
        entries=root.property('activityData').toVariant()['entries']
        assert root.property('history').toVariant()==[]
        assert any(row['kind']=='update' and row['outcome']=='verified' and '1.1' in row['versions'] for row in entries)
        assert any(row['kind']=='repair' and row['outcome']=='verified' for row in entries)
        assert any(row['outcome']=='unverified' for row in entries)
        assert not find_item(view,'emptyActivity').property('visible')
        click(view,root,'refreshActivityButton')
        wait(app,lambda: not root.property('busy'),'refresh action history')
        view.grabWindow().save(str(ROOT/'.local-evidence/activity-0216-fixture.png'))
        results.append('activity-real-receipts-without-saved-scans-and-refresh')
        wait(app,lambda:not root.property('busy') and not root.property('aiBusy'),'settle before slow AI regression')
        mode.write_text('slow-ai')
        ai_marker=base/'explanation-started'
        def ai_requests():
            return sum('explain-findings' in args or 'ask' in args for args in runtime.started_commands)
        ai_before=ai_requests()
        click(view,root,'scanMachineButton')
        wait(app,lambda:root.property('scanReceived') and not root.property('busy'),'local scan without AI consent')
        QTest.qWait(150)
        assert ai_requests()==ai_before and not ai_marker.exists(),'Local scan must not send AI requests'
        assert not root.property('explanationBusy') and root.property('findingExplanations').toVariant()=={}
        assert 'have not been requested' in root.property('explanationMessage')
        root.setProperty('selected','Diagnostics')
        click(view,root,'explainAllChecksButton')
        wait(app,lambda:ai_marker.exists() and root.property('explanationBusy'),'slow background AI actually started')
        assert ai_requests()==ai_before+1,'Explicit Explain all checks must start exactly one request'
        results.append('local-scan-sends-no-ai-until-explicit-explain-all-click')
        assert not root.property('aiBusy'),'Background AI must not gate local actions'
        assert find_item(view,'scanMachineButton').property('enabled')
        root.setProperty('selected','Protection')
        for attempt in range(2):
            wait(app,lambda:not root.property('busy') and root.property('explanationBusy'),'scan available while AI waits')
            scans_before=sum('check' in args for args in runtime.started_commands)
            ai_before=ai_requests()
            ai_marker.unlink(missing_ok=True)
            click(view,root,'scanMachineButton')
            wait(app,lambda:sum('check' in args for args in runtime.started_commands)==scans_before+1 and root.property('scanReceived') and not root.property('busy'),'scan click completes despite pending AI')
            assert root.property('selected')=='Overview'
            assert root.property('scanStatus').startswith('Scan complete · 1 catalog checks')
            assert find_item(view,'scanProgressLabel').property('visible')
            QTest.qWait(150)
            assert ai_requests()==ai_before and not ai_marker.exists(),'Rescan must not renew AI consent'
            assert not root.property('explanationBusy')
            root.setProperty('selected','Diagnostics')
            click(view,root,'explainAllChecksButton')
            wait(app,lambda:ai_marker.exists() and root.property('explanationBusy'),'new explicitly requested explanation started')
        click(view,root,'stopExplanationButton')
        wait(app,lambda:not root.property('explanationBusy'),'stop only plugin-owned AI request')
        assert find_item(view,'scanMachineButton').property('enabled')
        results.append('scan-click-twice-during-slow-ai-visible-completion-and-stop')
        wait(app,lambda:not root.property('busy'),'settle before retained-security fixture')
        go_rows=[]
        for installed,active,fixed in [('1.26.10',True,None),('1.26.9',False,'1.26.10'),('1.27.2',False,'1.27.3')]:
            go_rows.append(dict(name='go',source='mise',installed=installed,available=None,active=active,status='no listed update' if active else 'security review',configured_versions=['1.26.10'],security_fixed_versions=[fixed] if fixed else [],next_step='Review project pins before retiring retained toolchains.',advisories=[] if active else [dict(id='GO-2026-6809',severity='unknown',issues=['GO-2026-6809'],summary='Synthetic certificate advisory.')]))
        security_inventory=dict(schema=2,observed_at='2026-10-22T00:00:00Z',checked_at='2026-10-22T00:00:00Z',fresh=True,limits=[],items=go_rows,update_channels=dict(mise='available'),advisory_status='available',security_count=2,update_count=0)
        (base/'security-inventory.json').write_text(json.dumps(security_inventory));mode.write_text('security-retained')
        root.setProperty('operation','software')
        QMetaObject.invokeMethod(root,'receive',Qt.DirectConnection,Q_ARG('QVariant',json.dumps(security_inventory)))
        root.setProperty('selected','Overview')
        assert '2 retained versions' in root.property('message') and '0 configured-tool updates' in root.property('message')
        click(view,root,'overviewSecurityReviewButton')
        wait(app,lambda:not root.property('busy'),'security inventory reload')
        assert root.property('selected')=='Software' and root.property('softwareMode')=='Security'
        assert find_item(view,'softwareList').property('count')==2
        assert 'Retained' in find_item(view,'securityScope_1.26.9').property('text')
        assert '1.26.10' in find_item(view,'securityFix_1.26.9').property('text')
        assert '1.27.3' in find_item(view,'securityFix_1.27.2').property('text')
        click(view,root,'softwareMode_Updates')
        assert find_item(view,'softwareList').property('count')==0
        assert 'Security notices remain' in find_item(view,'softwareEmptyState').property('text')
        view.grabWindow().save(str(ROOT/'.local-evidence/security-retained-029-updates.png'))
        click(view,root,'softwareMode_Security')
        QTest.qWait(150)
        view.grabWindow().save(str(ROOT/'.local-evidence/security-retained-029-security.png'))
        results.append('patched-global-retained-vulnerable-go-visible-with-zero-updates-and-fixes')
        # Exercise the actual large result envelope and all profile selector paths.
        from ironclad.check_catalog import inventory as check_inventory
        from ironclad.model import Check,Evidence
        for profile in ('quick','full','super'):
            large=data.scan()
            large['checks']=[Check(r['id'],'observed','info',r['label'],[Evidence('Synthetic control fixture','No host data read.')]).dict() for r in check_inventory(profile)['checks']]
            (base/('profile-'+profile+'.json')).write_text(json.dumps(large))
        engine.write_text("import json,sys\nfrom pathlib import Path\np=sys.argv[sys.argv.index('--profile')+1]\nprint((Path("+repr(str(base))+" )/('profile-'+p+'.json')).read_text())\n")
        root.setProperty('selected','Diagnostics');root.setProperty('query','');root.setProperty('reviewOnly',False);root.setProperty('diagnosticGroup','Diagnostics')
        mode.write_text('large-profile')
        for index,(profile,count) in enumerate((('quick',90),('full',180),('super',420))):
            click(view,root,'scanProfileSelector')
            QTest.keyClick(view,Qt.Key_Home)
            for _ in range(index):QTest.keyClick(view,Qt.Key_Down)
            QTest.keyClick(view,Qt.Key_Return)
            wait(app,lambda:root.property('profile')==profile,'profile selector '+profile)
            ai_before=ai_requests()
            click(view,root,'scanMachineButton')
            wait(app,lambda:len(root.property('results').toVariant())==count and not root.property('busy'),'large scan '+profile)
            QTest.qWait(150)
            assert ai_requests()==ai_before and not root.property('explanationBusy'),'Profile scan must remain local: '+profile
            root.setProperty('selected','Diagnostics')
            click(view,root,'explainAllChecksButton')
            wait(app,lambda:not root.property('explanationBusy'),'bounded explanation '+profile)
            assert 'All checks have AI explanations' in root.property('explanationMessage'),root.property('explanationMessage')
            root.setProperty('selected','Diagnostics')
            wait(app,lambda:find_item(view,'findingsList').property('count')==count,'all catalog rows visible '+profile)
        QMetaObject.invokeMethod(find_item(view,'findingsList'),'positionViewAtEnd')
        QTest.qWait(100)
        view.grabWindow().save(str(ROOT/'.local-evidence/super-scan-ui-fixture.png'))
        results.append('quick-90-full-180-super-420-real-selector-scan-process-large-envelope-and-all-check-explanations')
        # A new scan must clear old facts/AI immediately and preserve both in gzip.
        mode.write_text('archive-delay')
        root.setProperty('aiAnswer','Old answer must clear');root.setProperty('aiBrief','Old brief must clear')
        click(view,root,'scanMachineButton')
        assert root.property('results').toVariant()==[]
        assert root.property('findingExplanations').toVariant()=={}
        assert root.property('aiAnswer')=='' and root.property('aiBrief')==''
        wait(app,lambda:root.property('scanReceived') and not root.property('busy'),'fresh super scan after archive')
        assert not root.property('explanationBusy') and root.property('findingExplanations').toVariant()=={}
        import gzip
        archives=[json.loads(gzip.decompress(p.read_bytes())) for p in (base/'state/scan-archives').glob('*.json.gz')]
        assert any(len(a['scan']['checks'])==420 and len(a['explanations'])==420 for a in archives)
        scans_before=sum('check' in args for args in runtime.started_commands)
        mode.write_text('archive-failure');click(view,root,'scanMachineButton')
        wait(app,lambda:not root.property('busy'),'archive failure is reported')
        assert root.property('results').toVariant()==[] and root.property('pendingArchiveScan') is not None
        assert sum('check' in args for args in runtime.started_commands)==scans_before
        assert 'could not be archived' in root.property('scanStatus')
        mode.write_text('archive-delay');click(view,root,'scanMachineButton')
        wait(app,lambda:root.property('scanReceived') and not root.property('busy'),'retry preserves and archives old scan')
        assert not root.property('explanationBusy') and root.property('findingExplanations').toVariant()=={}
        results.append('new-scan-clears-results-and-ai-gzip-preserves-420-checks-and-explanations-archive-failure-blocks-and-retries')
        target='service.ironclad_antimalware_engine.service.restrictfilesystems'
        root.setProperty('selected','Diagnostics');root.setProperty('diagnosticGroup','Diagnostics');root.setProperty('query',target)
        wait(app,lambda:find_item(view,'findingsList').property('count')==1,'individual Super Scan check')
        click(view,root,'reviewFinding_'+target);click(view,root,'planFix_'+target)
        wait(app,lambda:not root.property('aiBusy') and 'Synthetic fix plan' in root.property('aiAnswer'),'individual AI follow-up for a Super Scan control')
        assert target in root.property('aiQuestion') and target in root.property('aiBrief')
        assert 'All 420 checks' in root.property('aiBrief')
        results.append('individual-super-scan-ai-followup-uses-selected-420-check-snapshot-and-evidence')
        assert not runtime.errors,runtime.errors
        assert list((base/'state/maintenance').glob('*-finished.json')),'Completion receipts missing'
        print(json.dumps({'passed':results,'real_child_processes':len(runtime.started_commands),'actual_apps_changed':False}))
        view.setSource(QUrl())
        app.processEvents()
    return 0


def main():
    try:
        return run_tests()
    finally:
        for runtime in Runtime.instances:
            runtime.shutdown()
        Runtime.instances.clear()


if __name__=='__main__':raise SystemExit(main())
