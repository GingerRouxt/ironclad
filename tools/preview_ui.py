#!/usr/bin/env python3
"""Render original plugin QML with explicit mock shell types, never a live shell.
Optional developer tool: requires PySide6, not an Ironclad runtime dependency.
"""
import argparse
import json
import os
import resource
from pathlib import Path
import sys
import tempfile

os.environ['QT_QPA_PLATFORM']='offscreen'
os.environ['QT_QUICK_BACKEND']='software'
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
from PySide6.QtCore import Q_ARG, QMetaObject, Qt, QUrl, QTimer
from PySide6.QtGui import QGuiApplication, QPalette, QColor
from PySide6.QtQuick import QQuickView
from PySide6.QtQuickControls2 import QQuickStyle

ROOT=Path(__file__).resolve().parents[1]


def write(base, name, body):
    p=base/name; p.parent.mkdir(parents=True,exist_ok=True); p.write_text(body)


def stubs(base, theme):
    write(base,'qs/Ui/qmldir','module qs.Ui\nBarWidget 1.0 BarWidget.qml\nWidgetButton 1.0 WidgetButton.qml\nPanel 1.0 Panel.qml\nKeyboardPanel 1.0 KeyboardPanel.qml\n')
    write(base,'qs/Ui/BarWidget.qml','import QtQuick\nItem { property var bar: null; property var settings: ({}); property string moduleName: ""; property bool vertical: false }')
    write(base,'qs/Ui/WidgetButton.qml','import QtQuick\nItem { property var bar: null; property string text: ""; property real labelWidth: 100; implicitWidth: 110; implicitHeight: 30; signal pressed(int b); Text { text: parent.text; color: "white" } }')
    write(base,'qs/Ui/Panel.qml','''import QtQuick
Item {
 property var bar: null
 property var settings: ({})
 property string moduleName: ""
 property bool manageIpc: false
 property bool opened: false
 property bool popoutSwitchClosing: false
 function open() { opened=true }
 function close() { opened=false }
 function toggle() { opened=!opened }
 function closeForPopoutSwitch() { opened=false }
 function fixtureItemCenter(name, reveal) {
   var item = fixtureFindItem(name)
   if (!item) return null
   if (reveal) {
     var ancestor = item.parent
     while (ancestor) {
       if (typeof ancestor.contentY === "number" && typeof ancestor.contentHeight === "number") {
         var point = item.mapToItem(ancestor, item.width / 2, item.height / 2)
         if (point.y < 20 || point.y > ancestor.height - 25)
           ancestor.contentY = Math.max(0, Math.min(ancestor.contentHeight - ancestor.height, ancestor.contentY + point.y - ancestor.height / 2))
       }
       ancestor = ancestor.parent
     }
   }
   var center = item.mapToItem(null, item.width / 2, item.height / 2)
   return {x:center.x, y:center.y}
 }
 function fixtureFindItem(name) {
   var pending = [this]
   while (pending.length) {
     var item = pending.pop()
     if (item.objectName === name) return item
     var children = item.children || []
     for (var i = 0; i < children.length; ++i) pending.push(children[i])
   }
   return null
 }
}''')
    write(base,'qs/Ui/KeyboardPanel.qml','''import QtQuick
Rectangle {
 property var bar: null
 property var anchorItem: null
 property var owner: null
 property var focusTarget: null
 property bool open: false
 property int contentWidth: 1020
 property int contentHeight: 700
 width: contentWidth; height: contentHeight
 visible: open
 color: "transparent"
 function fittedContentWidth(w) { return w }
 function fittedContentHeight(h) { return h }
}''')
    write(base,'qs/Commons/qmldir','module qs.Commons\nsingleton Color 1.0 Color.qml\n')
    foreground='#eef2f6' if theme=='dark' else '#17212b'
    accent='#83b6c4' if theme=='dark' else '#285d73'
    background='#171d24' if theme=='dark' else '#edf1f5'
    write(base,'qs/Commons/Color.qml',f'''pragma Singleton
import QtQuick
QtObject {{
 id: themeColors
 property color foreground: "{foreground}"
 property color background: "{background}"
 property color accent: "{accent}"
 property color urgent: "#c35c68"
 readonly property QtObject popups: QtObject {{
  property color background: themeColors.background
  property color text: themeColors.foreground
 }}
}}''')
    write(base,'Quickshell/Io/qmldir','module Quickshell.Io\nProcess 1.0 Process.qml\nSplitParser 1.0 SplitParser.qml\n')
    write(base,'Quickshell/Io/Process.qml','import QtQuick\nQtObject { property var command: []; property bool running: false; property var stdout: null; property bool stdinEnabled: false; signal started(); function write(data) {} signal exited(int exitCode, int exitStatus) }')
    write(base,'Quickshell/Io/SplitParser.qml','import QtQuick\nQtObject { signal read(string data) }')


def fixture():
    sys.path.insert(0,str(ROOT))
    from ironclad.model import Check, Evidence
    checks=[]
    values=[('performance.cpu.load','pass','info','CPU load within advisory threshold','logical_cpus=8, load_1_5_15=(0.3, 0.5, 0.4)'),
            ('security.home.permissions','attention','medium','Home directory allows writes by other users','mode=0702'),
            ('network.listeners','attention','low','4 listening sockets; 1 wildcard bind','listeners=4; wildcard=1; addresses omitted'),
            ('security.firewall','unavailable','info','Firewall enforcement requires a permission-aware check','Not probed; no elevated calls'),
            ('storage.package_cache','pass','info','Package-cache candidates; retained rollback versions may be valuable','packages=42; apparent_bytes=870000000; reclaimable_bytes=unknown')]
    for id,state,severity,summary,evidence in values:
        c=Check(id,state,severity,summary,[Evidence('Synthetic preview data',evidence)],recommendation='Review the evidence and intended workflow before changing settings. No changes have been applied.')
        if id=='security.home.permissions': c.remediation_action_ids=['home.remove_world_write']
        checks.append(c.dict())
    return {'schema_version':'1.0','host':{},'scan_id':'11111111-1111-4111-8111-111111111111','collected_at':'2026-10-20T12:00:00Z','elapsed_ms':950,'checks':checks}


def main():
    p=argparse.ArgumentParser(); p.add_argument('--output',type=Path,required=True); p.add_argument('--theme',choices=['dark','light'],default='dark'); p.add_argument('--section',choices=['Overview','Protection','Software','AI','Diagnostics','Activity'],default='Overview'); a=p.parse_args()
    QQuickStyle.setStyle('Fusion')
    app=QGuiApplication([])
    palette=app.palette()
    dark=a.theme=='dark'
    for role,color in [(QPalette.Window,'#171d24' if dark else '#edf1f5'),(QPalette.Base,'#202933' if dark else '#ffffff'),(QPalette.Text,'#eef2f6' if dark else '#17212b'),(QPalette.WindowText,'#eef2f6' if dark else '#17212b'),(QPalette.Button,'#293541' if dark else '#dce5ed'),(QPalette.ButtonText,'#eef2f6' if dark else '#17212b')]: palette.setColor(role,QColor(color))
    app.setPalette(palette)
    with tempfile.TemporaryDirectory() as d:
        base=Path(d); stubs(base,a.theme)
        view=QQuickView(); view.engine().addImportPath(str(base)); view.setColor(QColor('#171d24' if dark else '#edf1f5'))
        view.setResizeMode(QQuickView.SizeRootObjectToView); view.resize(1020,700)
        view.setSource(QUrl.fromLocalFile(str(ROOT/'Panel.qml')))
        if view.status()==QQuickView.Error: raise RuntimeError('QML component load failed')
        root=view.rootObject()
        QMetaObject.invokeMethod(root,'open')
        QMetaObject.invokeMethod(root,'receive',Qt.DirectConnection,Q_ARG('QVariant',json.dumps(fixture())))
        view.show()
        errors=[]
        def verify():
            try:
                from PySide6.QtQml import QQmlComponent
                probe = QQmlComponent(view.engine())
                probe.setData(b'import QtQuick; import qs.Commons as Commons; QtObject { property var palette: Commons.Color }', QUrl())
                holder = probe.create()
                colors = holder.property('palette')
                original = {key: colors.property(key) for key in ('background', 'foreground', 'accent', 'urgent')}
                before_surface = root.property('surface')
                for bg, fg, accent in [('#281a35', '#e6daf3', '#ca83f0'), ('#faf2df', '#302416', '#765020')]:
                    for key, value in [('background', bg), ('foreground', fg), ('accent', accent), ('urgent', '#b03545')]:
                        colors.setProperty(key, QColor(value))
                    app.processEvents()
                    for role, expected in [('canvas', bg), ('ink', fg)]:
                        if root.property(role).name() != expected:
                            raise RuntimeError('live theme binding failed: ' + role + ' actual=' + root.property(role).name() + ' expected=' + expected + ' singleton=' + colors.property('background').name())
                    for foreground_role in ('ink', 'muted', 'accent', 'amber', 'aiAnswerInk', 'aiBriefInk'):
                        for background_role in ('canvas', 'surface', 'rail'):
                            def luminance(color):
                                values=[color.redF(),color.greenF(),color.blueF()]
                                values=[v/12.92 if v<=0.04045 else ((v+0.055)/1.055)**2.4 for v in values]
                                return sum(a*b for a,b in zip(values,(0.2126,0.7152,0.0722)))
                            x,y=luminance(root.property(foreground_role)),luminance(root.property(background_role))
                            if (max(x,y)+0.05)/(min(x,y)+0.05)<4.5:
                                raise RuntimeError('native palette text contrast: '+foreground_role+' / '+background_role)
                    if root.property('surface') == before_surface:
                        raise RuntimeError('surface did not follow live theme')
                    before_surface = root.property('surface')
                for key, value in original.items(): colors.setProperty(key, value)
                app.processEvents()
                if root.property('attentionCount')!=2: raise RuntimeError('UI count mismatch')
                snapshot=fixture()
                explanations={'scan_id':snapshot['scan_id'],'provider':'Synthetic fixture','explanations':[{'check_id':c['check_id'],'meaning':'First scan explanation.','action':'Choose an appropriate next step.','verification':'Check the result.'} for c in snapshot['checks']]}
                QMetaObject.invokeMethod(root,'receiveExplanations',Qt.DirectConnection,Q_ARG('QVariant',json.dumps(explanations)))
                if len(root.property('findingExplanations').toVariant())!=5: raise RuntimeError('inline explanations missing')
                snapshot['scan_id']='22222222-2222-4222-8222-222222222222'
                QMetaObject.invokeMethod(root,'receive',Qt.DirectConnection,Q_ARG('QVariant',json.dumps(snapshot)))
                if root.property('findingExplanations').toVariant(): raise RuntimeError('new scan kept stale answers')
                QMetaObject.invokeMethod(root,'receiveExplanations',Qt.DirectConnection,Q_ARG('QVariant',json.dumps(explanations)))
                if root.property('findingExplanations').toVariant(): raise RuntimeError('stale answer accepted')
                explanations['scan_id']=snapshot['scan_id']
                for row in explanations['explanations']:row['meaning']='Fresh explanation for the second scan.'
                QMetaObject.invokeMethod(root,'receiveExplanations',Qt.DirectConnection,Q_ARG('QVariant',json.dumps(explanations)))
                if root.property('findingExplanations').toVariant()['network.listeners']['meaning']!='Fresh explanation for the second scan.':raise RuntimeError('fresh inline answer missing')

                software={'schema':2,'observed_at':'2026-10-21T15:00:00Z','checked_at':'2026-10-21T14:55:00Z','fresh':True,'update_channels':{'mise':'available'},'advisory_status':'available','limits':[], 'items':[
                    {'name':'claude','installed':'2.1.303','available':'2.1.304','source':'mise','status':'update available','advisories':[]},
                    {'name':'node','installed':'24.22.0','available':'24.22.1','source':'mise','status':'update available','advisories':[]},
                    {'name':'codex','installed':'0.163.0','available':None,'source':'mise','status':'no listed update','advisories':[]},
                    {'name':'python','installed':'3.14.8','available':None,'source':'mise','status':'installed version','advisories':[]},
                    {'name':'ruff','installed':'0.17.0','available':None,'source':'uv tool','status':'manager review','advisories':[]}]}
                for item in software['items']:
                    item.update(active=True, next_step='Review this tool through its original package manager, then verify its version.')
                root.setProperty('operation','software')
                QMetaObject.invokeMethod(root,'receive',Qt.DirectConnection,Q_ARG('QVariant',json.dumps(software)))
                QMetaObject.invokeMethod(root,'receiveAdvice',Qt.DirectConnection,Q_ARG('QVariant',json.dumps({'brief':'Question: What should I address first?\n\nSynthetic preview findings. No AI request was made.'})))
                root.setProperty('aiOperation','ask')
                QMetaObject.invokeMethod(root,'receiveAdvice',Qt.DirectConnection,Q_ARG('QVariant',json.dumps({'answer':'Preview response — no AI request was made.\n\nStart with the home directory permissions. Confirm whether this folder is intentionally shared, review the required access, then use the reviewed permission change if appropriate.\n\nVerify by running a fresh scan.\n\nThe listening socket needs context: identify the owning application and whether its network scope is intended before changing anything.'})))
                if root.property('aiAnswer').find('Preview response') < 0: raise RuntimeError('AI response display failed')
                if a.section == 'AI':
                    root.setProperty('agentName','Codex · signed in')
                    root.setProperty('aiMessage','Preview · no agent request was made')
                from PySide6.QtCore import QObject
                for process in root.findChildren(QObject):
                    if process.metaObject().indexOfProperty('running') >= 0:
                        process.setProperty('running', False)
                root.setProperty('selected',a.section)
                app.processEvents()
                response = root.findChild(QObject, 'advisorResponseText')
                if response is None or response.property('color') != root.property('aiAnswerInk'):
                    raise RuntimeError('AI answer text did not use its distinct color')
                root.setProperty('showBrief', True)
                app.processEvents()
                if response.property('color') != root.property('aiBriefInk'):
                    raise RuntimeError('Brief text did not use its distinct color')
                if root.property('aiAnswerInk') == root.property('aiBriefInk'):
                    raise RuntimeError('Brief and answer colors must differ')
                root.setProperty('showBrief', False)
                app.processEvents()
                a.output.parent.mkdir(parents=True,exist_ok=True)
                if not view.grabWindow().save(str(a.output)): raise RuntimeError('render failed')
                old=root.property('scanTime')
                QMetaObject.invokeMethod(root,'receive',Qt.DirectConnection,Q_ARG('QVariant','not json'))
                if root.property('scanTime')!=old or 'Invalid engine response' not in root.property('message'): raise RuntimeError('error state failed')
                root.setProperty('operation','scan')
                root.setProperty('repairFollowUp', {'check_id':'security.home.permissions','verified':True})
                QMetaObject.invokeMethod(root,'receive',Qt.DirectConnection,Q_ARG('QVariant','invalid scan'))
                if root.property('repairScanState') != 'unknown': raise RuntimeError('bad follow-up scan claimed success')
                root.setProperty('repairFollowUp', {'check_id':'security.home.permissions','verified':True})
                QMetaObject.invokeMethod(root,'markRepairUnknown')
                if root.property('repairScanState') != 'unknown': raise RuntimeError('cancelled follow-up scan claimed success')

                # Inert processes never emit exits: settle fixture status jobs explicitly.
                from PySide6.QtCore import QObject
                for process in root.findChildren(QObject):
                    if process.metaObject().indexOfProperty('running') >= 0:
                        process.setProperty('running', False)
                # Exercise one-click prepare -> ask using mock Process only; no agent runs.
                QMetaObject.invokeMethod(root,'askAgent')
                if not root.property('askAfterBrief'): raise RuntimeError('one-click agent request did not prepare')
                QMetaObject.invokeMethod(root,'receiveAdvice',Qt.DirectConnection,Q_ARG('QVariant',json.dumps({'brief':'Question: synthetic context'})))
                # QObject lookup is used because Process is a mock QtObject.
                from PySide6.QtCore import QObject
                request = root.findChild(QObject, 'advisorRequest')
                if request is None: raise RuntimeError('advisor process missing')
                request.setProperty('running',False)
                QMetaObject.invokeMethod(request,'exited',Qt.DirectConnection,Q_ARG(int,0),Q_ARG(int,0))
                app.processEvents()
                if root.property('aiOperation') != 'ask' or root.property('askAfterBrief'): raise RuntimeError('one-click agent handoff failed')
                if '--send' not in request.property('command').toVariant(): raise RuntimeError('explicit agent send missing')
                request.setProperty('running',False)
                QMetaObject.invokeMethod(root,'refreshSoftware')
                refresh_request = root.findChild(QObject, 'refreshRequest')
                if refresh_request is None or not refresh_request.property('running'): raise RuntimeError('in-panel refresh did not start')
                command = refresh_request.property('command').toVariant()
                if '--allow-network' not in command or 'foot' in command: raise RuntimeError('refresh still relies on terminal')
                refresh_request.setProperty('running',False)
                root.setProperty('operation','software')
                QMetaObject.invokeMethod(root,'receive',Qt.DirectConnection,Q_ARG('QVariant',json.dumps(software)))
                if root.property('softwareUpdates') != 2: raise RuntimeError('refreshed inventory not displayed')
                for section in ('Overview','Protection','Software','AI','Diagnostics','Activity'):
                    root.setProperty('selected',section); app.processEvents()
                QMetaObject.invokeMethod(root,'close')
                if root.property('opened'): raise RuntimeError('close lifecycle failed')
                print('Mock shell QML: load, scan display, invalid response retention, sections, close and render passed.')
            except Exception as error:
                errors.append(str(error))
            finally: app.quit()
        QTimer.singleShot(600,verify); app.exec()
        view.setSource(QUrl()); app.processEvents()
        if errors: raise RuntimeError('; '.join(errors))
    return 0

if __name__=='__main__': raise SystemExit(main())
