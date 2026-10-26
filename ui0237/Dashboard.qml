import QtQuick
import Quickshell.Io
import qs.Ui as Ui

Ui.BarWidget {
    id: root
    moduleName: "com.zerodaysecurity.ironclad"
    readonly property bool opened: details.opened
    readonly property bool popoutSwitchClosing: details.popoutSwitchClosing
    function open() { details.open() }
    function close() { details.close() }
    function togglePanel() { details.toggle() }
    function closeForPopoutSwitch() { details.closeForPopoutSwitch() }
    readonly property real openPanelIndicatorWidth: button.labelWidth
    implicitWidth: button.implicitWidth
    implicitHeight: button.implicitHeight
    Ui.WidgetButton {
        id: button
        anchors.fill: parent
        bar: root.bar
        text: root.vertical ? "IC" : (details.busy ? "Ironclad …" : details.results.length ? "Ironclad · " + details.attentionCount : "Ironclad")
        onPressed: function(b) { if (b === Qt.LeftButton) root.togglePanel() }
    }
    IpcHandler {
        target: root.moduleName
        function open(): void { root.open() }
        function close(): void { root.close() }
        function toggle(): void { root.togglePanel() }
        function scan(profile: string): void {
            if (profile !== "quick" && profile !== "full" && profile !== "super") return
            details.profile = profile
            details.scan()
        }
        function section(name: string): void {
            if (details.sections.indexOf(name) < 0) return
            details.navigate(name)
        }
        function evidence(checkId: string): void {
            if (details.results.some(c => c.check_id === checkId)) details.expandedCheckId = checkId
        }
        function historyOptIn(enabled: bool): void { details.remember = enabled }
        function reviewBaseline(): void { details.reviewAction("baseline.replace") }
        function reportDialog(): void { details.chooseReport() }
        function reviewFix(checkId: string): void { details.reviewFix(checkId) }
        function dismissFix(): void { details.dismissFix() }
        function fixStatus(): string {
            return JSON.stringify({stage: details.fixStage, checkId: details.fixCheckId, plans: details.fixPlans.length, title: details.fixPlan ? details.fixPlan.title : null, message: details.fixMessage})
        }
        function reviewUpdate(target: string): void { details.reviewUpdate(target) }
        function selectUpdate(target: string): void {
            if (details.softwareData.items.some(i => i.source + ":" + i.name === target)) details.toggleTool(target)
        }
        function reviewSelectedUpdates(): void { details.reviewSelected() }
        function clearUpdateSelection(): void { if (!details.busy) details.selectedTools = [] }
        function dismissUpdate(): void { details.dismissUpdate() }
        function updateStatus(): string {
            return JSON.stringify({stage: details.updateStage, target: details.updatePlan ? details.updatePlan.target : null, message: details.updateMessage})
        }
        function softwareStatus(): string {
            return JSON.stringify({fresh: details.softwareData.fresh, configuredUpdates: details.softwareUpdates,
                security: details.softwareSecuritySummary, mode: details.softwareMode,
                affected: details.softwareData.items.filter(i => i.advisories.length > 0).map(i => ({name:i.name, installed:i.installed,
                    scope:i.version_scope, configured:i.configured_versions || [], fixes:i.security_fixed_versions || []}))})
        }
        function refreshSoftware(): void { details.refreshSoftware() }
        function prepareBrief(): void { details.requestBrief() }
        function explanationStatus(): string {
            return JSON.stringify({busy: details.explanationBusy, count: Object.keys(details.findingExplanations).length, findings: details.results.length, provider: details.explanationProvider, message: details.explanationMessage})
        }
        function advisorStatus(): string {
            return JSON.stringify({agent: details.agentName, busy: details.aiBusy, briefCharacters: details.aiBrief.length, answerCharacters: details.aiAnswer.length, message: details.aiMessage})
        }
        function status(): string {
            return JSON.stringify({version: "0.2.37", opened: root.opened, busy: details.busy, checks: details.results.length, section: details.selected, scanTime: details.scanTime, scanStatus: details.scanStatus, scanEnabled: details.scanControlEnabled, scanFocused: details.scanControlFocused, message: details.message})
        }
    }
    Workspace {
        id: details
        bar: root.bar
        settings: root.settings
        anchorItem: button
        hostWidget: root
    }
}
