pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
    id: root
    property var stateData: null
    property var review: null
    property string stage: "idle"
    property string message: ""
    property bool working: false
    property color ink
    property color muted
    property color accent
    property color accentInk
    property color surface
    property color rail
    property color line
    property color urgent
    property bool showReviewed: false
    signal changeRequested(string action)
    signal approved()
    signal dismissed()
    signal refreshRequested()
    signal reviewed(string identifier)
    signal adviceRequested(string ruleId)
    implicitHeight: body.implicitHeight + 32
    radius: 11; color: surface; border.color: line
    component Label: BodyText { color: root.ink; Layout.minimumWidth: 0 }
    component Button: ControlButton {
        ink: root.ink; muted: root.muted; accent: root.accent; accentInk: root.accentInk
        surface: root.surface; rail: root.rail; line: root.line
    }
    ColumnLayout {
        id: body
        anchors.left: parent.left; anchors.right: parent.right; anchors.top: parent.top
        anchors.margins: 16; spacing: 12
        RowLayout {
            Layout.fillWidth: true
            Label { text: "Live protection"; font.pixelSize: 19; font.weight: Font.DemiBold; Layout.fillWidth: true }
            Label { objectName: "monitorStateLabel"; text: !root.stateData ? "Checking" : root.stateData.state === "monitoring" ? "Monitoring" : root.stateData.state === "degraded" ? "Coverage needs review" : root.stateData.state === "not_installed" ? "Not enabled" : root.stateData.state.replace(/_/g, " "); color: root.stateData && root.stateData.state === "monitoring" ? root.accent : root.stateData && root.stateData.state === "degraded" ? root.urgent : root.muted }
        }
        Label { text: root.stateData ? root.stateData.message : "Checking the embedded sensor. No monitoring coverage is assumed yet."; Layout.fillWidth: true; lineHeight: 1.35 }
        Label { text: "Falco runs behind Ironclad and watches for selected suspicious system activity. It can flag persistence, authentication changes, kernel modules and memory-backed execution. Legitimate updates can trigger alerts too."; color: root.muted; Layout.fillWidth: true; lineHeight: 1.35 }
        Flow {
            Layout.fillWidth: true; spacing: 8
            Button { objectName: "enableMonitorButton"; text: root.stateData && root.stateData.installed ? "Start monitoring" : "Enable monitoring"; primary: true; visible: !!root.stateData && !root.stateData.monitoring && root.stateData.compatible && root.stateData.owner_match; onClicked: root.changeRequested("enable") }
            Button { objectName: "updateMonitorButton"; text: "Review bundled sensor update…"; visible: !!root.stateData && root.stateData.installed && root.stateData.update_available === true && root.stateData.owner_match; onClicked: root.changeRequested("enable") }
            Button { objectName: "stopMonitorButton"; text: "Stop monitoring"; visible: !!root.stateData && root.stateData.installed && root.stateData.owner_match && root.stateData.state !== "stopped"; onClicked: root.changeRequested("disable") }
            Button { objectName: "removeMonitorButton"; text: "Remove sensor"; visible: !!root.stateData && root.stateData.installed && root.stateData.owner_match; onClicked: root.changeRequested("remove") }
            Button { objectName: "refreshMonitorButton"; text: "Check status"; onClicked: root.refreshRequested() }
        }
        Flow {
            Layout.fillWidth: true; spacing: 8
            Button { objectName: "falcoDocsButton"; text: "Falco documentation ↗"; onClicked: Qt.openUrlExternally("https://falco.org/docs/") }
            Button { objectName: "falcoHelpButton"; text: "Falco troubleshooting ↗"; onClicked: Qt.openUrlExternally("https://falco.org/docs/troubleshooting/") }
        }
        Label { text: "Official Falco guides · opens in your browser"; color: root.muted; font.pixelSize: 13; Layout.fillWidth: true }
        Rectangle {
            visible: root.stage !== "idle"
            Layout.fillWidth: true; implicitHeight: reviewBody.implicitHeight + 24
            radius: 8; color: root.rail; border.color: root.line
            ColumnLayout {
                id: reviewBody
                anchors.left: parent.left; anchors.right: parent.right; anchors.top: parent.top; anchors.margins: 12; spacing: 10
                Label { text: root.stage === "preparing" ? "Preparing the component…" : root.stage === "applying" ? "Applying your reviewed change…" : root.stage === "review" ? "Review monitoring change" : "Monitoring result"; font.weight: Font.DemiBold; Layout.fillWidth: true }
                Label { text: root.message; Layout.fillWidth: true; lineHeight: 1.4 }
                Label { visible: !!root.review; text: root.review ? root.review.impact + "\n\n" + root.review.recovery : ""; Layout.fillWidth: true; lineHeight: 1.4 }
                Label { visible: root.stage === "review"; text: "The OS will ask you to authenticate when needed. Only Ironclad’s sensor component and service are changed. No terminal or separate dashboard opens."; color: root.muted; Layout.fillWidth: true }
                RowLayout {
                    Button { objectName: "approveMonitorButton"; visible: root.stage === "review"; text: "Approve change"; primary: true; onClicked: root.approved() }
                    Button { objectName: "dismissMonitorButton"; text: root.stage === "review" ? "Cancel" : "Close"; visible: root.stage !== "applying" && root.stage !== "preparing"; onClicked: root.dismissed() }
                }
            }
        }
        Label { visible: !!root.stateData && !!root.stateData.metrics; text: root.stateData && root.stateData.metrics ? "Kernel events observed: " + root.stateData.metrics.events + "   ·   Dropped: " + root.stateData.metrics.kernel_drops + " kernel / " + root.stateData.metrics.output_drops + " output" : ""; color: root.muted; Layout.fillWidth: true }
        Label { objectName: "asyncMonitorHealthLabel"; visible: !!root.stateData && !!root.stateData.metrics; text: root.stateData && root.stateData.metrics ? "Async reader: " + (root.stateData.metrics.async_reader === "1" ? "running" : "unverified") + "   ·   Events: " + (root.stateData.metrics.async_events || "0") + "   ·   Emitted: " + (root.stateData.metrics.async_emitted || "0") + "   ·   Pending: " + (root.stateData.metrics.async_pending || "0") + "   ·   Processing errors: " + (root.stateData.metrics.async_errors || "0") : ""; color: root.stateData && root.stateData.metrics && root.stateData.metrics.async_reader === "1" && root.stateData.metrics.async_errors === "0" ? root.muted : root.urgent; Layout.fillWidth: true }
        Label { visible: !!root.stateData && root.stateData.installed; text: root.stateData ? root.stateData.unreviewed + " alerts to review" : "Alerts"; font.weight: Font.DemiBold; Layout.fillWidth: true }
        CheckBox { visible: !!root.stateData && root.stateData.alerts.length > 0; objectName: "showReviewedMonitorToggle"; text: "Include reviewed alerts"; checked: root.showReviewed; onToggled: root.showReviewed = checked; palette.windowText: root.ink; enabled: !root.working }
        Label { visible: !!root.stateData && root.stateData.installed && root.stateData.alerts.filter(a => !a.reviewed || root.showReviewed).length === 0; text: "No alerts in this view. That does not prove the machine is free of malware or unknown threats."; color: root.muted; Layout.fillWidth: true }
        Repeater {
            model: root.stateData ? root.stateData.alerts.filter(a => !a.reviewed || root.showReviewed) : []
            delegate: Rectangle {
                id: alert
                required property var modelData
                Layout.fillWidth: true; implicitHeight: alertBody.implicitHeight + 24
                radius: 8; color: root.rail; border.color: root.line
                ColumnLayout {
                    id: alertBody
                    anchors.left: parent.left; anchors.right: parent.right; anchors.top: parent.top; anchors.margins: 12; spacing: 8
                    Label { text: alert.modelData.title + (alert.modelData.reviewed ? " · reviewed" : ""); font.weight: Font.DemiBold; Layout.fillWidth: true }
                    Label { text: alert.modelData.time + " · " + alert.modelData.app; color: root.muted; font.pixelSize: 13; Layout.fillWidth: true }
                    Label { text: alert.modelData.meaning; Layout.fillWidth: true; lineHeight: 1.35 }
                    Label { text: "What to do: " + alert.modelData.action; Layout.fillWidth: true; lineHeight: 1.35 }
                    Label { text: "Verify: " + alert.modelData.verify; color: root.muted; Layout.fillWidth: true; lineHeight: 1.35 }
                    Flow {
                        Layout.fillWidth: true; spacing: 8
                        Button { objectName: "reviewMonitor_" + alert.modelData.id; text: "Mark reviewed"; visible: !alert.modelData.reviewed; onClicked: root.reviewed(alert.modelData.id) }
                        Button { objectName: "askMonitor_" + alert.modelData.id; text: "Ask your AI"; onClicked: root.adviceRequested(alert.modelData.rule_id) }
                    }
                }
            }
        }
        Label { text: (root.stateData ? root.stateData.rules_count : "Unverified") + " detection rules, no automatic blocking or quarantine. The sensor runs while Ironclad is closed. Its last 256 alerts stay in a private local feed; this view shows the newest 64. Reviewing an alert does not fix its cause. Unknown threats can be missed."; color: root.muted; font.pixelSize: 13; Layout.fillWidth: true; lineHeight: 1.35 }
        Label { text: "Supported asynchronous checks cover io_uring OPENAT, OPENAT2 and direct opens of the watched policy locations. Other asynchronous operations and unknown threats can still be missed. A running reader is required for verified monitoring."; color: root.muted; Layout.fillWidth: true }
        Label { visible: !!root.stateData && root.stateData.limits.length > 0; text: root.stateData ? root.stateData.limits.join("\n") : ""; color: root.urgent; Layout.fillWidth: true }
    }
}
