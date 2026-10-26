pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "State.js" as Model

ScrollView {
    id: root
    property var checks: []
    property var ignored: []
    property var software: ({items: [], fresh: false})
    readonly property var softwareSecurity: Model.softwareSecurity(software.items)
    property var capability: null
    property var monitor: null
    property string scanTime: "No scan yet"
    property bool working: false
    property bool preferenceWorking: false
    property color ink
    property color muted
    property color accent
    property color accentInk
    property color surface
    property color rail
    property color line
    property color urgent
    readonly property var priorities: Model.overviewFindings(checks, ignored)
    readonly property var health: Model.overviewHealth(capability, monitor)
    readonly property int pending: Model.filtered(checks, "Overview", "", false).filter(c => ignored.indexOf(c.check_id) < 0).length
    signal protectionRequested()
    signal diagnosticsRequested()
    signal findingRequested(string checkId)
    signal ignoreRequested(string checkId)
    signal scanRequested()
    signal securityRequested()
    signal softwareCheckRequested()
    signal fileRequested()
    signal updatesRequested()
    signal adviceRequested()
    clip: true
    contentWidth: availableWidth - 12
    ScrollBar.vertical.policy: ScrollBar.AlwaysOn
    component Label: BodyText { color: root.ink; Layout.minimumWidth: 0 }
    component Button: ControlButton {
        ink: root.ink; muted: root.muted; accent: root.accent; accentInk: root.accentInk
        surface: root.surface; rail: root.rail; line: root.line
    }
    ColumnLayout {
        width: Math.max(0, root.availableWidth - 12); spacing: 18
        Rectangle {
            objectName: "overviewSoftwareSecurity"
            Layout.fillWidth: true; implicitHeight: securityBody.implicitHeight + 28
            color: root.surface; radius: 9; border.color: root.softwareSecurity.total ? root.urgent : root.line
            ColumnLayout {
                id: securityBody
                anchors { left: parent.left; right: parent.right; top: parent.top; margins: 14 }
                spacing: 8
                Label { text: root.softwareSecurity.total ? root.softwareSecurity.text : "Software security"; Layout.fillWidth: true; font.weight: Font.DemiBold; color: root.softwareSecurity.total ? root.urgent : root.ink }
                Label { text: root.softwareSecurity.total ? "Retained toolchains can still be selected by projects. Zero configured-tool updates does not mean no security notices." : root.software.fresh && root.software.advisory_status === "available" ? "No advisory matched the evaluated versions. Unsupported software remains outside coverage." : "Software advisories have not been freshly verified. Local diagnostics do not perform an online vulnerability check."; Layout.fillWidth: true; color: root.muted }
                Label { text: root.software.checked_at ? "Software last checked: " + Model.displayTime(root.software.checked_at) + (root.software.fresh ? "" : " · refresh needed") : "Software check: not yet verified"; color: root.muted; Layout.fillWidth: true }
                Flow {
                    Layout.fillWidth: true; spacing: 8
                    Button { objectName: "overviewSecurityReviewButton"; text: "Review software security"; onClicked: root.securityRequested() }
                    Button { objectName: "overviewSoftwareCheckButton"; text: "Check software online"; enabled: !root.working; onClicked: root.softwareCheckRequested() }
                }
                Label { text: "Online check: configured tool sources, package names/versions to OSV and the public CISA catalog. No files uploaded or software installed."; Layout.fillWidth: true; color: root.muted }
            }
        }
        Label { text: "Protection at a glance"; font.pixelSize: 17; font.weight: Font.DemiBold; Layout.fillWidth: true }
        GridLayout {
            columns: 2
            Layout.fillWidth: true; columnSpacing: 10; rowSpacing: 10
            Repeater {
                model: root.health
                delegate: Rectangle {
                    id: healthCard
                    required property var modelData
                    Layout.fillWidth: true; Layout.preferredWidth: 1; Layout.minimumWidth: 0
                    implicitHeight: healthBody.implicitHeight + 28
                    color: root.surface; radius: 9; border.color: modelData.warning ? root.urgent : root.line
                    ColumnLayout {
                        id: healthBody
                        anchors { left: parent.left; right: parent.right; top: parent.top; margins: 14 }
                        spacing: 7
                        Label { text: healthCard.modelData.label; color: root.muted; font.pixelSize: 13; Layout.fillWidth: true }
                        Label { objectName: "overviewHealth_" + healthCard.modelData.id; text: healthCard.modelData.value; color: healthCard.modelData.warning ? root.urgent : root.ink; font.pixelSize: 16; font.weight: Font.DemiBold; Layout.fillWidth: true }
                        Label { text: healthCard.modelData.detail; color: root.muted; font.pixelSize: 13; Layout.fillWidth: true }
                    }
                }
            }
        }
        Button { objectName: "overviewProtectionButton"; text: "Open protection & updates"; onClicked: root.protectionRequested() }
        Label { text: "Needs your review"; font.pixelSize: 17; font.weight: Font.DemiBold; Layout.fillWidth: true }
        Label { text: !root.checks.length ? "Run a diagnostic scan to see suggested actions." : root.pending ? root.pending + " findings need review. Showing the first " + root.priorities.length + " by severity." : "No unignored findings need action in this scan. Coverage limits remain in Diagnostics."; color: root.muted; Layout.fillWidth: true }
        Repeater {
            model: root.priorities
            delegate: Rectangle {
                id: priority
                required property var modelData
                Layout.fillWidth: true; implicitHeight: priorityBody.implicitHeight + 24
                color: root.surface; radius: 9; border.color: root.line
                RowLayout {
                    id: priorityBody
                    anchors { left: parent.left; right: parent.right; top: parent.top; margins: 12 }
                    spacing: 10
                    ColumnLayout {
                        Layout.fillWidth: true; spacing: 7
                        Label { text: Model.findingTitle(priority.modelData); font.weight: Font.DemiBold; maximumLineCount: 2; elide: Text.ElideRight; Layout.fillWidth: true }
                        Label { text: priority.modelData.severity + " priority · " + priority.modelData.status + " · " + Model.section(priority.modelData.check_id); color: root.muted; font.pixelSize: 13; Layout.fillWidth: true }
                    }
                    Button { objectName: "overviewReview_" + priority.modelData.check_id; text: "Review"; onClicked: root.findingRequested(priority.modelData.check_id) }
                    Button { objectName: "overviewIgnore_" + priority.modelData.check_id; text: "Ignore"; enabled: !root.preferenceWorking; onClicked: root.ignoreRequested(priority.modelData.check_id) }
                }
            }
        }
        Flow {
            Layout.fillWidth: true; spacing: 8
            Button { objectName: "overviewScanFileButton"; text: "Scan a file"; onClicked: root.fileRequested() }
            Button { objectName: "overviewUpdatesButton"; text: "Protection updates"; onClicked: root.updatesRequested() }
            Button { objectName: "overviewAdviceButton"; text: "Ask your AI"; onClicked: root.adviceRequested() }
        }
        Flow {
            Layout.fillWidth: true; spacing: 8
            Button { objectName: "overviewDiagnosticsButton"; text: "All findings & ignored items"; onClicked: root.diagnosticsRequested() }
            Button { visible: !root.checks.length; text: "Run first scan"; enabled: !root.working; onClicked: root.scanRequested() }
        }
        Label { text: "Diagnostics checked: " + Model.displayTime(root.scanTime) + ". Ignoring a finding does not repair it. Status and coverage do not prove the machine is free of threats."; color: root.muted; font.pixelSize: 13; Layout.fillWidth: true; lineHeight: 1.35 }
        Item { implicitHeight: 4 }
    }
}
