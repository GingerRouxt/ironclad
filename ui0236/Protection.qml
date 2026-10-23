pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "State.js" as Model

ScrollView {
    id: root
    property var software: ({items: [], fresh: false})
    property var capability: null
    property bool working: false
    property var automaticReview: null
    property string automaticStage: "idle"
    property string automaticMessage: ""
    signal automaticChangeRequested(string action)
    signal automaticApproved()
    signal automaticDismissed()
    signal automaticRefreshRequested()
    signal automaticReviewed(string identifier)
    property int tab: 0
    property var scrollingContent: contentItem
    onTabChanged: if (scrollingContent) scrollingContent.contentY = 0
    property var monitor: null
    property var monitorReview: null
    property string monitorStage: "idle"
    property string monitorMessage: ""
    signal monitorChangeRequested(string action)
    signal monitorApproved()
    signal monitorDismissed()
    signal monitorRefreshRequested()
    signal monitorReviewed(string identifier)
    signal monitorAdviceRequested(string ruleId)
    property color ink
    property color muted
    property color accent
    property color accentInk
    property color surface
    property color rail
    property color line
    property color urgent
    readonly property var risks: Model.protectionRisks(software)
    readonly property int exploited: software.items.reduce((n, i) => n + i.advisories.filter(a => a.known_exploited === true).length, 0)
    readonly property int matched: software.items.reduce((n, i) => n + i.advisories.length, 0)
    readonly property int covered: software.items.filter(i => i.advisory_coverage === "supported").length
    readonly property var scanner: capability ? capability.scanner : null
    readonly property var last: capability ? capability.last_scan : null
    signal adviceRequested()
    signal checkRequested()
    signal chooseRequested()
    signal setupRequested()
    signal signaturesRequested()
    signal automaticUpdatesRequested(bool enabled)
    signal maintenanceRequested()
    readonly property var updates: capability && capability.updates ? capability.updates : null
    signal updateRequested(var item)
    signal softwareRequested()
    contentWidth: Math.max(0, availableWidth - 12)
    clip: true
    ScrollBar.vertical.policy: ScrollBar.AlwaysOn

    component Label: BodyText { color: root.ink; Layout.minimumWidth: 0 }
    component Button: ControlButton {
        ink: root.ink; muted: root.muted; accent: root.accent; accentInk: root.accentInk
        surface: root.surface; rail: root.rail; line: root.line
    }
    component Metric: Rectangle {
        id: metric
        property string value
        property string title
        property string detail
        property bool alert: false
        Layout.fillWidth: true
        Layout.minimumWidth: 0
        Layout.preferredWidth: 1
        implicitHeight: 106
        color: root.surface
        radius: 9
        ColumnLayout {
            anchors.fill: parent; anchors.margins: 14; spacing: 6
            Label { text: metric.title; color: root.muted; font.pixelSize: 13 }
            Label { text: metric.value; color: metric.alert ? root.urgent : root.ink; font.pixelSize: 25; font.weight: Font.DemiBold }
            Label { text: metric.detail; color: root.muted; font.pixelSize: 13; Layout.fillWidth: true }
        }
    }
    ColumnLayout {
        width: Math.max(0, root.availableWidth - 12)
        spacing: 18
        Flow {
            Layout.fillWidth: true; spacing: 8
            Repeater {
                model: [{label:"Monitoring", value:0}, {label:"Automatic malware", value:5}, {label:"One-off scan", value:1}, {label:"Updates", value:2}, {label:"Software risks", value:3}, {label:"Help", value:4}]
                delegate: Button {
                    required property var modelData
                    objectName: "protectionTab_" + modelData.value
                    text: modelData.label; primary: root.tab === modelData.value
                    Accessible.name: modelData.label + (root.tab === modelData.value ? ", selected" : "")
                    onClicked: root.tab = modelData.value
                }
            }
        }
        ColumnLayout {
            visible: root.tab === 0
            Layout.fillWidth: true; spacing: 18
        Monitoring {
            objectName: "monitorView"
            Layout.fillWidth: true
            stateData: root.monitor; review: root.monitorReview; stage: root.monitorStage; message: root.monitorMessage; working: root.working
            ink: root.ink; muted: root.muted; accent: root.accent; accentInk: root.accentInk
            surface: root.surface; rail: root.rail; line: root.line; urgent: root.urgent
            onChangeRequested: action => root.monitorChangeRequested(action)
            onApproved: root.monitorApproved()
            onDismissed: root.monitorDismissed()
            onRefreshRequested: root.monitorRefreshRequested()
            onReviewed: identifier => root.monitorReviewed(identifier)
            onAdviceRequested: ruleId => root.monitorAdviceRequested(ruleId)
        }
        }
        ColumnLayout {
            visible: root.tab === 5
            Layout.fillWidth: true; spacing: 18
        AutomaticMalware {
            objectName: "automaticMalwareView"
            stateData: root.capability && root.capability.automatic_malware ? root.capability.automatic_malware : null
            review: root.automaticReview; stage: root.automaticStage; message: root.automaticMessage; working: root.working
            ink: root.ink; muted: root.muted; accent: root.accent; accentInk: root.accentInk
            surface: root.surface; rail: root.rail; line: root.line; urgent: root.urgent
            onChangeRequested: action => root.automaticChangeRequested(action)
            onApproved: root.automaticApproved()
            onDismissed: root.automaticDismissed()
            onRefreshRequested: root.automaticRefreshRequested()
            onReviewed: identifier => root.automaticReviewed(identifier)
        }
        }
        ColumnLayout {
            visible: root.tab === 1
            Layout.fillWidth: true; spacing: 18
        Rectangle {
            Layout.fillWidth: true
            implicitHeight: scanContent.implicitHeight + 32
            color: root.surface; radius: 10; border.color: root.line
            ColumnLayout {
                id: scanContent
                anchors { left: parent.left; right: parent.right; top: parent.top; margins: 16 }
                spacing: 12
                RowLayout {
                    Layout.fillWidth: true
                    Label { text: "One-off file scan"; font.pixelSize: 19; font.weight: Font.DemiBold; Layout.fillWidth: true }
                    Label { objectName: "scannerReadiness"; text: !root.scanner ? "NOT VERIFIED" : root.scanner.ready ? "READY" : root.scanner && root.scanner.installed && root.scanner.sandbox_available !== false ? "SIGNATURES NEEDED" : "SETUP NEEDED"; color: root.accent; font.pixelSize: 13; font.letterSpacing: 1.1 }
                }
                Label { text: root.scanner ? root.scanner.message : "Checking the local scanner…"; Layout.fillWidth: true; color: root.muted }
                Label { text: "ClamAV scans one file you choose, locally. Nothing is deleted, quarantined or uploaded. Hidden folders, common credential files and linked files are excluded."; Layout.fillWidth: true; font.pixelSize: 13; lineHeight: 1.35 }
                Flow {
                    Layout.fillWidth: true; spacing: 8
                    Button { objectName: "chooseMalwareFileButton"; text: "Choose file…"; primary: true; enabled: !!root.scanner && root.scanner.ready && !root.working; onClicked: root.chooseRequested() }
                    Button { objectName: "setupScannerButton"; visible: !root.scanner || !root.scanner.installed || root.scanner.sandbox_available === false; text: "Set up scanner…"; enabled: !root.working; onClicked: root.setupRequested() }
                    Button { objectName: "updateSignaturesButton"; visible: !!root.scanner && root.scanner.installed; text: "Update signatures…"; enabled: !root.working; onClicked: root.signaturesRequested() }
                }
                Flow {
                    Layout.fillWidth: true; spacing: 8
                    Button { objectName: "clamavDocsButton"; text: "ClamAV documentation ↗"; onClicked: Qt.openUrlExternally("https://docs.clamav.net/manual/Usage.html") }
                    Button { objectName: "clamavSignaturesHelpButton"; text: "Signature update help ↗"; onClicked: Qt.openUrlExternally("https://docs.clamav.net/manual/Usage/SignatureManagement.html") }
                }
                Label { text: "Official ClamAV guides · opens in your browser"; color: root.muted; font.pixelSize: 13; Layout.fillWidth: true }
                Label { visible: !!root.scanner && !!root.scanner.signatures_at; text: root.scanner && root.scanner.signatures_at ? "Signature files modified " + new Date(root.scanner.signatures_at).toLocaleString() : ""; color: root.muted; Layout.fillWidth: true; font.pixelSize: 13 }
                ColumnLayout {
                    visible: !!root.last
                    Layout.fillWidth: true; spacing: 8
                    Rectangle { Layout.fillWidth: true; implicitHeight: 1; color: root.line }
                    Label { objectName: "lastMalwareOutcome"; text: !root.last ? "" : root.last.outcome === "detected" ? "File flagged" : root.last.outcome === "no_detection" ? "No detection in the last file" : "Last scan incomplete"; font.weight: Font.DemiBold; color: root.last && root.last.outcome === "detected" ? root.urgent : root.ink }
                    Label { text: root.last ? root.last.name + " · " + new Date(root.last.finished_at).toLocaleString() : ""; color: root.muted; Layout.fillWidth: true; font.pixelSize: 13 }
                    Label { text: root.last ? root.last.message : ""; Layout.fillWidth: true; lineHeight: 1.35 }
                    Label { visible: !!root.last && root.last.detections.length > 0; text: root.last ? root.last.detections.join("\n") : ""; Layout.fillWidth: true; color: root.urgent; font.pixelSize: 13 }
                }
                Label { visible: !!root.capability && root.capability.limits.length > 0; text: root.capability ? root.capability.limits.join("\n") : ""; Layout.fillWidth: true; color: root.urgent; font.pixelSize: 13 }
            }
        }
        }
        ColumnLayout {
            visible: root.tab === 2
            Layout.fillWidth: true; spacing: 18
        Rectangle {
            Layout.fillWidth: true
            implicitHeight: updateHealth.implicitHeight + 32
            color: root.surface; radius: 9; border.color: root.updates && root.updates.issues.length ? root.urgent : root.line
            ColumnLayout {
                id: updateHealth
                anchors { left: parent.left; right: parent.right; top: parent.top; margins: 16 }
                spacing: 9
                Label { objectName: "protectionUpdateHeading"; text: "Protection maintenance"; font.pixelSize: 17; font.weight: Font.DemiBold }
                Label { objectName: "automaticUpdateStatus"; text: !root.updates ? "Update health has not been verified." : root.updates.automatic ? "Automatic updates are enabled" : "Automatic updates are off or unavailable"; color: !root.updates ? root.muted : root.updates.issues.length ? root.urgent : root.ink; Layout.fillWidth: true }
                Label { text: root.updates ? root.updates.issues.join("\n") : "Refresh protection status to check signature maintenance."; visible: !root.updates || root.updates.issues.length > 0; color: root.updates ? root.urgent : root.muted; Layout.fillWidth: true; lineHeight: 1.35 }
                Label { text: root.updates && root.updates.last_success ? "Last successful signature refresh: " + new Date(root.updates.last_success).toLocaleString() : "No successful background signature refresh recorded."; Layout.fillWidth: true; color: root.muted; font.pixelSize: 13 }
                Label { text: "Automatic maintenance contacts ClamAV for official signatures every four hours and GitHub for ClamAV/Falco release versions daily, while your user session is available. No files are uploaded. Engine, rule and plugin code changes require reviewed updates."; Layout.fillWidth: true; font.pixelSize: 13; lineHeight: 1.35 }
                Flow {
                    Layout.fillWidth: true; spacing: 8
                    Button { objectName: "automaticUpdatesButton"; text: root.updates && root.updates.automatic ? "Turn off automatic updates" : "Enable automatic updates"; enabled: !!root.scanner && root.scanner.installed && !root.working; onClicked: root.automaticUpdatesRequested(!(root.updates && root.updates.automatic)) }
                    Button { objectName: "maintainProtectionButton"; text: "Update protection now"; enabled: !!root.scanner && root.scanner.installed && !root.working; onClicked: root.maintenanceRequested() }
                }
                Repeater {
                    model: root.updates ? root.updates.engines : []
                    delegate: Label {
                        required property var modelData
                        text: modelData.name + ": " + (modelData.installed || "not verified") + (modelData.latest ? " · upstream " + modelData.latest : " · upstream not checked") + (modelData.update_available ? " · review update" : "")
                        Layout.fillWidth: true; color: modelData.update_available ? root.urgent : root.muted; font.pixelSize: 13
                    }
                }
                Label { text: root.updates ? "Detection policy " + root.updates.policy_version + " · " + root.updates.plugin_update : ""; Layout.fillWidth: true; font.pixelSize: 13; color: root.muted }
            }
        }
        }
        ColumnLayout {
            visible: root.tab === 3
            Layout.fillWidth: true; spacing: 18
        Rectangle {
            Layout.fillWidth: true
            implicitHeight: hero.implicitHeight + 36
            radius: 11; color: root.surface; border.color: root.line
            ColumnLayout {
                id: hero
                anchors { left: parent.left; right: parent.right; top: parent.top; margins: 18 }
                spacing: 10
                RowLayout {
                    Layout.fillWidth: true
                    Label { text: "Software advisories"; color: root.accent; font.pixelSize: 13; font.letterSpacing: 1.5; Layout.fillWidth: true }
                    Label { text: "On demand"; color: root.muted; font.pixelSize: 13; font.letterSpacing: 1.1 }
                }
                Label { text: root.exploited ? "Put the exploited flaws first." : "Less guesswork. More control."; font.pixelSize: 23; font.weight: Font.DemiBold; Layout.fillWidth: true }
                Label { text: "Prioritize software risks. Check a download before you run it. Every result comes with a next step."; color: root.muted; Layout.fillWidth: true; lineHeight: 1.35 }
                RowLayout {
                    Layout.fillWidth: true
                    Button { objectName: "checkProtectionButton"; text: "Check software risks"; primary: true; enabled: !root.working; onClicked: root.checkRequested() }
                    Button { objectName: "protectionAdviceButton"; text: "Ask your AI"; enabled: !root.working; onClicked: root.adviceRequested() }
                    Label { text: root.software.checked_at ? "Software checked " + new Date(root.software.checked_at).toLocaleString() + (root.software.fresh ? "" : " · refresh needed") : "Software risks haven’t been checked yet."; color: root.muted; font.pixelSize: 13; Layout.fillWidth: true }
                }
            }
        }
        RowLayout {
            Layout.fillWidth: true; spacing: 10
            Metric { title: "Known exploited"; value: root.covered > 0 && root.software.fresh && root.software.advisory_status === "available" && root.software.kev_status === "available" && root.software.advisory_details_status === "available" || root.exploited > 0 ? String(root.exploited) : "—"; detail: "Exact matches to CISA’s catalog"; alert: root.exploited > 0 }
            Metric { title: "Advisories matched"; value: (root.covered > 0 && root.software.advisory_status === "available") || root.risks.length ? String(root.matched) : "—"; detail: root.software.fresh ? "For evaluated installed versions" : "Refresh to check current risk" }
            Metric { title: "Advisory coverage"; value: root.covered + " / " + root.software.items.length; detail: "Inventory entries supported by OSV" }
        }
        Label { text: "Network check: configured mise update sources; supported package names/versions go to api.osv.dev. CISA’s public catalog downloads from raw.githubusercontent.com/cisagov/kev-data. No file contents are uploaded. Ask your AI shares redacted findings and software notices through your signed-in agent."; color: root.muted; font.pixelSize: 13; Layout.fillWidth: true; lineHeight: 1.3 }
        Label { visible: root.software.kev_status === "unavailable" || root.software.advisory_status === "unavailable" || root.software.advisory_details_status === "partial"; text: "Some advisory or exploitation data is unavailable. Coverage is incomplete; existing matches still need review."; color: root.urgent; Layout.fillWidth: true; font.pixelSize: 13 }
        Label { text: "Your next moves"; font.pixelSize: 16; font.weight: Font.DemiBold }
        Label { visible: root.matched > root.risks.length; text: "Showing the first " + root.risks.length + " of " + root.matched + " matches, highest priority first."; color: root.muted; Layout.fillWidth: true; font.pixelSize: 13 }
        Repeater {
            model: root.risks
            delegate: Rectangle {
                id: risk
                required property var modelData
                Layout.fillWidth: true
                implicitHeight: riskContent.implicitHeight + 28
                color: root.surface; radius: 9
                ColumnLayout {
                    id: riskContent
                    anchors { left: parent.left; right: parent.right; top: parent.top; margins: 14 }
                    spacing: 9
                    Label { text: (risk.modelData.advisory.known_exploited ? "KNOWN EXPLOITED  /  " : "ADVISORY  /  ") + risk.modelData.item.name + " " + risk.modelData.item.installed; color: risk.modelData.advisory.known_exploited ? root.urgent : root.accent; font.weight: Font.DemiBold; Layout.fillWidth: true }
                    Label { text: risk.modelData.advisory.summary || "An advisory matches this installed package version. Review the advisory and available update."; Layout.fillWidth: true; lineHeight: 1.35 }
                    Label { text: risk.modelData.advisory.issues.join(" · ") + (risk.modelData.item.active === false ? " · retained version; may still be used" : ""); color: root.muted; font.pixelSize: 13; Layout.fillWidth: true }
                    Label { text: risk.modelData.advisory.known_exploited ? "Prioritize an approved update or the vendor’s mitigation. This catalog match does not establish that this machine was attacked." : "Review the vendor’s fix and update this app through its original installer. Test its normal workflow afterward."; Layout.fillWidth: true; font.pixelSize: 13 }
                    Button { objectName: "riskUpdate_" + risk.modelData.item.name; text: Model.canUpdate(risk.modelData.item) ? "Review update…" : "Review installed version"; enabled: !root.working; onClicked: root.updateRequested(risk.modelData.item) }
                }
            }
        }
        Rectangle {
            visible: !root.risks.length
            Layout.fillWidth: true; implicitHeight: emptyRisk.implicitHeight + 28
            color: root.surface; radius: 9
            Label { id: emptyRisk; anchors { left: parent.left; right: parent.right; top: parent.top; margins: 14 } text: root.covered === 0 ? "No inventory entries currently have advisory matching coverage. Review unsupported software through its vendor; an empty match list is not clearance." : !root.software.fresh || root.software.advisory_status !== "available" ? "Check software risks to load current advisory matches. Unchecked software stays unknown." : "No advisories matched the evaluated versions. Unsupported software and unknown vulnerabilities remain outside this result."; color: root.muted; lineHeight: 1.4 }
        }
        }
        ColumnLayout {
            visible: root.tab === 4
            Layout.fillWidth: true; spacing: 18
        Label { text: "What’s covered—and what isn’t"; font.pixelSize: 15; font.weight: Font.DemiBold }
        Label { text: "Advisories: supported Python tools, npm tools and the Go standard library. Other runtimes, SDKs, project dependencies and standalone binaries need their own vendor checks.\n\nFile scans: on demand, for the selected file and within engine limits. Falco behavior monitoring, automatic ClamAV Downloads scanning and one-off file scans are separate. Automatic scanning reports its exact mode and health in Automatic malware. No tool can certify that a machine has no malware or unknown vulnerabilities."; Layout.fillWidth: true; color: root.muted; lineHeight: 1.4; font.pixelSize: 13 }
        Button { text: "See the full software inventory"; onClicked: root.softwareRequested() }
        }
        Item { implicitHeight: 8 }
    }
}
