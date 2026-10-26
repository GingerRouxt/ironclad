pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Dialogs
import Quickshell.Io
import qs.Commons as Commons
import qs.Ui as Ui
import "State.js" as Model

Ui.Panel {
    id: root
    moduleName: "com.zerodaysecurity.ironclad"
    manageIpc: false
    property var anchorItem: null
    property var hostWidget: null
    readonly property var hostBar: bar
    property string message: "Ready when you are. Scans stay on this machine."
    property var results: []
    property string scanTime: "No scan yet"
    property string scanStatus: "No diagnostic scan yet. Choose Scan machine to start."
    property bool scanReceived: false
    property bool cancellingAdvice: false
    readonly property bool scanControlEnabled: scanButton.enabled
    readonly property bool scanControlFocused: scanButton.activeFocus
    property string selected: "Overview"
    property string operation: "scan"
    property string query: ""
    property string expandedCheckId: ""
    property bool reviewOnly: false
    property bool remember: false
    property string profile: "quick"
    property var history: []
    property var actionHistory: []
    property var activityData: ({entries: [], limits: []})
    property var repairFollowUp: null
    property string repairScanState: ""
    function markRepairUnknown() {
        if (!repairFollowUp) return
        repairScanState = "unknown"
        fixMessage = "The follow-up scan could not finish. The finding’s current state is unknown; scan again before assuming it cleared."
        if (fixStage !== "idle") fixStage = "error"
        repairFollowUp = null
    }
    function loadActivity() { runReadOnly(["history"], "history") }
    property var monitorData: null
    property var monitorPlan: null
    property string monitorStage: "idle"
    property string monitorMessage: ""
    property string monitorOperation: ""
    function parseMonitor(value) {
        if (!value || value.schema !== 1 || typeof value.installed !== "boolean" || typeof value.monitoring !== "boolean" || !Array.isArray(value.alerts) || value.alerts.length > 64 || !Array.isArray(value.limits) || typeof value.state !== "string" || typeof value.message !== "string") throw new Error("monitoring state")
        for (const row of value.alerts) {
            if (!row || !/^[a-f0-9]{16}:[0-9]{1,12}$/.test(row.id) || typeof row.reviewed !== "boolean") throw new Error("alert")
            for (const key of ["title", "meaning", "action", "verify", "time", "app", "rule_id"]) if (typeof row[key] !== "string" || row[key].length > 2048) throw new Error("alert text")
        }
        return value
    }
    function loadMonitor() {
        if (monitorStatusRequest.running || monitorRequest.running) return
        monitorStatusRequest.command = ["/usr/bin/python3", "-I", "-B", companionPath, "monitor-status", "--json"]
        monitorStatusRequest.running = true
    }
    function reviewMonitor(action) {
        if (busy || aiBusy) return
        monitorPlan = null; monitorOperation = "plan"; monitorStage = "preparing"
        monitorMessage = action === "enable" ? "Downloading and checking the pinned official Falco component from download.falco.org if needed. No monitoring starts until you review and approve." : "Preparing a scoped sensor change."
        monitorRequest.command = ["/usr/bin/python3", "-I", "-B", companionPath, "monitor-plan", "--json", "--target", action].concat(action === "enable" ? ["--allow-network"] : [])
        monitorRequest.running = true
    }
    function approveMonitor() {
        if (busy || aiBusy || monitorStage !== "review" || !monitorPlan) return
        monitorOperation = "apply"; monitorStage = "applying"
        monitorMessage = "Complete the OS authentication prompt. Ironclad stays closed so you can type. Reopen it from the bar to check the result."
        monitorRequest.command = ["/usr/bin/python3", "-I", "-B", companionPath, "monitor-apply", "--json", "--approve", monitorPlan.digest]
        root.close()
        monitorAuthenticationDelay.restart()
    }
    Timer { id: monitorAuthenticationDelay; interval: 200; onTriggered: monitorRequest.running = true }
    function reviewMonitorAlert(identifier) {
        if (busy || aiBusy) return
        monitorOperation = "review"; monitorRequest.alertId = identifier
        monitorRequest.command = ["/usr/bin/python3", "-I", "-B", companionPath, "monitor-review", "--json"]
        monitorRequest.running = true
    }
    Process {
        id: monitorStatusRequest
        objectName: "monitorStatusRequest"
        stdout: SplitParser { onRead: data => {
            try { if (data.length > 524288) throw new Error("size"); root.monitorData = root.parseMonitor(JSON.parse(data)) }
            catch (_) { root.monitorData = null; root.monitorMessage = "Monitoring status could not be verified. No active coverage is assumed." }
        } }
        onExited: function(exitCode, exitStatus) { if (exitCode !== 0 || exitStatus !== 0) { root.monitorData = null; root.monitorMessage = "Monitoring status is unavailable. Check status again." } }
    }
    Process {
        id: monitorRequest
        objectName: "monitorRequest"
        property string alertId: ""
        property bool received: false
        stdinEnabled: true
        onStarted: write(JSON.stringify(root.monitorOperation === "review" ? {id: alertId} : {plan: root.monitorPlan}) + "\n")
        onRunningChanged: if (running) received = false
        stdout: SplitParser { onRead: data => {
            try {
                if (data.length > 524288) throw new Error("size")
                const value = JSON.parse(data)
                if (typeof value.error === "string" && value.error.length <= 512) { root.monitorStage = "error"; root.monitorMessage = value.error }
                else if (root.monitorOperation === "plan") {
                    if (value.schema !== 1 || !/^[a-f0-9]{64}$/.test(value.digest) || ["enable", "disable", "remove"].indexOf(value.action) < 0 || typeof value.impact !== "string" || typeof value.recovery !== "string" || value.impact.length > 4096 || value.recovery.length > 4096) throw new Error("plan")
                    root.monitorPlan = value; root.monitorStage = "review"; root.monitorMessage = "Review the impact before allowing this change."
                } else if (root.monitorOperation === "review") root.monitorData = root.parseMonitor(value)
                else {
                    root.monitorData = root.parseMonitor(value.status); root.monitorStage = value.verified === true ? "done" : "error"
                    root.monitorMessage = typeof value.message === "string" && value.message.length <= 2048 ? value.message : "Check the current monitoring state."
                    root.monitorPlan = null
                }
                monitorRequest.received = true
            } catch (_) { root.monitorStage = "error"; root.monitorMessage = "The monitoring result could not be verified. Refresh status before trying again." }
        } }
        onExited: function(exitCode, exitStatus) {
            if (!received || (exitCode !== 0 || exitStatus !== 0) && root.monitorStage !== "error") { root.monitorStage = "error"; root.monitorMessage = "Monitoring change cancelled or incomplete. Check its status before retrying." }
            Qt.callLater(function() { root.loadMonitor() })
        }
    }
    Timer { interval: 5000; repeat: true; running: root.opened && (root.selected === "Protection" || root.selected === "Overview"); onTriggered: root.loadMonitor() }
    property var softwareData: ({items: [], fresh: false, limits: []})
    property string softwareQuery: ""
    property bool updatesOnly: false
    property string diagnosticGroup: "Diagnostics"
    property string terminalOperation: ""
    readonly property int softwareUpdates: softwareData.items.filter(i => !!i.available).length
    readonly property bool updateSourceReady: !!(softwareData.fresh && softwareData.update_channels && softwareData.update_channels.mise === "available")
    readonly property var softwareSecuritySummary: Model.softwareSecurity(softwareData.items)
    readonly property int softwareAlerts: softwareData.items.filter(i => i.advisories.length > 0).length
    readonly property string companionPath: decodeURIComponent(Qt.resolvedUrl("../companion.py").toString().replace(/^file:\/\//, ""))
    readonly property var totals: Model.counts(results)
    property var ignoredFindings: []
    property bool showIgnoredFindings: false
    property string ignoreMessage: ""
    property string undoIgnoreId: ""
    readonly property int ignoredFindingCount: results.filter(c => ignoredFindings.indexOf(c.check_id) >= 0).length
    readonly property int attentionCount: Model.counts(results.filter(c => ignoredFindings.indexOf(c.check_id) < 0)).review
    readonly property var visibleFindings: Model.filtered(results, selected === "Overview" ? "Overview" : diagnosticGroup, selected === "Overview" ? "" : query, false).filter(c => showIgnoredFindings || ignoredFindings.indexOf(c.check_id) < 0)
    Component.onCompleted: loadFindingPreferences()
    function loadFindingPreferences() { changeFindingPreference("status", "") }
    function changeFindingPreference(action, checkId) {
        if (findingPreferences.running) return
        findingPreferences.request = {action: action, check_id: checkId, checks: results}
        findingPreferences.received = false
        findingPreferences.command = ["/usr/bin/python3", "-I", "-B", companionPath, "finding-preferences", "--json"]
        findingPreferences.running = true
    }
    Process {
        id: findingPreferences
        objectName: "findingPreferencesRequest"
        property var request: ({})
        property bool received: false
        stdinEnabled: true
        onStarted: write(JSON.stringify(findingPreferences.request) + "\n")
        onRunningChanged: if (running) preferenceDeadline.restart()
        stdout: SplitParser { onRead: data => {
            try {
                if (data.length > 32768) throw new Error("size")
                const value = JSON.parse(data)
                if (value.error || value.schema !== 1 || !Array.isArray(value.ignored) || value.ignored.length > 512 || value.ignored.some(id => typeof id !== "string" || !root.results.some(c => c.check_id === id))) throw new Error("preferences")
                if (JSON.stringify(findingPreferences.request.checks) === JSON.stringify(root.results)) root.ignoredFindings = value.ignored
                root.ignoreMessage = findingPreferences.request.action === "ignore" ? "Finding ignored on this machine. Restore it under Show ignored. Changed evidence appears again." : findingPreferences.request.action === "restore" ? "Finding restored. No system settings changed." : ""
                if (findingPreferences.request.action === "ignore") root.undoIgnoreId = findingPreferences.request.check_id
                else if (findingPreferences.request.action === "restore") root.undoIgnoreId = ""
                findingPreferences.received = true
            } catch (_) { root.ignoreMessage = "Could not read or save ignored findings. No system settings were changed." }
        } }
        onExited: function(exitCode, exitStatus) {
            preferenceDeadline.stop()
            if (!findingPreferences.received || exitCode !== 0 || exitStatus !== 0) root.ignoreMessage = "Could not read or save ignored findings. No system settings were changed."
            if (JSON.stringify(findingPreferences.request.checks) !== JSON.stringify(root.results)) Qt.callLater(root.loadFindingPreferences)
        }
    }
    Timer { id: preferenceDeadline; interval: 10000; onTriggered: { findingPreferences.running = false; root.ignoreMessage = "Saving ignored findings timed out. Findings have not been marked fixed." } }

    readonly property bool busy: scanQueued || scannerAuthenticationDelay.running || monitorAuthenticationDelay.running || engine.running || scanArchiveRequest.running || refreshRequest.running || updateRequest.running || fixRequest.running || fixTerminal.running || protectionRequest.running || malwareRequest.running || scannerSetupRequest.running || monitorRequest.running || automaticRequest.running
    readonly property string scriptPath: decodeURIComponent(Qt.resolvedUrl("../engine.py").toString().replace(/^file:\/\//, ""))
    readonly property var sections: ["Overview", "Protection", "Software", "AI", "Diagnostics", "Activity"]
    function switchPanel(direction) {
        return hostBar && typeof hostBar.switchPanelFrom === "function" ? hostBar.switchPanelFrom(hostWidget || root, direction) : false
    }
    function runReadOnly(args, kind) {
        if (engine.running) return
        operation = kind
        message = kind === "scan" ? "Scanning locally…" : "Working locally…"
        engine.command = ["/usr/bin/python3", "-I", "-B", scriptPath].concat(args)
        engine.running = true
    }
    function cancelAdvice() {
        cancellingAdvice = true
        askAfterBrief = false
        explanationDeadline.stop(); aiDeadline.stop()
        findingAdvisor.running = false
        advisor.running = false
        cancellingAdvice = false
        explanationMessage = "AI explanation stopped. Recorded evidence and steps remain available."
        aiMessage = "AI request stopped. You can ask again after the scan."
    }
    property var pendingArchiveScan: null
    property var pendingArchiveExplanations: ({})
    property string pendingScanProfile: "quick"
    property bool pendingScanOverview: true
    property bool archiveVerified: false
    property bool scanLaunchCancelled: false
    property bool scanQueued: false
    function clearCurrentScan() {
        results = []; findingExplanations = ({}); explanationScan = null
        explanationProvider = ""; explanationMessage = "Waiting for the new scan."
        aiAnswer = ""; aiBrief = ""; briefReady = false; aiMessage = ""; aiQuestion = "What should I address first?"
        expandedCheckId = ""; ignoredFindings = []; ignoreMessage = ""; undoIgnoreId = ""
        scanTime = "No new result yet"; scanReceived = false
    }
    function beginDiagnosticScan() {
        if (scanLaunchCancelled || engine.running) { scanQueued = false; return }
        scanStatus = "Scanning " + pendingScanProfile + " checks locally…"
        if (pendingScanOverview) selected = "Overview"
        const args = ["check", "--profile", pendingScanProfile, "--format", "json"]
        if (remember) args.push("--save")
        runReadOnly(args, "scan")
        scanQueued = false
    }
    function scan(showOverview) {
        if (busy) { message = "Finish or cancel the current local operation before scanning."; return }
        cancelAdvice()
        if (!pendingArchiveScan && explanationScan) {
            pendingArchiveScan = explanationScan
            pendingArchiveExplanations = Object.assign({}, findingExplanations)
        }
        scanLaunchCancelled = false; scanQueued = true
        pendingScanProfile = profile; pendingScanOverview = showOverview !== false
        clearCurrentScan()
        if (pendingArchiveScan) {
            scanStatus = "Archiving the previous scan as private gzip…"
            archiveVerified = false
            scanArchiveRequest.command = ["/usr/bin/python3", "-I", "-B", companionPath, "scan-archive", "--json"]
            scanArchiveRequest.running = true
        } else beginDiagnosticScan()
    }
    Process {
        id: scanArchiveRequest
        objectName: "scanArchiveRequest"
        stdinEnabled: true
        onStarted: write(JSON.stringify({scan: root.pendingArchiveScan, explanations: root.pendingArchiveExplanations}) + "\n")
        stdout: SplitParser { onRead: data => {
            try {
                if (data.length > 4096) throw new Error("size")
                const response = JSON.parse(data)
                if (!root.pendingArchiveScan || response.archived !== true || response.scan_id !== root.pendingArchiveScan.scan_id || typeof response.file !== "string" || !/^[a-f0-9-]+\.json\.gz$/.test(response.file)) throw new Error("archive")
                root.archiveVerified = true
            } catch (_) { root.archiveVerified = false }
        } }
        onRunningChanged: if (running) scanArchiveDeadline.restart()
        onExited: function(exitCode, exitStatus) {
            scanArchiveDeadline.stop()
            if (root.scanLaunchCancelled) { root.scanQueued = false; root.scanStatus = "Archive cancelled. Previous scan remains in memory; retry when ready."; return }
            if (exitCode === 0 && exitStatus === 0 && root.archiveVerified) {
                root.pendingArchiveScan = null; root.pendingArchiveExplanations = ({})
                Qt.callLater(root.beginDiagnosticScan)
            } else { root.scanQueued = false; root.scanStatus = "Previous scan could not be archived. It remains in memory; retry Scan machine. No new scan started." }
        }
    }
    Timer { id: scanArchiveDeadline; interval: 10000; onTriggered: { root.scanLaunchCancelled = true; root.scanQueued = false; scanArchiveRequest.running = false; root.scanStatus = "Archive timed out. Previous scan remains in memory; retry before starting a new scan." } }
    function receive(data) {
        try {
            if (data.length > (operation === "software" ? 1048576 : 2097152)) throw new Error("limit")
            const response = JSON.parse(data)
            if (operation === "scan") {
                const result = Model.validate(response)
                findingAdvisor.running = false
                findingExplanations = ({})
                explanationProvider = ""
                explanationScan = result
                undoIgnoreId = ""; ignoreMessage = ""
                results = result.checks
                ignoredFindings = []
                Qt.callLater(root.loadFindingPreferences)
                if (repairFollowUp) {
                    const outcome = Model.followUp(results, repairFollowUp.check_id)
                    repairScanState = outcome.state
                    fixMessage = (repairFollowUp.verified ? "The reviewed repair passed its own check. " : "The repair did not verify completion. ") + outcome.title + ". " + outcome.detail
                    if (fixStage !== "idle" && repairFollowUp.verified && outcome.state !== "resolved") fixStage = "error"
                    repairFollowUp = null
                }
                explanationMessage = "Preparing fresh AI explanations…"
                scanReceived = true
                scanTime = result.collected_at
                scanStatus = "Scan complete · " + result.checks.length + " catalog checks · " + (totals.total - totals.unavailable) + " assessed · " + totals.review + " to review · " + totals.unavailable + " unavailable / not applicable · " + Model.displayTime(scanTime)
                message = totals.review + " to review · " + totals.unavailable + " coverage limits · " + Math.round(result.elapsed_ms) + " ms"
            } else if (operation === "software") {
                softwareData = Model.software(response)
                const eligible = softwareData.items.filter(i => Model.canUpdate(i)).map(i => i.source + ":" + i.name)
                selectedTools = selectedTools.filter(t => eligible.indexOf(t) >= 0)
                message = softwareData.fresh && !updateSourceReady ? "Update source unavailable. Try checking again." : softwareData.fresh ? Model.softwareSecurity(softwareData.items).text + " · " + softwareUpdates + " configured-tool updates · metadata checked recently" : "Inventory ready · check online for update availability"
            } else if (operation === "history") {
                if (!Array.isArray(response.scans) || response.scans.length > 32 || !Array.isArray(response.actions)) throw new Error("history")
                const activity = Model.activityRows(response.activity || {entries: [], limits: []})
                history = response.scans
                actionHistory = response.actions
                activityData = activity
                message = activityData.entries.length + " recorded repairs / updates · " + history.length + " saved scans"
            } else if (operation === "report") message = "Redacted report exported. Review it before sharing."
        } catch (_) { message = "Invalid engine response; previous results retained"; if (operation === "scan") { scanReceived = false; scanStatus = "Scan failed: invalid response. Previous scan is archived; no current result."; markRepairUnknown() } }
    }
    property var automaticPlan: null
    property string automaticStage: "idle"
    property string automaticMessage: ""
    property string automaticOperation: "plan"
    property string automaticReviewId: ""
    function reviewAutomatic(action) {
        if (busy || aiBusy) return
        automaticPlan = null; automaticStage = "loading"; automaticMessage = "Preparing the exact automatic malware change…"; automaticOperation = "plan"
        automaticRequest.command = ["/usr/bin/python3", "-I", "-B", companionPath, "automatic-malware-plan", "--target", action, "--json"]
        automaticRequest.running = true
    }
    function approveAutomatic() {
        if (busy || aiBusy || !automaticPlan || automaticStage !== "review") return
        automaticStage = "applying"; automaticOperation = "apply"; automaticMessage = "Complete OS authentication. One-off scans and Falco stay separate."
        automaticRequest.command = ["/usr/bin/python3", "-I", "-B", companionPath, "automatic-malware-apply", "--approve", automaticPlan.digest, "--json"]
        root.close(); automaticAuthenticationDelay.restart()
    }
    function reviewAutomaticDetection(identifier) {
        if (busy || aiBusy) return
        automaticOperation = "review"; automaticReviewId = identifier
        automaticRequest.command = ["/usr/bin/python3", "-I", "-B", companionPath, "automatic-malware-review", "--json"]
        automaticRequest.running = true
    }
    Timer { id: automaticAuthenticationDelay; interval: 200; onTriggered: automaticRequest.running = true }
    Process {
        id: automaticRequest
        objectName: "automaticMalwareRequest"
        stdinEnabled: true
        property bool received: false
        onStarted: if (root.automaticOperation !== "plan") write(JSON.stringify(root.automaticOperation === "review" ? {id: root.automaticReviewId} : {plan: root.automaticPlan}) + "\n")
        onRunningChanged: if (running) received = false
        stdout: SplitParser { onRead: data => {
            try {
                if (data.length > 65536) throw new Error("limit")
                const response = JSON.parse(data)
                if (response.error) throw new Error("request")
                if (root.automaticOperation === "plan") {
                    root.automaticPlan = Model.automaticMalwarePlan(response)
                    root.automaticStage = "review"; root.automaticMessage = "Review the scope and mode. OS authentication is required."
                } else {
                    if (root.automaticOperation === "apply" && response.verified !== true) throw new Error("unverified")
                    Model.automaticMalwareState(root.automaticOperation === "review" ? response : response.status)
                    root.automaticStage = root.automaticOperation === "review" ? "idle" : "done"
                    root.automaticMessage = response.message || "Detection acknowledged. No file was changed."
                    root.loadProtection()
                }
                automaticRequest.received = true
            } catch (_) { root.automaticStage = "error"; root.automaticMessage = "Automatic malware protection did not verify. Refresh its status; no active coverage is assumed." }
        } }
        onExited: function(exitCode, exitStatus) {
            if (!received || exitCode !== 0 || exitStatus !== 0) { root.automaticStage = "error"; root.automaticMessage = "Automatic malware change did not complete. Check OS authentication and refresh status." }
            root.loadProtection()
        }
    }
    property var protectionData: null
    property string malwareStage: "idle"
    property string malwareOperation: "plan"
    property string malwareMessage: ""
    property var malwarePlan: null
    property var malwareResult: null
    function loadProtection() {
        if (protectionRequest.running) return
        protectionRequest.command = ["/usr/bin/python3", "-I", "-B", companionPath, "protection-status", "--json"]
        protectionRequest.running = true
    }
    function configureProtectionUpdates(enabled) {
        if (busy || aiBusy) return
        scannerSetupRequest.command = ["/usr/bin/python3", "-I", "-B", companionPath, enabled ? "protection-updates-enable" : "protection-updates-disable", "--json"].concat(enabled ? ["--allow-network"] : [])
        malwareStage = "setup"
        malwareMessage = enabled ? "Enabling background signature updates and engine release checks…" : "Disabling future automatic updates…"
        scannerSetupRequest.running = true
    }
    function maintainProtection() {
        if (busy || aiBusy) return
        scannerSetupRequest.command = ["/usr/bin/python3", "-I", "-B", companionPath, "protection-maintain", "--json", "--allow-network"]
        malwareStage = "setup"; malwareMessage = "Updating official signatures and checking engine releases…"
        scannerSetupRequest.running = true
    }
    Timer {
        interval: 60000; repeat: true; running: root.opened && (root.selected === "Protection" || root.selected === "Overview")
        onTriggered: { root.loadProtection(); root.loadMonitor() }
    }
    function reviewMalwareFile(path) {
        if (busy || aiBusy) { message = "Finish the current operation before reviewing a file scan."; return }
        malwarePlan = null; malwareResult = null
        malwareStage = "loading"; malwareOperation = "plan"
        malwareMessage = "Checking the selected file, scanner and signatures. No file scan has started."
        malwareRequest.targetPath = path
        malwareRequest.command = ["/usr/bin/python3", "-I", "-B", companionPath, "malware-plan", "--json"]
        malwareRequest.running = true
    }
    function approveMalwareScan() {
        if (busy || aiBusy || malwareStage !== "review" || !malwarePlan) return
        malwareOperation = "scan"; malwareStage = "scanning"
        malwareMessage = "Scanning this file locally… Nothing is deleted, quarantined or uploaded."
        malwareRequest.command = ["/usr/bin/python3", "-I", "-B", companionPath, "malware-scan", "--json", "--approve", malwarePlan.digest]
        malwareRequest.running = true
    }
    function cancelMalwareScan() {
        malwareRequest.running = false
        malwareStage = "cancelled"
        malwareMessage = "Scan stopped. The file has not been cleared; check the last recorded result before trying again."
    }
    function dismissMalware() {
        if (malwareRequest.running || scannerSetupRequest.running || monitorRequest.running) return
        malwareStage = "idle"; malwarePlan = null; malwareResult = null
    }
    function reviewScannerSetup(signatures) {
        if (busy || aiBusy) return
        malwarePlan = null; malwareResult = null
        malwareStage = signatures ? "signatures-review" : "install-review"
        malwareMessage = signatures ? "Download official ClamAV signature updates into Ironclad’s private local data folder. The updater contacts ClamAV’s database service; no selected files or documents are sent." : "Install ClamAV, Bubblewrap isolation and their required dependencies using the system package manager. An OS authentication prompt may appear here. After installation, download signatures before scanning. No background scanning is enabled."
    }
    function approveScannerSetup() {
        if (busy || aiBusy || ["install-review", "signatures-review"].indexOf(malwareStage) < 0) return
        const signatures = malwareStage === "signatures-review"
        scannerSetupRequest.command = ["/usr/bin/python3", "-I", "-B", companionPath, signatures ? "scanner-signatures" : "scanner-install", "--json"].concat(signatures ? ["--allow-network"] : [])
        malwareStage = "setup"
        malwareMessage = signatures ? "Downloading official signatures… This can take several minutes. File contents stay on your machine." : "Installing the scanner… Complete the OS authentication prompt if requested. Let the package transaction finish."
        if (signatures) scannerSetupRequest.running = true
        else { root.close(); scannerAuthenticationDelay.restart() }
    }
    Timer { id: scannerAuthenticationDelay; interval: 200; onTriggered: scannerSetupRequest.running = true }
    Process {
        id: protectionRequest
        objectName: "protectionRequest"
        command: []
        stdout: SplitParser { onRead: data => {
            try {
                if (data.length > 65536) throw new Error("size")
                root.protectionData = Model.protectionState(JSON.parse(data))
            } catch (_) { root.message = "Protection coverage could not be read. Nothing is assumed protected; try reopening Protection." }
        } }
        onExited: function(exitCode, exitStatus) { if (exitCode !== 0 || exitStatus !== 0) { root.protectionData = null; root.message = "Protection health could not be verified. Refresh Protection and check its setup." } }
    }
    Process {
        id: malwareRequest
        objectName: "malwareRequest"
        property string targetPath: ""
        property bool received: false
        stdinEnabled: true
        onStarted: write(JSON.stringify(root.malwareOperation === "plan" ? {path: targetPath} : {plan: root.malwarePlan}) + "\n")
        onRunningChanged: if (running) { received = false; malwareDeadline.restart() }
        stdout: SplitParser { onRead: data => {
            try {
                if (data.length > 65536) throw new Error("size")
                const response = JSON.parse(data)
                if (typeof response.error === "string" && response.error.length <= 512) {
                    root.malwareStage = "error"; root.malwareMessage = response.error + " No clearance is assumed."
                    malwareRequest.received = true
                    return
                }
                if (root.malwareOperation === "plan") {
                    root.malwarePlan = Model.malwarePlan(response)
                    root.malwareStage = "review"
                    root.malwareMessage = "Review this exact file before scanning. The file, scanner and signatures are rechecked when you approve."
                } else {
                    root.malwareResult = Model.malwareResult(response)
                    root.malwareStage = "done"
                    root.malwareMessage = response.message
                }
                malwareRequest.received = true
            } catch (_) { root.malwareStage = "error"; root.malwareMessage = "Could not read a complete scanner result. The file has not been cleared." }
        } }
        onExited: function(exitCode, exitStatus) {
            malwareDeadline.stop()
            if (root.malwareStage !== "cancelled" && (!received || ((exitCode !== 0 || exitStatus !== 0) && root.malwareStage !== "error"))) {
                root.malwareStage = "error"
                root.malwareMessage = root.malwareOperation === "plan" ? "Could not review this file. Choose an owned, nonempty regular file under 100 MiB in your home folder. Hidden, credential and linked files are excluded. Check scanner/signature setup, then try again." : "The scan did not return a complete result. The file may have changed or the engine could not finish. No clearance is assumed; review again."
            }
            if (root.malwareOperation === "scan") Qt.callLater(function() { root.loadProtection() })
        }
    }
    Timer { id: malwareDeadline; interval: 165000; onTriggered: root.cancelMalwareScan() }
    Process {
        id: scannerSetupRequest
        objectName: "scannerSetupRequest"
        property bool received: false
        onRunningChanged: if (running) received = false
        stdout: SplitParser { onRead: data => {
            try {
                if (data.length > 65536) throw new Error("size")
                const response = JSON.parse(data)
                if (typeof response.error === "string" && response.error.length <= 512) {
                    root.malwareStage = "error"; root.malwareMessage = response.error
                } else if (response.scanner && typeof response.scanner.installed === "boolean" && typeof response.message === "string" && response.message.length <= 512) {
                    root.malwareStage = "setup-done"; root.malwareMessage = response.message
                } else throw new Error("response")
                scannerSetupRequest.received = true
            } catch (_) { root.malwareStage = "error"; root.malwareMessage = "Scanner setup returned an unreadable result. Check readiness before scanning." }
        } }
        onExited: function(exitCode, exitStatus) {
            if (!received || (exitCode !== 0 || exitStatus !== 0) && root.malwareStage !== "error") {
                root.malwareStage = "error"; root.malwareMessage = "Scanner setup cancelled or incomplete. Check readiness and try again."
            }
            Qt.callLater(function() { root.loadProtection() })
        }
    }
    // Native dialogs are regular windows. Release the shell overlay/grab first,
    // then restore the panel only after this dialog accepts or cancels.
    property string pendingNativeDialog: ""
    function chooseNativeDialog(kind) {
        if (busy || aiBusy || pendingNativeDialog || ["malware", "report"].indexOf(kind) < 0) return
        pendingNativeDialog = kind
        root.close()
        nativeDialogDelay.restart()
    }
    function finishNativeDialog(kind, url) {
        if (pendingNativeDialog !== kind) return
        pendingNativeDialog = ""
        nativeDialogReturn.kind = kind
        nativeDialogReturn.url = url
        nativeDialogReturn.restart()
    }
    Timer {
        id: nativeDialogDelay
        interval: 200
        onTriggered: {
            root.close()
            if (root.pendingNativeDialog === "malware") malwareFileDialog.open()
            else if (root.pendingNativeDialog === "report") exportDialog.open()
        }
    }
    Timer {
        id: nativeDialogReturn
        property string kind: ""
        property string url: ""
        interval: 200
        onTriggered: {
            root.open()
            if (!url) return
            if (url.indexOf("file://") !== 0) { root.message = "Choose a local file"; return }
            const path = decodeURIComponent(url.substring(7))
            if (kind === "malware") root.reviewMalwareFile(path)
            else root.runReadOnly(["report", "--fresh", "--format", "html", "--output", path], "report")
            url = ""
        }
    }
    FileDialog {
        id: malwareFileDialog
        objectName: "malwareFileDialog"
        title: "Choose one download or file to scan locally"
        fileMode: FileDialog.OpenFile
        options: FileDialog.DontUseNativeDialog
        onAccepted: root.finishNativeDialog("malware", selectedFile.toString())
        onRejected: root.finishNativeDialog("malware", "")
    }
    property string fixStage: "idle"
    property string fixOperation: "options"
    property string fixCheckId: ""
    property string fixMessage: ""
    property string fixManual: ""
    property var fixPlans: []
    property var fixPlan: null
    property var fixResult: null
    property string fixTicket: ""
    function reviewFix(checkId) {
        if (busy || aiBusy) return
        repairScanState = ""
        repairFollowUp = null
        fixCheckId = checkId
        fixPlan = null
        fixResult = null
        fixPlans = []
        fixManual = ""
        fixTicket = ""
        fixStage = "loading"
        fixMessage = "Checking which repairs match the current state. Nothing is changed."
        fixOperation = "options"
        fixRequest.command = ["/usr/bin/python3", "-I", "-B", companionPath, "fix-options", "--json", "--target", checkId]
        fixRequest.running = true
    }
    function chooseFix(plan) {
        if (fixRequest.running || fixTerminal.running) return
        fixPlan = Model.repairPlan(plan)
        fixStage = "review"
        fixMessage = "Review the exact change, its impact and how to undo it. Apply fix will perform this change."
    }
    function approveFix() {
        if (busy || aiBusy || fixStage !== "review" || !fixPlan) return
        fixOperation = "queue"
        fixStage = "authorizing"
        fixMessage = "Validating your approved repair…"
        fixRequest.command = ["/usr/bin/python3", "-I", "-B", companionPath, "fix-queue", "--json", "--approve", fixPlan.digest]
        fixRequest.running = true
    }
    function dismissFix() {
        if (fixRequest.running || fixTerminal.running) return
        fixStage = "idle"
        fixPlan = null
    }
    function receiveFix(data) {
        try {
            if (data.length > 262144) throw new Error("size")
            const response = JSON.parse(data)
            if (response.error) throw new Error("backend")
            if (fixOperation === "options") {
                if (response.check_id !== fixCheckId || !Array.isArray(response.plans) || response.plans.length > 16 || typeof response.manual !== "string") throw new Error("options")
                fixPlans = response.plans.map(p => Model.repairPlan(p))
                if (fixPlans.some(p => p.check_id !== fixCheckId)) throw new Error("finding")
                fixManual = response.manual
                fixStage = fixPlans.length ? "choose" : "manual"
                fixMessage = fixPlans.length ? "Choose the repair you want to review. Nothing has been changed." : "This finding needs guided steps; there is no supported automatic repair for its current state."
                if (fixPlans.length === 1) { fixPlan = fixPlans[0]; fixStage = "review"; fixMessage = "Review this exact change before applying it. Nothing has been changed." }
            } else if (fixOperation === "queue") {
                if (!/^[a-f0-9]{32}$/.test(response.ticket) || !fixPlan || response.digest !== fixPlan.digest) throw new Error("ticket")
                fixTicket = response.ticket
                fixStage = "queued"
            } else {
                if (response.ticket !== fixTicket || typeof response.verified !== "boolean" || typeof response.message !== "string") throw new Error("result")
                repairFollowUp = {check_id: fixCheckId, verified: response.verified}
                fixResult = response
                fixStage = response.verified ? "done" : "error"
                fixMessage = response.message + " A fresh scan will check the machine again."
            }
        } catch (_) { fixStage = "error"; fixMessage = "The repair could not be reviewed or verified. Its conditions may have changed. Nothing is assumed fixed; review again or use the guided steps." }
    }
    Process {
        id: fixRequest
        objectName: "fixRequest"
        stdinEnabled: true
        onStarted: if (root.fixOperation === "queue") write(JSON.stringify({plan: root.fixPlan}) + "\n")
        stdout: SplitParser { onRead: data => root.receiveFix(data) }
        onRunningChanged: if (running) fixDeadline.start()
        onExited: function(exitCode, exitStatus) {
            fixDeadline.stop()
            if (exitCode === 0 && exitStatus === 0 && root.fixStage === "queued") {
                root.fixStage = "applying"
                root.fixMessage = "Applying the approved fix in a terminal. Enter your administrator password there if asked."
                fixTerminal.command = ["/usr/bin/foot", "--app-id=com.zerodaysecurity.ironclad.fix", "--title=Ironclad · Apply reviewed fix", "/usr/bin/python3", "-I", "-B", root.companionPath, "fix-run", "--ticket", root.fixTicket, "--approve", root.fixPlan.digest]
                root.close()
                fixTerminal.running = true
            } else if (["loading", "authorizing", "verifying"].indexOf(root.fixStage) >= 0) {
                root.fixStage = "error"
                root.fixMessage = "The repair process ended without a verified result. Review again; do not assume any issue was fixed."
            }
            if (root.fixOperation === "result") Qt.callLater(function() { root.scan(false) })
        }
    }
    Process {
        id: fixTerminal
        objectName: "fixTerminal"
        onExited: function(exitCode, exitStatus) {
            root.open()
            root.fixStage = "verifying"
            root.fixMessage = "Reading the repair result…"
            root.fixOperation = "result"
            fixRequest.command = ["/usr/bin/python3", "-I", "-B", root.companionPath, "fix-result", "--json", "--ticket", root.fixTicket]
            fixRequest.running = true
        }
    }
    Timer { id: fixDeadline; interval: 180000; onTriggered: { fixRequest.running = false; root.fixStage = "error"; root.fixMessage = "Repair review timed out. Review again; no success is assumed." } }
    function reviewAction(action) {
        // The UI cannot approve an action. A separate terminal shows the exact
        // fresh preview and requires user confirmation before engine mutation.
        if (action !== "home.remove_world_write" && action !== "baseline.replace") return
        if (actionTerminal.running) { message = "An action review is already open"; return }
        root.close()
        if (action === "home.remove_world_write") terminalOperation = "remediation"
        actionTerminal.command = ["/usr/bin/foot", "--app-id=com.zerodaysecurity.ironclad.review", "--title=Ironclad · Review and apply", "/usr/bin/python3", "-I", "-B", scriptPath, "action", "apply", action]
        actionTerminal.running = true
        message = "Review opened in a separate terminal. Closing or declining keeps settings unchanged."
    }
    function inspectFinding(checkId) {
        const entry = Model.inspection(checkId)
        if (!entry || inspectionTerminal.running) return
        root.close()
        inspectionTerminal.command = ["/usr/bin/foot", "--app-id=com.zerodaysecurity.ironclad.inspect", "--title=Ironclad · Inspect finding", "--hold"].concat(entry.command)
        inspectionTerminal.running = true
        message = "Inspection opened in a terminal. This only displays information; it does not repair or change settings."
    }
    Process {
        id: inspectionTerminal
        objectName: "inspectionTerminal"
        onExited: function(exitCode, exitStatus) {
            root.open()
            root.message = exitCode === 0 && exitStatus === 0 ? "Inspection closed. No settings were changed." : "Inspection could not finish. No repair is assumed."
        }
    }
    function planFindingFix(checkId, context) {
        const check = results.find(c => c.check_id === checkId)
        if (!check || aiBusy || busy) return
        const scopedCheck = context ? Object.assign({}, check, {summary: check.summary.substring(0, 200) + "; Repair review: " + String(context).substring(0, 250)}) : check
        aiQuestion = Model.fixQuestion(scopedCheck, findingExplanations[checkId])
        navigate("AI")
        askAgent()
    }
    function reviewSchedule(operation) {
        if (operation !== "enable" && operation !== "disable") return
        if (actionTerminal.running) { message = "An action review is already open"; return }
        root.close()
        actionTerminal.command = ["/usr/bin/foot", "--app-id=com.zerodaysecurity.ironclad.review", "--title=Ironclad · Optional scheduling", "/usr/bin/python3", "-I", "-B", scriptPath, "schedule", operation]
        actionTerminal.running = true
        message = "Scheduling review opened; no change is made unless you confirm in that terminal."
    }
    function updateOmarchy() {
        if (root.busy || omarchyUpdater.running) return
        omarchyUpdater.command = ["/usr/bin/foot", "--app-id=com.zerodaysecurity.ironclad.omarchy-update", "--title=Omarchy · Build and system update", "/usr/bin/omarchy", "update"]
        omarchyUpdater.running = true
        root.message = "Omarchy updater opened. Review and confirm in its terminal to begin."
    }
    Process {
        id: omarchyUpdater
        objectName: "omarchyUpdater"
        onExited: function(exitCode, exitStatus) {
            root.message = exitCode === 0 && exitStatus === 0 ? "Omarchy updater closed. Review its terminal output for the result." : "Omarchy update cancelled or incomplete. Review its terminal output."
        }
    }
    function loadSoftware() { runReadOnly(["software"], "software") }
    function refreshSoftware() {
        if (busy || aiBusy) return
        message = "Checking software versions and security notices…"
        operation = "software"
        refreshRequest.command = ["/usr/bin/python3", "-I", "-B", companionPath, "refresh", "--allow-network", "--json"]
        refreshRequest.running = true
    }
    function cancelWork() {
        if (scanArchiveRequest.running || scanQueued) { scanLaunchCancelled = true; scanQueued = false; scanArchiveRequest.running = false; message = "Archive cancelled. Previous scan remains in memory."; return }
        if (operation === "scan") { scanReceived = false; scanStatus = "Scan failed: invalid response. Previous scan is archived; no current result."; markRepairUnknown() }
        engine.running = false
        refreshRequest.running = false
        if (updateStage === "planning") { updateRequest.running = false; updateStage = "idle" }
        message = "Cancelled. Previous results kept."
    }
    Process {
        id: refreshRequest
        objectName: "refreshRequest"
        property bool received: false
        onRunningChanged: if (running) { received = false; refreshDeadline.start() }
        stdout: SplitParser {
            onRead: data => {
                root.receive(data)
                refreshRequest.received = true
            }
        }
        onExited: function(exitCode, exitStatus) {
            refreshDeadline.stop()
            if (exitCode !== 0 || exitStatus !== 0 || !received) root.message = "Could not refresh software metadata. Previous results kept. Try again or check your connection."
        }
    }
    Timer { id: refreshDeadline; interval: 150000; onTriggered: { refreshRequest.running = false; root.message = "Update check timed out. Previous results kept." } }
    property var selectedTools: []
    property var updateBatch: null
    function toggleTool(target) {
        if (busy) return
        selectedTools = selectedTools.indexOf(target) >= 0 ? selectedTools.filter(t => t !== target) : selectedTools.length < 32 ? selectedTools.concat([target]) : selectedTools
    }
    function selectListedUpdates() {
        if (busy) return
        selectedTools = Model.appItems(softwareData.items, softwareQuery, softwareMode).filter(i => Model.canUpdate(i) && !!i.available).map(i => i.source + ":" + i.name).filter((t, i, list) => list.indexOf(t) === i).slice(0, 32)
    }
    function reviewSelected() {
        if (busy || aiBusy || !selectedTools.length) return
        updatePlan = null
        updateBatch = null
        updateStage = "planning"
        updateMessage = "Preparing selected application updates…"
        updateOperation = "plan-selected"
        updateRequest.command = ["/usr/bin/python3", "-I", "-B", companionPath, "plan-selected", "--json"]
        updateRequest.running = true
    }
    property var updatePlan: null
    property string updateStage: "idle"
    property string updateMessage: ""
    property string updateOperation: "plan"
    property string approvedDigest: ""
    property var updateResult: null
    function reviewUpdate(target) {
        if (busy || aiBusy) { message = "Finish the current operation, then review the update."; return }
        selected = "Software"
        updateBatch = null
        updateStage = "planning"
        updateMessage = "Preparing this application's update plan…"
        updatePlan = null
        updateResult = null
        updateOperation = "plan"
        updateRequest.command = ["/usr/bin/python3", "-I", "-B", companionPath, "plan", "--json", "--target", target]
        updateRequest.running = true
    }
    function approveUpdate() {
        if (busy || updateStage !== "review" || (!updatePlan && !updateBatch)) return
        if (updateBatch) {
            approvedDigest = updateBatch.digest
            updateStage = "applying"
            updateMessage = "Starting selected updates…"
            updateOperation = "apply-selected"
            updateRequest.command = ["/usr/bin/python3", "-I", "-B", companionPath, "apply-selected", "--json", "--approve", approvedDigest]
            updateRequest.running = true
            return
        }
        approvedDigest = updatePlan.digest
        updateStage = "applying"
        updateMessage = "Updating " + updatePlan.name + "… Keep the application closed until this finishes."
        updateOperation = "apply"
        updateRequest.command = ["/usr/bin/python3", "-I", "-B", companionPath, "apply-update", "--json", "--approve", approvedDigest]
        updateRequest.running = true
    }
    function dismissUpdate() {
        if (updateRequest.running) return
        updateStage = "idle"
        updateBatch = null
        updatePlan = null
        updateResult = null
        updateMessage = ""
    }
    function receiveUpdate(data) {
        try {
            if (data.length > 65536) throw new Error("limit")
            const response = JSON.parse(data)
            if (updateOperation === "apply-selected" && typeof response.progress === "number") {
                updateDeadline.restart()
                updateMessage = "Updating " + response.progress + " of " + response.total + ": " + response.target + "…"
                return
            }
            if (typeof response.error === "string") {
                updateStage = "error"
                updateMessage = response.error
            } else if (updateOperation === "plan-selected") {
                if (response.operation !== "selected-application-updates" || !Array.isArray(response.plans) || !response.plans.length || response.plans.length > 32 || !/^[0-9a-f]{64}$/.test(response.digest)) throw new Error("batch")
                response.plans = response.plans.map(p => Model.updatePlan(p))
                updateBatch = response
                updateStage = "review"
                updateMessage = "Review the selected updates, then click Install updates below to start. They run one at a time and stop if an update fails. Nothing has been installed yet."
            } else if (updateOperation === "apply-selected") {
                if (response.batch_result !== true || typeof response.verified !== "boolean" || !Array.isArray(response.results) || !Array.isArray(response.skipped)) throw new Error("batch result")
                updateStage = response.verified ? "done" : "error"
                updateMessage = response.results.map(r => r.target + ": " + (r.verified ? "verified · " + r.observed_versions.join(", ") : "failed · " + r.reason)).join("\n") + (response.skipped.length ? "\nNot run: " + response.skipped.join(", ") : "") + "\nRestart updated applications and check your normal workflow."
                const completed = response.results.filter(r => r.verified).map(r => r.target)
                selectedTools = selectedTools.filter(t => completed.indexOf(t) < 0)
            } else if (updateOperation === "plan") {
                updatePlan = Model.updatePlan(response)
                updateStage = "review"
                updateMessage = "Review the version, command and scope, then click Install update below to start. Nothing has been installed yet."
            } else {
                if (typeof response.verified !== "boolean" || !Array.isArray(response.observed_versions)) throw new Error("result")
                updateResult = response
                updateStage = response.verified ? "done" : "error"
                updateMessage = response.verified ? (response.version_changed ? "Update finished. Observed version: " : "Manager completed; version unchanged: ") + response.observed_versions.join(", ") + ". Restart the application and check your normal workflow." + (response.metadata_retained ? "" : " Check for updates again before reviewing other tools.") : "Update did not verify. " + (response.reason || "manager failure") + ". Manager exit: " + response.updater_exit_code + ". Check the application before trying again."
            }
        } catch (_) { updateStage = "error"; updateMessage = "Could not read the update result. No success is assumed. Check the application before retrying." }
    }
    Process {
        id: updateRequest
        objectName: "updateRequest"
        stdinEnabled: true
        onStarted: {
            if (root.updateOperation === "apply") write(JSON.stringify({plan: root.updatePlan}) + "\n")
            else if (root.updateOperation === "plan-selected") write(JSON.stringify({targets: root.selectedTools}) + "\n")
            else if (root.updateOperation === "apply-selected") write(JSON.stringify({batch: root.updateBatch}) + "\n")
        }
        stdout: SplitParser { onRead: data => root.receiveUpdate(data) }
        onRunningChanged: if (running) updateDeadline.start()
        onExited: function(exitCode, exitStatus) {
            updateDeadline.stop()
            if (root.updateStage === "planning" || root.updateStage === "applying") {
                root.updateStage = "error"
                root.updateMessage = "The update process stopped without a result (exit " + exitCode + "). No success is assumed. Check the application before retrying."
            }
            if (root.updateOperation === "apply" || root.updateOperation === "apply-selected") Qt.callLater(function() { root.loadSoftware() })
        }
    }
    Timer { id: updateDeadline; interval: 930000; onTriggered: { updateRequest.running = false; root.updateStage = "error"; root.updateMessage = "Update timed out. The application may be partially updated; check it before retrying." } }
    property string softwareMode: "Security"
    property string expandedSoftware: ""
    property var explanationScan: null
    property var findingExplanations: ({})
    property string explanationMessage: "Scan locally, then choose whether to request AI explanations."
    property string explanationProvider: ""
    function explainScan() {
        if (!explanationScan || findingAdvisor.running || advisor.running || engine.running) return
        findingExplanations = ({})
        explanationProvider = ""
        explanationMessage = "Your signed-in agent is explaining all " + results.length + " checks…"
        findingAdvisor.command = ["/usr/bin/python3", "-I", "-B", companionPath, "explain-findings", "--json", "--send"]
        findingAdvisor.running = true
    }
    function receiveExplanations(data) {
        try {
            if (data.length > 131072) throw new Error("size")
            const response = JSON.parse(data)
            if (!explanationScan || response.scan_id !== explanationScan.scan_id) return
            if (!Array.isArray(response.explanations) || response.total !== results.length || typeof response.done !== "boolean") throw new Error("explanations")
            const rows = Object.assign({}, findingExplanations)
            for (const row of response.explanations) {
                if (!results.some(c => c.check_id === row.check_id) || rows[row.check_id]) throw new Error("finding")
                for (const key of ["meaning", "action", "verification"]) if (typeof row[key] !== "string" || !row[key].trim() || row[key].length > 600) throw new Error("text")
                rows[row.check_id] = row
            }
            if (response.completed !== Object.keys(rows).length || response.done !== (response.completed === results.length)) throw new Error("progress")
            findingExplanations = rows
            explanationProvider = response.provider || "your agent"
            explanationMessage = "AI explained " + response.completed + " of " + results.length + " checks" + (response.done ? ". All checks have AI explanations." : "…")
            explanationDeadline.restart()
        } catch (_) { explanationMessage = "AI response could not be verified. Completed explanations remain; retry for this scan." }
    }
    Process {
        id: findingAdvisor
        objectName: "findingAdvisor"
        stdinEnabled: true
        onStarted: write(JSON.stringify({scan: root.explanationScan}) + "\n")
        stdout: SplitParser { onRead: data => root.receiveExplanations(data) }
        onRunningChanged: if (running) explanationDeadline.start()
        onExited: function(exitCode, exitStatus) {
            explanationDeadline.stop()
            if (!root.cancellingAdvice && (exitCode !== 0 || exitStatus !== 0 || Object.keys(root.findingExplanations).length !== root.results.length)) root.explanationMessage = "AI explained " + Object.keys(root.findingExplanations).length + " of " + root.results.length + " checks. The remaining explanations did not complete; retry when your agent is available."
        }
    }
    Timer { id: explanationDeadline; interval: 135000; onTriggered: { findingAdvisor.running = false; root.explanationMessage = "AI explanations timed out. Try again when your agent is available." } }
    property string aiQuestion: "What should I address first?"
    property string aiBrief: ""
    property string aiAnswer: ""
    property string aiMessage: ""
    property string aiOperation: "brief"
    property bool showBrief: false
    property string agentName: "your signed-in agent"
    property bool askAfterBrief: false
    property bool briefReady: false
    readonly property bool aiBusy: advisor.running
    readonly property bool explanationBusy: findingAdvisor.running
    // Bind to the shell singleton: its palette updates in place on theme changes.
    readonly property color canvas: Commons.Color.popups.background
    readonly property color ink: Commons.Color.popups.text
    readonly property color rail: Qt.tint(canvas, Qt.rgba(ink.r, ink.g, ink.b, 0.025))
    readonly property color surface: Qt.tint(canvas, Qt.rgba(ink.r, ink.g, ink.b, 0.055))
    readonly property color line: Qt.tint(canvas, Qt.rgba(ink.r, ink.g, ink.b, 0.30))
    readonly property color muted: readable(Qt.tint(canvas, Qt.rgba(ink.r, ink.g, ink.b, 0.82)))
    readonly property color accent: readable(Commons.Color.accent)
    readonly property color accentInk: luminance(accent) > 0.179 ? "#000000" : "#ffffff"
    readonly property color amber: readable(Commons.Color.urgent)
    readonly property color aiAnswerInk: readable(luminance(canvas) < 0.179 ? Qt.rgba(0.96, 0.97, 0.99, 1) : Qt.rgba(0.08, 0.13, 0.19, 1))
    readonly property color aiBriefInk: readable(luminance(canvas) < 0.179 ? Qt.rgba(0.72, 0.83, 0.96, 1) : Qt.rgba(0.14, 0.30, 0.46, 1))
    readonly property bool displayingAnswer: aiAnswer.length > 0 && !showBrief
    function luminance(color) {
        function channel(value) { return value <= 0.04045 ? value / 12.92 : Math.pow((value + 0.055) / 1.055, 2.4) }
        return 0.2126 * channel(color.r) + 0.7152 * channel(color.g) + 0.0722 * channel(color.b)
    }
    function contrast(a, b) {
        const x = luminance(a), y = luminance(b)
        return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05)
    }
    function readable(color) {
        const target = contrast(Qt.rgba(1,1,1,1), surface) > contrast(Qt.rgba(0,0,0,1), surface) ? Qt.rgba(1,1,1,1) : Qt.rgba(0,0,0,1)
        for (let step = 0; step <= 20; step++) {
            const candidate = Qt.tint(color, Qt.rgba(target.r, target.g, target.b, step / 20))
            if (contrast(candidate, canvas) >= 4.5 && contrast(candidate, surface) >= 4.5 && contrast(candidate, rail) >= 4.5) return candidate
        }
        return target
    }
    onOpenedChanged: if (opened && selected === "Overview") { loadProtection(); loadMonitor() }
    function navigate(name) {
        selected = name
        if (name === "Protection" || name === "Overview") { if (!engine.running) loadSoftware(); loadProtection(); loadMonitor() }
        if (name === "Software" && !busy) loadSoftware()
        if (name === "AI") checkAgent()
        if (name === "Activity" && !busy) loadActivity()
    }
    function requestBrief() {
        if (aiBusy || busy) { aiMessage = "Let the current scan finish, then prepare a brief."; return }
        if (findingAdvisor.running) { explanationDeadline.stop(); findingAdvisor.running = false }
        aiOperation = "brief"
        aiBrief = ""
        briefReady = false
        aiMessage = "Preparing a fresh local brief…"
        aiAnswer = ""
        advisor.command = ["/usr/bin/python3", "-I", "-B", companionPath, "brief", "--json", "--input-question"]
        advisor.running = true
    }
    function askAgent() {
        if (aiBusy || busy) return
        askAfterBrief = true
        requestBrief()
    }
    function checkAgent() {
        if (agentStatus.running) return
        agentStatus.command = ["/usr/bin/python3", "-I", "-B", companionPath, "agent-status", "--json"]
        agentStatus.running = true
    }
    Process {
        id: agentStatus
        stdout: SplitParser {
            onRead: data => {
                try {
                    const state = JSON.parse(data)
                    root.agentName = state.available ? state.agent : "No signed-in agent found"
                } catch (_) { root.agentName = "your signed-in agent" }
            }
        }
    }
    function sendBrief() {
        if (aiBusy || !aiBrief) return
        aiOperation = "ask"
        aiMessage = "Asking " + agentName + "…"
        advisor.command = ["/usr/bin/python3", "-I", "-B", companionPath, "ask", "--json", "--input-brief", "--send"]
        advisor.running = true
    }
    function receiveAdvice(data) {
        try {
            if (data.length > 2097152) throw new Error("limit")
            const response = JSON.parse(data)
            if (aiOperation === "brief" && typeof response.brief === "string" && response.brief.length > 0 && response.brief.length <= 524288) {
                aiBrief = response.brief
                briefReady = true
                aiMessage = "Brief ready. Nothing has been sent."
            } else if (aiOperation === "ask" && typeof response.answer === "string") {
                aiAnswer = response.answer
                aiMessage = (response.provider || agentName) + " · advice based on this machine’s findings"
            } else throw new Error("schema")
        } catch (_) { askAfterBrief = false; aiMessage = "Could not read the response. Your findings are still here." }
    }
    Process {
        id: advisor
        objectName: "advisorRequest"
        stdinEnabled: true
        onStarted: write(JSON.stringify(root.aiOperation === "ask" ? {brief: root.aiBrief} : {question: root.aiQuestion, scan: root.explanationScan}) + "\n")
        stdout: SplitParser { onRead: data => root.receiveAdvice(data) }
        onRunningChanged: if (running) aiDeadline.start()
        onExited: function(exitCode, exitStatus) {
            aiDeadline.stop()
            if (root.cancellingAdvice) return
            if (exitCode === 0 && exitStatus === 0 && root.aiOperation === "brief" && root.askAfterBrief && root.briefReady) {
                root.askAfterBrief = false
                Qt.callLater(function() { root.sendBrief() })
            } else root.askAfterBrief = false
            if (exitCode !== 0 || exitStatus !== 0) root.aiMessage = root.aiOperation === "brief" ? "Could not prepare a brief. Finish any running scan and try again." : "Could not ask the agent. Check that Codex or Claude Code is signed in, then retry."
        }
    }
    Timer { id: aiDeadline; interval: 135000; onTriggered: { advisor.running = false; root.askAfterBrief = false; root.aiMessage = "The agent request timed out. Try again when it is available." } }
    TextEdit { id: clipboard; visible: false; text: root.aiBrief; textFormat: TextEdit.PlainText }
    function chooseReport() { chooseNativeDialog("report") }
    Process {
        id: engine
        objectName: "diagnosticEngine"
        stdout: SplitParser { onRead: data => root.receive(data) }
        onExited: function(exitCode, exitStatus) {
            deadline.stop()
            if (exitCode !== 0 || exitStatus !== 0) {
                root.message = "Could not finish. Previous results kept; try again."
                if (root.operation === "scan") { root.markRepairUnknown(); root.scanStatus = "Scan did not finish. Previous scan is archived; retry for a current result." }
            }
            else if (root.operation === "scan") {
                if (!root.scanReceived) root.scanStatus = "Scan returned no valid result. Previous scan is archived."
                else {
                    root.explanationMessage = "Local scan complete. AI explanations have not been requested."
                    Qt.callLater(function() { root.loadSoftware() })
                }
            }
        }
        onRunningChanged: if (running) deadline.start()
    }
    Process {
        id: actionTerminal
        onExited: function(exitCode, exitStatus) {
            root.message = exitCode === 0 && exitStatus === 0 ? "Terminal session finished. Refreshing software observations." : "Session declined or incomplete. Review the terminal result."
            if (root.terminalOperation === "refresh" || root.terminalOperation === "update") Qt.callLater(function() { root.loadSoftware() })
            if (root.terminalOperation === "remediation") Qt.callLater(function() { root.open(); root.scan() })
            root.terminalOperation = ""
        }
    }
    Timer {
        id: deadline
        interval: 15000
        onTriggered: { engine.running = false; if (root.operation === "scan") { root.markRepairUnknown(); root.scanStatus = "Scan timed out. Previous scan is archived; no current result." }; root.message = "Operation timed out; previous results retained" }
    }
    FileDialog {
        id: exportDialog
        objectName: "exportDialog"
        title: "Export redacted Ironclad report"
        fileMode: FileDialog.SaveFile
        options: FileDialog.DontUseNativeDialog
        nameFilters: ["HTML report (*.html)"]
        defaultSuffix: "html"
        onAccepted: root.finishNativeDialog("report", selectedFile.toString())
        onRejected: root.finishNativeDialog("report", "")
    }
    component Copy: BodyText { color: root.ink; Layout.minimumWidth: 0 }
    component Action: ControlButton {
        ink: root.ink; muted: root.muted; accent: root.accent; accentInk: root.accentInk
        surface: root.surface; rail: root.rail; line: root.line
    }
    component Input: TextField {
        id: field
        color: root.ink
        placeholderTextColor: root.muted
        font.family: "Inter"; font.pixelSize: 13
        leftPadding: 12; rightPadding: 12
        implicitHeight: 38
        selectByMouse: true
        background: Rectangle { radius: 7; color: root.surface; border.color: field.activeFocus ? root.accent : root.line }
    }
    component Choice: ComboBox {
        id: choice
        implicitHeight: 38
        leftPadding: 12; rightPadding: 26
        palette.window: root.surface
        palette.base: root.surface
        palette.text: root.ink
        palette.button: root.surface
        palette.buttonText: root.ink
        palette.highlight: root.accent
        palette.highlightedText: root.accentInk
        background: Rectangle { radius: 7; color: root.surface; border.color: choice.activeFocus ? root.accent : root.line }
        contentItem: Text { text: choice.displayText; color: root.ink; font.family: "Inter"; font.pixelSize: 13; verticalAlignment: Text.AlignVCenter; elide: Text.ElideRight; textFormat: Text.PlainText }
        indicator: Text { text: "⌄"; color: root.muted; anchors.right: parent.right; anchors.rightMargin: 10; anchors.verticalCenter: parent.verticalCenter; font.pixelSize: 13 }
    }
    component Badge: Rectangle {
        id: badge
        property string text: ""
        property bool alert: false
        implicitWidth: badgeText.implicitWidth + 18
        implicitHeight: 25
        radius: 5
        color: alert ? Qt.rgba(root.amber.r, root.amber.g, root.amber.b, 0.11) : Qt.rgba(root.accent.r, root.accent.g, root.accent.b, 0.08)
        Copy { id: badgeText; anchors.centerIn: parent; text: badge.text; color: badge.alert ? root.amber : root.accent; font.pixelSize: 13; font.weight: Font.Medium }
    }
    component Metric: Rectangle {
        id: metric
        property string value: ""
        property string label: ""
        property string detail: ""
        property bool alert: false
        Layout.fillWidth: true
        implicitHeight: 104
        radius: 10; color: root.surface; border.color: root.line
        ColumnLayout {
            anchors.fill: parent; anchors.margins: 16; spacing: 5
            Copy { text: metric.label; color: root.muted; font.pixelSize: 13 }
            Copy { text: metric.value; font.pixelSize: 27; font.weight: Font.DemiBold; color: metric.alert ? root.amber : root.ink }
            Copy { text: metric.detail; color: root.muted; font.pixelSize: 13; Layout.fillWidth: true; elide: Text.ElideRight; maximumLineCount: 1 }
        }
    }
    Ui.KeyboardPanel {
        id: panel
        anchorItem: root.anchorItem
        owner: root.hostWidget || root
        bar: root.bar
        open: root.opened
        contentWidth: panel.fittedContentWidth(1020)
        contentHeight: panel.fittedContentHeight(700)
        focusTarget: scanButton
        Rectangle {
            anchors.fill: parent
            color: root.canvas
            radius: 14
            border.color: root.line
            clip: true
            Keys.onEscapePressed: { if (root.expandedCheckId) root.expandedCheckId = ""; else root.close() }
            RowLayout {
                enabled: root.fixStage === "idle"
                anchors.fill: parent
                spacing: 0
                Rectangle {
                    Layout.preferredWidth: 184
                    Layout.fillHeight: true
                    color: root.rail
                    ColumnLayout {
                        anchors.fill: parent; anchors.margins: 16; spacing: 7
                        RowLayout {
                            Layout.topMargin: 12; Layout.bottomMargin: 32
                            spacing: 10
                            Rectangle {
                                implicitWidth: 29; implicitHeight: 32; radius: 7; color: root.accent
                                Copy { anchors.centerIn: parent; text: "I"; color: root.accentInk; font.weight: Font.Bold; font.pixelSize: 23 }
                            }
                            Copy { text: "ironclad"; font.pixelSize: 19; font.weight: Font.DemiBold; font.letterSpacing: -0.6 }
                        }
                        Copy { text: "Local protection"; color: root.muted; font.pixelSize: 13; font.letterSpacing: 1.6; Layout.leftMargin: 10; Layout.bottomMargin: 6 }
                        Repeater {
                            model: root.sections
                            delegate: Button {
                                id: nav
                                required property string modelData
                                required property int index
                                Layout.fillWidth: true
                                implicitHeight: 42
                                hoverEnabled: true
                                background: Rectangle { radius: 7; color: root.selected === nav.modelData ? root.surface : nav.hovered ? root.line : "transparent"; border.color: nav.activeFocus ? root.accent : "transparent" }
                                contentItem: RowLayout {
                                    spacing: 11
                                    NavIcon { symbol: nav.index; ink: root.selected === nav.modelData ? root.accent : root.muted; Layout.preferredWidth: 20; Layout.preferredHeight: 20 }
                                    Copy { text: nav.modelData === "AI" ? "AI advisor" : nav.modelData; font.pixelSize: 13; font.weight: root.selected === nav.modelData ? Font.DemiBold : Font.Normal; Layout.fillWidth: true }
                                }
                                onClicked: root.navigate(modelData)
                            }
                        }
                        Item { Layout.fillHeight: true }
                        Rectangle { Layout.fillWidth: true; implicitHeight: 1; color: root.line }
                        Copy { text: "Your machine.\nYour call."; color: root.muted; font.pixelSize: 13; font.letterSpacing: 1.2; lineHeight: 1.5; Layout.topMargin: 10 }
                        Copy { text: "Zero Day Security"; color: root.muted; font.pixelSize: 13; Layout.topMargin: 10; Layout.bottomMargin: 6 }
                    }
                }
                ColumnLayout {
                    Layout.fillWidth: true; Layout.fillHeight: true
                    Layout.margins: 24
                    spacing: 18
                    RowLayout {
                        Layout.fillWidth: true
                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 6
                            Copy { text: "Ironclad · " + (root.selected === "AI" ? "AI advisor" : root.selected); color: root.muted; font.pixelSize: 13; font.letterSpacing: 1.6 }
                            Copy {
                                text: root.selected === "Overview" ? "Your workstation" : root.selected === "Protection" ? "Protection" : root.selected === "Software" ? "Software" : root.selected === "AI" ? "AI advisor" : root.selected === "Diagnostics" ? "Diagnostics" : "Activity"
                                Layout.fillWidth: true; font.pixelSize: 26; font.weight: Font.DemiBold; font.letterSpacing: -0.7
                            }
                        }
                        Item { Layout.fillWidth: true }
                        Action { visible: root.busy && root.updateStage !== "applying"; text: "Cancel"; quiet: true; onClicked: { root.cancelWork() } }
                        Choice {
                            objectName: "scanProfileSelector"
                            model: ["Quick · 90", "Full · 180", "Super Scan · 420"]
                            currentIndex: ["quick", "full", "super"].indexOf(root.profile)
                            enabled: !root.busy
                            onActivated: root.profile = ["quick", "full", "super"][currentIndex]
                            Accessible.name: "Scan coverage profile"
                        }
                        Action { id: scanButton; objectName: "scanMachineButton"; text: engine.running && root.operation === "scan" ? "Scanning…" : "Scan machine"; primary: true; enabled: !root.busy; onClicked: root.scan() }
                        Action { text: "×"; quiet: true; implicitWidth: 30; leftPadding: 8; rightPadding: 8; onClicked: root.close(); Accessible.name: "Close Ironclad" }
                    }
                    RowLayout {
                        Layout.fillWidth: true
                        Copy { objectName: "scanProgressLabel"; text: root.scanStatus; Layout.fillWidth: true; color: root.ink; font.pixelSize: 13 }
                        Copy { visible: root.explanationBusy; text: "AI explaining in background"; color: root.muted; font.pixelSize: 13 }
                        Action { objectName: "stopExplanationButton"; visible: root.explanationBusy; text: "Stop AI"; quiet: true; onClicked: root.cancelAdvice() }
                    }
                    Overview {
                        objectName: "overviewView"
                        visible: root.selected === "Overview"
                        Layout.fillWidth: true; Layout.fillHeight: true
                        checks: root.results; ignored: root.ignoredFindings
                        software: root.softwareData
                        capability: root.protectionData; monitor: root.monitorData
                        scanTime: root.scanTime; working: root.busy; preferenceWorking: findingPreferences.running
                        ink: root.ink; muted: root.muted; accent: root.accent; accentInk: root.accentInk
                        surface: root.surface; rail: root.rail; line: root.line; urgent: root.amber
                        onProtectionRequested: root.navigate("Protection")
                        onSecurityRequested: { root.softwareMode = "Security"; root.softwareQuery = ""; root.navigate("Software") }
                        onSoftwareCheckRequested: { root.selected = "Software"; root.softwareMode = "Security"; root.refreshSoftware() }
                        onFileRequested: { protectionView.tab = 1; root.navigate("Protection") }
                        onUpdatesRequested: { protectionView.tab = 2; root.navigate("Protection") }
                        onAdviceRequested: root.navigate("AI")
                        onDiagnosticsRequested: { root.query = ""; root.reviewOnly = false; root.diagnosticGroup = "Diagnostics"; root.showIgnoredFindings = root.ignoredFindingCount > 0; root.navigate("Diagnostics") }
                        onScanRequested: root.scan()
                        onIgnoreRequested: checkId => root.changeFindingPreference("ignore", checkId)
                        onFindingRequested: checkId => {
                            root.query = ""; root.reviewOnly = false; root.diagnosticGroup = "Diagnostics"
                            root.navigate("Diagnostics"); root.expandedCheckId = checkId
                            Qt.callLater(function() { const index = root.visibleFindings.findIndex(c => c.check_id === checkId); if (index >= 0) findingsList.positionViewAtIndex(index, ListView.Beginning) })
                        }
                    }
                    // Diagnostics retains the full searchable evidence and finding actions.
                    ColumnLayout {
                        visible: root.selected === "Diagnostics"
                        Layout.fillWidth: true; Layout.fillHeight: true
                        spacing: 18
                        RowLayout {
                            visible: root.selected === "Overview"
                            Layout.fillWidth: true; spacing: 10
                            Metric { label: "Needs attention"; value: root.results.length ? String(root.attentionCount) : "—"; detail: "Findings with next steps"; alert: root.attentionCount > 0 }
                            Metric { label: "Software updates"; value: root.updateSourceReady ? String(root.softwareUpdates) : "—"; detail: root.softwareData.fresh ? "Compatible versions listed" : "Check online to see updates" }
                            Metric { label: "Observed"; value: root.results.length ? String(root.totals.observed) : "—"; detail: "No action flagged" }
                        }
                        RowLayout {
                            Layout.fillWidth: true
                            Copy { text: root.selected === "Overview" ? "What needs your attention" : "Machine observations"; font.pixelSize: 14; font.weight: Font.DemiBold; Layout.fillWidth: true }
                            Action { visible: root.selected === "Overview"; text: "Ask your AI  ↗"; quiet: true; onClicked: root.navigate("AI") }
                        }
                        RowLayout {
                            Layout.fillWidth: true
                            Copy { text: root.explanationMessage + " Explain all checks sends bounded, redacted findings to your agent's provider. Account limits apply."; color: root.muted; font.pixelSize: 13; Layout.fillWidth: true }
                            Action { objectName: "explainAllChecksButton"; text: "Explain all checks"; quiet: true; enabled: !!root.explanationScan && !root.aiBusy && !root.explanationBusy && !root.busy; onClicked: root.explainScan() }
                        }
                        RowLayout {
                            visible: root.selected === "Diagnostics"
                            Layout.fillWidth: true
                            Input { Layout.fillWidth: true; text: root.query; placeholderText: "Search observations…"; onTextChanged: root.query = text; Accessible.name: "Search diagnostics" }
                            Choice { model: ["Diagnostics", "Performance", "Security", "Storage", "Startup", "Packages", "Network", "Backups", "Developer", "Hardware"]; onActivated: root.diagnosticGroup = currentText; Accessible.name: "Diagnostic category" }
                        }
                        Rectangle {
                            visible: !root.results.length || root.visibleFindings.length === 0
                            Layout.fillWidth: true; Layout.fillHeight: true
                            color: root.surface; radius: 10; border.color: root.line
                            ColumnLayout {
                                anchors.centerIn: parent; width: parent.width - 64; spacing: 12
                                Copy { text: root.results.length ? "Nothing flagged for action." : "Start with a fresh look."; font.pixelSize: 20; font.weight: Font.DemiBold; Layout.fillWidth: true }
                                Copy { text: root.results.length ? "This scan has " + root.totals.unavailable + " coverage limits. Open Diagnostics to see what was and wasn’t checked." : "A quick scan checks this machine locally. You’ll get findings, practical next steps, and a way to verify each change."; color: root.muted; Layout.fillWidth: true; lineHeight: 1.5 }
                                Action { text: root.results.length ? "See diagnostics" : "Run first scan"; onClicked: root.results.length ? root.navigate("Diagnostics") : root.scan(); enabled: !root.busy; Layout.topMargin: 6 }
                            }
                        }
                        RowLayout {
                            Layout.fillWidth: true
                            visible: root.ignoredFindingCount > 0 || root.ignoreMessage.length > 0
                            Copy { text: root.ignoreMessage || (root.ignoredFindingCount + " ignored · kept in scan reports, not marked fixed"); color: root.muted; font.pixelSize: 13; Layout.fillWidth: true }
                            Action { objectName: "toggleIgnoredFindings"; visible: root.ignoredFindingCount > 0; text: root.showIgnoredFindings ? "Hide ignored" : "Show ignored (" + root.ignoredFindingCount + ")"; quiet: true; onClicked: root.showIgnoredFindings = !root.showIgnoredFindings }
                        }
                        Item {
                            visible: root.results.length > 0 && root.visibleFindings.length > 0
                            Layout.fillWidth: true; Layout.fillHeight: true; clip: true
                            ListView {
                                id: findingsList
                                objectName: "findingsList"
                                anchors { fill: parent; rightMargin: 22 }
                                clip: true
                                boundsBehavior: Flickable.StopAtBounds
                                ScrollBar.vertical: ScrollBar {
                                    id: findingsScrollbar
                                    objectName: "findingsScrollbar"
                                    parent: findingsList.parent
                                    anchors { right: parent.right; top: parent.top; bottom: parent.bottom }
                                    policy: ScrollBar.AlwaysOn
                                    width: 14
                                    minimumSize: 0.08
                                    contentItem: Rectangle { implicitWidth: 10; radius: 5; color: findingsScrollbar.pressed ? root.accent : root.muted; opacity: findingsScrollbar.size < 1 ? 1 : 0.35 }
                                    background: Rectangle { radius: 6; color: root.surface; border.color: root.line }
                                }
                                model: root.visibleFindings
                                spacing: 8
                                delegate: Rectangle {
                                    id: findingRow
                                    required property var modelData
                                    readonly property bool expanded: root.expandedCheckId === modelData.check_id
                                    readonly property bool ignored: root.ignoredFindings.indexOf(modelData.check_id) >= 0
                                    width: ListView.view.width
                                    implicitHeight: findingContent.implicitHeight + 28
                                    color: root.surface; border.color: expanded ? root.line : "transparent"; radius: 9
                                    ColumnLayout {
                                        id: findingContent
                                        anchors { left: parent.left; right: parent.right; top: parent.top; margins: 14 }
                                        spacing: 10
                                        RowLayout {
                                            Layout.fillWidth: true; spacing: 12
                                            Rectangle { implicitWidth: 5; implicitHeight: 28; radius: 2; color: findingRow.modelData.status === "attention" || findingRow.modelData.status === "critical" ? root.amber : root.muted }
                                            Copy { text: Model.findingTitle(findingRow.modelData); Layout.fillWidth: true; font.weight: Font.Medium; font.pixelSize: 13 }
                                            Action { objectName: "reviewFinding_" + findingRow.modelData.check_id; text: findingRow.expanded ? "Close details" : "Review"; quiet: true; onClicked: root.expandedCheckId = findingRow.expanded ? "" : findingRow.modelData.check_id; Accessible.name: "Review " + findingRow.modelData.summary }
                                            Action { objectName: "rowIgnore_" + findingRow.modelData.check_id; text: findingRow.ignored ? "Restore" : "Ignore"; quiet: true; enabled: !findingPreferences.running; onClicked: root.changeFindingPreference(findingRow.ignored ? "restore" : "ignore", findingRow.modelData.check_id) }
                                        }
                                        Flow {
                                            visible: findingRow.expanded
                                            objectName: "findingActions_" + findingRow.modelData.check_id
                                            Layout.fillWidth: true
                                            spacing: 8
                                            Action { objectName: "reviewFix_" + findingRow.modelData.check_id; visible: ["attention", "critical", "error"].indexOf(findingRow.modelData.status) >= 0; text: Model.canReviewRepair(findingRow.modelData) ? "Fix…" : "How to fix"; primary: true; enabled: !root.busy && !root.aiBusy; onClicked: { if (Model.canReviewRepair(findingRow.modelData)) root.reviewFix(findingRow.modelData.check_id); else root.expandedCheckId = findingRow.modelData.check_id } }
                                            Action { objectName: "inspectFinding_" + findingRow.modelData.check_id; visible: !!Model.inspection(findingRow.modelData.check_id); text: Model.inspection(findingRow.modelData.check_id) ? Model.inspection(findingRow.modelData.check_id).label : "Inspect"; enabled: !root.busy; onClicked: root.inspectFinding(findingRow.modelData.check_id) }
                                            Action { objectName: "planFix_" + findingRow.modelData.check_id; text: "Ask AI about this check"; enabled: !root.busy && !root.aiBusy; onClicked: root.planFindingFix(findingRow.modelData.check_id) }
                                        }
                                        Copy { visible: findingRow.ignored; text: "Ignored · no system changes · not marked fixed"; color: root.muted; font.pixelSize: 13; Layout.fillWidth: true }
                                        Copy { visible: findingRow.expanded; text: "Observation: " + findingRow.modelData.summary; Layout.fillWidth: true; color: root.muted }
                                        Copy { visible: findingRow.expanded; objectName: "affected_" + findingRow.modelData.check_id; text: "Affected: " + Model.affected(findingRow.modelData); Layout.fillWidth: true; color: root.accent; font.pixelSize: 13; lineHeight: 1.45 }
                                        ColumnLayout {
                                            Layout.fillWidth: true; spacing: 8
                                            visible: findingRow.expanded && !!root.findingExplanations[findingRow.modelData.check_id]
                                            Copy { objectName: "findingMeaning_" + findingRow.modelData.check_id; text: root.findingExplanations[findingRow.modelData.check_id] ? root.findingExplanations[findingRow.modelData.check_id].meaning : ""; Layout.fillWidth: true; color: root.aiAnswerInk; font.pixelSize: 13; lineHeight: 1.45 }
                                            Copy { text: "If you want to address it"; color: root.ink; font.pixelSize: 13; font.weight: Font.Medium }
                                            Copy { objectName: "findingAction_" + findingRow.modelData.check_id; text: root.findingExplanations[findingRow.modelData.check_id] ? root.findingExplanations[findingRow.modelData.check_id].action : ""; Layout.fillWidth: true; color: root.aiAnswerInk; font.pixelSize: 13; lineHeight: 1.45 }
                                            Copy { objectName: "findingVerification_" + findingRow.modelData.check_id; text: root.findingExplanations[findingRow.modelData.check_id] ? "Check afterward: " + root.findingExplanations[findingRow.modelData.check_id].verification : ""; Layout.fillWidth: true; color: root.aiAnswerInk; font.pixelSize: 13; lineHeight: 1.45 }
                                        }
                                        ColumnLayout {
                                            visible: findingRow.expanded && !root.findingExplanations[findingRow.modelData.check_id]
                                            Layout.fillWidth: true; spacing: 8
                                            Copy { text: root.explanationMessage; Layout.fillWidth: true; color: root.muted; font.pixelSize: 13; lineHeight: 1.45 }
                                            Copy { visible: findingRow.expanded; objectName: "fallbackAdvice_" + findingRow.modelData.check_id; text: "What you can do: " + findingRow.modelData.recommendation; Layout.fillWidth: true; font.pixelSize: 13; lineHeight: 1.45 }
                                        }
                                        Copy { visible: findingRow.expanded; text: "Fix reviews available repairs before applying a change, then verifies and rescans. Inspection only reads information; AI plans do not run changes."; Layout.fillWidth: true; color: root.muted; font.pixelSize: 13; lineHeight: 1.3 }
                                        ColumnLayout {
                                            visible: findingRow.expanded
                                            Layout.fillWidth: true; spacing: 10
                                            Rectangle { Layout.fillWidth: true; implicitHeight: 1; color: root.line }
                                            Copy { text: "NEXT STEPS"; color: root.accent; font.pixelSize: 13; font.letterSpacing: 1.4 }
                                            Copy { text: Model.nextSteps(findingRow.modelData).map((s, i) => (i+1) + ".  " + s).join("\n\n"); Layout.fillWidth: true; lineHeight: 1.4 }
                                            Copy { text: "Verify  /  " + (findingRow.modelData.verification || "Repeat this check."); Layout.fillWidth: true; color: root.accent; font.pixelSize: 13; lineHeight: 1.45 }
                                            Copy { text: "EVIDENCE\n" + Model.evidence(findingRow.modelData); Layout.fillWidth: true; color: root.muted; font.pixelSize: 13; lineHeight: 1.4 }

                                        }
                                    }
                                }
                            }
                        }
                        RowLayout {
                            Layout.fillWidth: true
                            Copy { text: root.results.length ? root.totals.total + " observations  ·  " + root.totals.unavailable + " coverage limits" : "Read-only checks. No account required."; color: root.muted; font.pixelSize: 13; Layout.fillWidth: true }
                            Action { text: "Export report"; quiet: true; enabled: !root.busy; onClicked: root.chooseReport() }
                        }
                    }
                    Protection {
                        id: protectionView
                        objectName: "protectionView"
                        visible: root.selected === "Protection"
                        Layout.fillWidth: true; Layout.fillHeight: true
                        software: root.softwareData
                        capability: root.protectionData
                        monitor: root.monitorData
                        monitorReview: root.monitorPlan
                        monitorStage: root.monitorStage
                        monitorMessage: root.monitorMessage
                        automaticReview: root.automaticPlan; automaticStage: root.automaticStage; automaticMessage: root.automaticMessage
                        onAutomaticChangeRequested: action => root.reviewAutomatic(action)
                        onAutomaticApproved: root.approveAutomatic()
                        onAutomaticDismissed: { root.automaticStage = "idle"; root.automaticPlan = null }
                        onAutomaticRefreshRequested: root.loadProtection()
                        onAutomaticReviewed: identifier => root.reviewAutomaticDetection(identifier)
                        onMonitorChangeRequested: action => root.reviewMonitor(action)
                        onMonitorApproved: root.approveMonitor()
                        onMonitorDismissed: { root.monitorStage = "idle"; root.monitorPlan = null }
                        onMonitorRefreshRequested: root.loadMonitor()
                        onMonitorReviewed: identifier => root.reviewMonitorAlert(identifier)
                        onMonitorAdviceRequested: ruleId => {
                            root.aiQuestion = "Explain the Falco detection category " + ruleId + " in plain English: possible legitimate causes, safe investigation and remediation steps, and how to verify them. No specific event metadata is being shared. Do not assume compromise or approval."
                            root.navigate("AI"); root.askAgent()
                        }
                        working: root.busy || root.aiBusy
                        ink: root.ink; muted: root.muted; accent: root.accent; accentInk: root.accentInk
                        surface: root.surface; rail: root.rail; line: root.line; urgent: root.amber
                        onAdviceRequested: {
                            root.aiQuestion = "Which matched software advisories should I address first? Explain the known exploitation evidence and coverage gaps in plain English, with reviewed update or mitigation steps and how to verify them. Do not assume compromise or approval."
                            root.navigate("AI"); root.askAgent()
                        }
                        onCheckRequested: root.refreshSoftware()
                        onChooseRequested: root.chooseNativeDialog("malware")
                        onSetupRequested: root.reviewScannerSetup(false)
                        onSignaturesRequested: root.reviewScannerSetup(true)
                        onAutomaticUpdatesRequested: enabled => root.configureProtectionUpdates(enabled)
                        onMaintenanceRequested: root.maintainProtection()
                        onSoftwareRequested: { root.softwareMode = "Installed"; root.navigate("Software") }
                        onUpdateRequested: item => {
                            if (Model.canUpdate(item)) root.reviewUpdate(item.source + ":" + item.name)
                            else { root.softwareMode = "All versions"; root.softwareQuery = item.name; root.navigate("Software") }
                        }
                    }
                    ColumnLayout {
                        id: softwarePage
                        readonly property bool reviewingUpdate: root.updateStage === "review" || root.updateStage === "planning" || root.updateStage === "applying"
                        visible: root.selected === "Software"
                        Layout.fillWidth: true; Layout.fillHeight: true; spacing: 14
                        RowLayout {
                            visible: root.softwareMode !== "Security" && !softwarePage.reviewingUpdate
                            Layout.fillWidth: true
                            Copy { text: "Apps, languages, runtimes & developer tools.\nApp updates below. Build updates use the official Omarchy updater."; color: root.muted; Layout.fillWidth: true; lineHeight: 1.5; font.pixelSize: 13 }
                            Action { text: refreshRequest.running ? "Checking…" : "Check for updates"; enabled: !root.busy && !root.aiBusy; onClicked: root.refreshSoftware() }
                        }
                        RowLayout {
                            visible: root.softwareMode !== "Security" && !softwarePage.reviewingUpdate
                            Layout.fillWidth: true; spacing: 12
                            ColumnLayout {
                                Layout.fillWidth: true; spacing: 3
                                Copy { text: "Omarchy build & system"; font.weight: Font.DemiBold; font.pixelSize: 13 }
                                Copy { text: "Official updater · build, system packages & migrations · confirmation in terminal"; color: root.muted; font.pixelSize: 13; Layout.fillWidth: true }
                            }
                            Action { objectName: "updateOmarchyButton"; text: omarchyUpdater.running ? "Updater open…" : "Update Omarchy…"; enabled: !root.busy && !omarchyUpdater.running; onClicked: root.updateOmarchy() }
                        }
                        RowLayout {
                            Layout.fillWidth: true; spacing: 7
                            Repeater {
                                model: ["Security", "Updates", "Installed", "All versions", "Unverified"]
                                delegate: Action { required property string modelData; objectName: "softwareMode_" + modelData; text: modelData; primary: root.softwareMode === modelData; quiet: root.softwareMode !== modelData; onClicked: root.softwareMode = modelData }
                            }
                            Item { Layout.fillWidth: true }
                            Action { objectName: "securityRefreshButton"; visible: root.softwareMode === "Security"; text: "Check software"; enabled: !root.busy && !root.aiBusy; onClicked: root.refreshSoftware() }
                            Copy { visible: root.softwareMode !== "Security"; text: root.updateSourceReady ? root.softwareUpdates + " configured-tool updates" : "Online check needed"; color: root.softwareData.fresh ? root.accent : root.muted; font.pixelSize: 13 }
                        }
                        Copy { objectName: "softwareSecuritySummary"; text: Model.softwareSecurity(root.softwareData.items).text + ". Update availability is separate; zero configured-tool updates does not clear retained versions."; color: root.softwareAlerts ? root.amber : root.muted; Layout.fillWidth: true; font.weight: Font.Medium }
                        Copy { text: "Online checks use configured mise sources, send supported Python/npm/Go package names and versions to api.osv.dev, and download CISA’s public catalog from raw.githubusercontent.com/cisagov/kev-data. Nothing is installed."; color: root.muted; font.pixelSize: 13; Layout.fillWidth: true; lineHeight: 1.4 }
                        Rectangle {
                            visible: root.updateStage !== "idle"
                            Layout.fillWidth: true
                            implicitHeight: updateDetails.implicitHeight + 28
                            radius: 9; color: root.surface; border.color: root.updateStage === "error" ? root.amber : root.accent
                            ColumnLayout {
                                id: updateDetails
                                anchors { left: parent.left; right: parent.right; top: parent.top; margins: 14 }
                                spacing: 10
                                Copy { text: root.updateStage === "done" ? "Updates completed" : root.updateBatch ? "Update " + root.updateBatch.plans.length + " selected apps" : root.updatePlan ? "Update " + root.updatePlan.name : "Application update"; font.weight: Font.DemiBold; font.pixelSize: 15; Layout.fillWidth: true }
                                ScrollView {
                                    id: updateStatusScroll
                                    contentWidth: availableWidth
                                    implicitHeight: Math.min(updateStatusText.implicitHeight, 120)
                                    Layout.fillWidth: true
                                    Layout.preferredHeight: implicitHeight
                                    Layout.minimumHeight: implicitHeight
                                    Layout.maximumHeight: 120
                                    clip: true
                                    Copy { id: updateStatusText; width: updateStatusScroll.availableWidth; text: root.updateMessage; color: root.updateStage === "error" ? root.amber : root.muted; font.pixelSize: 13 }
                                }
                                Copy { visible: !!root.updatePlan && root.updateStage === "review"; text: root.updatePlan ? root.updatePlan.installed + " → " + (root.updatePlan.available || "manager-selected compatible version") + " · " + root.updatePlan.source : ""; color: root.accent; Layout.fillWidth: true; font.pixelSize: 13 }
                                ScrollView {
                                    id: updatePlanScroll
                                    objectName: "updatePlanScroll"
                                    visible: !!root.updatePlan && root.updateStage === "review"
                                    contentWidth: availableWidth
                                    implicitHeight: Math.min(updatePlanText.implicitHeight, 120)
                                    Layout.fillWidth: true
                                    Layout.preferredHeight: implicitHeight
                                    Layout.minimumHeight: implicitHeight
                                    Layout.maximumHeight: 120
                                    clip: true
                                    Copy { id: updatePlanText; width: updatePlanScroll.availableWidth; text: root.updatePlan ? root.updatePlan.scope + "\n\n" + root.updatePlan.impact + "\n\nCommand: " + root.updatePlan.command.join(" ") : ""; font.pixelSize: 13; lineHeight: 1.3 }
                                }
                                ScrollView {
                                    id: selectedReviewScroll
                                    contentWidth: availableWidth
                                    implicitHeight: 120
                                    visible: !!root.updateBatch && root.updateStage === "review"
                                    Layout.fillWidth: true; Layout.preferredHeight: 120; Layout.minimumHeight: 120; Layout.maximumHeight: 120; clip: true
                                    ColumnLayout {
                                        width: selectedReviewScroll.availableWidth; spacing: 14
                                        Repeater {
                                            model: root.updateBatch ? root.updateBatch.plans : []
                                            delegate: Copy { required property var modelData; text: modelData.name + " · " + modelData.installed + " → " + (modelData.available || "manager-selected version") + "\n" + modelData.scope + "\n" + modelData.impact + "\nCommand: " + modelData.command.join(" "); Layout.fillWidth: true; font.pixelSize: 13 }
                                        }
                                    }
                                }
                                RowLayout {
                                    Action { objectName: "approveUpdateButton"; visible: root.updateStage === "review"; text: root.updateBatch ? "Install " + root.updateBatch.plans.length + " updates" : root.updatePlan ? "Install update for " + root.updatePlan.name : "Install update"; primary: true; onClicked: root.approveUpdate() }
                                    Action { objectName: "cancelUpdateButton"; visible: !updateRequest.running; text: root.updateStage === "review" ? "Cancel" : "Dismiss"; onClicked: root.dismissUpdate() }
                                }
                            }
                        }
                        Input { Layout.fillWidth: true; placeholderText: "Find an app or language…"; onTextChanged: root.softwareQuery = text; Accessible.name: "Search software" }
                        Item {
                            Layout.fillWidth: true; Layout.fillHeight: true
                            Layout.minimumHeight: 90
                            visible: root.updateStage !== "review" && root.updateStage !== "applying" && root.updateStage !== "planning"
                            ListView {
                                id: softwareList
                                objectName: "softwareList"
                                anchors { fill: parent; rightMargin: 22 }
                                clip: true
                                boundsBehavior: Flickable.StopAtBounds
                                ScrollBar.vertical: ScrollBar {
                                    id: softwareScrollbar
                                    objectName: "softwareScrollbar"
                                    parent: softwareList.parent
                                    anchors { right: parent.right; top: parent.top; bottom: parent.bottom }
                                    policy: ScrollBar.AlwaysOn
                                    width: 14
                                    minimumSize: 0.08
                                    contentItem: Rectangle { implicitWidth: 10; radius: 5; color: softwareScrollbar.pressed ? root.accent : root.muted; opacity: softwareScrollbar.size < 1 ? 1 : 0.35 }
                                    background: Rectangle { radius: 6; color: root.surface; border.color: root.line }
                                }
                                spacing: 7
                                Copy {
                                    objectName: "softwareEmptyState"
                                    anchors.centerIn: parent
                                    width: parent.width - 30
                                    horizontalAlignment: Text.AlignHCenter
                                    visible: softwareList.count === 0
                                    text: root.softwareQuery ? "No matching software." : root.softwareMode === "Updates" ? (root.updateSourceReady ? root.softwareAlerts ? "No configured-tool updates listed.\nSecurity notices remain in the Security tab, including retained versions." : "No configured-tool updates listed. Advisory coverage is limited; this is not a complete all-clear." : "Check for updates to see available versions.") : root.softwareMode === "Security" ? "No matched advisories in this inventory. Refresh the online check; unsupported software remains outside coverage." : "No software in this view."
                                    color: root.muted
                                }
                                model: Model.appItems(root.softwareData.items, root.softwareQuery, root.softwareMode)
                                delegate: Rectangle {
                                    id: toolRow
                                    required property var modelData
                                    readonly property string identity: modelData.source + ":" + modelData.name + ":" + modelData.installed
                                    readonly property bool expanded: root.expandedSoftware === identity
                                    width: ListView.view.width
                                    implicitHeight: toolContent.implicitHeight + 26
                                    radius: 9; color: root.surface
                                    ColumnLayout {
                                        id: toolContent
                                        anchors { left: parent.left; right: parent.right; top: parent.top; margins: 13 }
                                        spacing: 12
                                        RowLayout {
                                            Layout.fillWidth: true; spacing: 13
                                            CheckBox {
                                                objectName: "selectTool_" + toolRow.modelData.name
                                                visible: Model.canUpdate(toolRow.modelData)
                                                enabled: !root.busy
                                                checked: root.selectedTools.indexOf(toolRow.modelData.source + ":" + toolRow.modelData.name) >= 0
                                                Accessible.name: "Select " + toolRow.modelData.name + " for update"
                                                onClicked: root.toggleTool(toolRow.modelData.source + ":" + toolRow.modelData.name)
                                            }
                                            Rectangle { implicitWidth: 34; implicitHeight: 36; radius: 7; color: root.rail; Copy { anchors.centerIn: parent; text: toolRow.modelData.name.charAt(0).toUpperCase(); font.pixelSize: 15; color: root.muted; font.weight: Font.DemiBold } }
                                            ColumnLayout {
                                                Layout.fillWidth: true; spacing: 4
                                                Copy { text: toolRow.modelData.name; font.weight: Font.DemiBold; Layout.fillWidth: true; elide: Text.ElideMiddle; maximumLineCount: 1 }
                                                Copy { text: toolRow.modelData.installed + (toolRow.modelData.available ? "  →  " + toolRow.modelData.available : "") + "   ·   " + toolRow.modelData.source; color: root.muted; font.pixelSize: 13; Layout.fillWidth: true; elide: Text.ElideRight; maximumLineCount: 1 }
                                            }
                                            Badge { visible: !Model.canUpdate(toolRow.modelData); text: toolRow.modelData.advisories.length ? "Security notice" : toolRow.modelData.available ? "Version listed" : toolRow.modelData.source === "local launcher" ? "Unverified" : "Installed"; alert: toolRow.modelData.advisories.length > 0 }
                                            Action { objectName: "updateTool_" + toolRow.modelData.name; visible: Model.canUpdate(toolRow.modelData); text: "Review update…"; primary: !!toolRow.modelData.available; enabled: !root.busy && !root.aiBusy; onClicked: root.reviewUpdate(toolRow.modelData.source + ":" + toolRow.modelData.name) }
                                            Action { objectName: "softwareDetails_" + toolRow.modelData.name; text: toolRow.expanded ? "Close" : "Details"; quiet: true; onClicked: root.expandedSoftware = toolRow.expanded ? "" : toolRow.identity }
                                        }
                                        ColumnLayout {
                                            visible: toolRow.modelData.advisories.length > 0
                                            Layout.fillWidth: true; spacing: 8
                                            Copy { objectName: "securityScope_" + toolRow.modelData.installed; text: Model.securityVersionText(toolRow.modelData) + (toolRow.modelData.configured_versions && toolRow.modelData.configured_versions.length ? " · Global: " + toolRow.modelData.configured_versions.join(", ") : ""); Layout.fillWidth: true; color: root.amber }
                                            Copy { objectName: "securityFix_" + toolRow.modelData.installed; text: Model.fixedReleaseText(toolRow.modelData); Layout.fillWidth: true; font.weight: Font.Medium }
                                            Copy { text: toolRow.modelData.next_step || "Review the publisher notice and the tool's original installer."; Layout.fillWidth: true; color: root.muted }
                                            Repeater {
                                                model: toolRow.modelData.advisories
                                                delegate: ColumnLayout {
                                                    id: advisoryRow
                                                    required property var modelData
                                                    Layout.fillWidth: true
                                                    Copy { text: advisoryRow.modelData.id + " · " + (advisoryRow.modelData.summary || "Matched advisory"); Layout.fillWidth: true }
                                                    Action { text: "Read publisher advisory ↗"; quiet: true; onClicked: Qt.openUrlExternally("https://osv.dev/vulnerability/" + encodeURIComponent(advisoryRow.modelData.id)) }
                                                }
                                            }
                                        }
                                        ColumnLayout {
                                            visible: toolRow.expanded
                                            Layout.fillWidth: true; spacing: 10
                                            Copy { text: toolRow.modelData.next_step || "Identify its installer before updating."; Layout.fillWidth: true; color: root.muted; lineHeight: 1.4; font.pixelSize: 13 }
                                            Repeater { model: toolRow.modelData.advisories; delegate: Copy { required property var modelData; text: modelData.id + " · " + modelData.severity; Layout.fillWidth: true; color: root.amber } }
                                        }
                                    }
                                }
                            }
                        }
                        RowLayout {
                            visible: root.softwareMode !== "Security" && root.updateStage !== "review" && root.updateStage !== "applying" && root.updateStage !== "planning"
                            Layout.fillWidth: true
                            Action { objectName: "selectListedUpdatesButton"; text: "Select listed updates"; quiet: true; enabled: !root.busy; onClicked: root.selectListedUpdates() }
                            Action { objectName: "clearSelectionButton"; text: "Clear"; quiet: true; enabled: !root.busy && root.selectedTools.length > 0; onClicked: root.selectedTools = [] }
                            Item { Layout.fillWidth: true }
                            Action { objectName: "updateSelectedButton"; text: "Review selected (" + root.selectedTools.length + ")…"; primary: true; enabled: !root.busy && !root.aiBusy && root.selectedTools.length > 0; onClicked: root.reviewSelected() }
                        }
                        Copy { visible: root.softwareMode !== "Security"; text: root.softwareMode === "Unverified" ? "Launchers only. Ironclad won’t run them or guess how to update them." : "Advisories cover supported Python/npm tools. Interpreter/SDK CVEs and other installers aren’t covered yet."; color: root.muted; font.pixelSize: 13; Layout.fillWidth: true; lineHeight: 1.4 }
                    }
                    ColumnLayout {
                        visible: root.selected === "AI"
                        Layout.fillWidth: true; Layout.fillHeight: true; spacing: 14
                        RowLayout {
                            Layout.fillWidth: true
                            Rectangle { implicitWidth: 7; implicitHeight: 7; radius: 4; color: root.accent }
                            Copy { text: root.agentName; color: root.accent; font.pixelSize: 13; Layout.fillWidth: true }
                        }
                        Copy { text: "Ask about findings, protection or detection rules."; color: root.muted; Layout.fillWidth: true; font.pixelSize: 13 }
                        RowLayout {
                            Layout.fillWidth: true; spacing: 10
                            Input { Layout.fillWidth: true; text: root.aiQuestion; placeholderText: "What should I address first?"; onTextEdited: root.aiQuestion = text; Accessible.name: "Ask your signed-in agent"; enabled: !root.aiBusy; onAccepted: root.askAgent() }
                            Action { text: root.aiBusy ? "Asking…" : "Ask agent"; primary: true; enabled: !root.aiBusy && !root.busy; onClicked: root.askAgent() }
                        }
                        Copy { text: "Shares your question and a brief of this machine’s findings with your agent. Normal account limits apply. Advice and rule drafts only; nothing is validated or installed by AI."; color: root.muted; font.pixelSize: 13; Layout.fillWidth: true; lineHeight: 1.45 }
                        RowLayout {
                            Layout.fillWidth: true
                            Copy { text: root.aiMessage || "No extra setup. Your agent handles its own login."; color: root.muted; font.pixelSize: 13; Layout.fillWidth: true }
                            Action { text: "Cancel"; visible: root.aiBusy; quiet: true; onClicked: { root.askAfterBrief = false; advisor.running = false; root.aiMessage = "Cancelled." } }
                        }
                        Rectangle {
                            Layout.fillWidth: true; Layout.fillHeight: true
                            radius: 10; color: root.rail; border.color: root.line
                            ColumnLayout {
                                anchors.fill: parent; anchors.margins: 22; spacing: 12
                                RowLayout {
                                    Layout.fillWidth: true
                                    Copy { text: root.displayingAnswer ? "AI answer" : "Your brief"; font.pixelSize: 15; font.weight: Font.DemiBold; color: root.ink; Layout.fillWidth: true }
                                    Action { text: root.showBrief ? "Show answer" : "Show brief"; visible: !!root.aiAnswer; quiet: true; onClicked: root.showBrief = !root.showBrief }
                                }
                                ScrollView {
                                    Layout.fillWidth: true; Layout.fillHeight: true; clip: true
                                    TextArea {
                                        objectName: "advisorResponseText"
                                        text: root.displayingAnswer ? root.aiAnswer : root.aiBrief.substring(root.aiBrief.indexOf("Question:")) || "Ask about findings, ClamAV, Falco or detection rules. Includes reviewed official guides and the bundled policy; no live web browsing."
                                        readOnly: true; selectByMouse: true; wrapMode: TextEdit.Wrap; textFormat: TextEdit.PlainText
                                        color: root.displayingAnswer ? root.aiAnswerInk : root.aiBriefInk; font.family: "Inter"; font.pixelSize: 15; selectionColor: root.accent; selectedTextColor: root.accentInk; background: null
                                    }
                                }
                            }
                        }
                    }
                    ColumnLayout {
                        visible: root.selected === "Activity"
                        Layout.fillWidth: true; Layout.fillHeight: true; spacing: 16
                        RowLayout {
                            Layout.fillWidth: true
                            Copy { text: "Repairs & updates"; font.pixelSize: 18; font.weight: Font.DemiBold; Layout.fillWidth: true }
                            Action { objectName: "refreshActivityButton"; text: "Refresh history"; enabled: !root.busy; onClicked: root.loadActivity() }
                        }
                        Copy { text: "Actions are recorded locally, even when scan history is off. Results describe the check made at that time."; color: root.muted; font.pixelSize: 13; Layout.fillWidth: true }
                        Copy { visible: root.activityData.limits.length > 0; text: root.activityData.limits.join("\n"); color: root.amber; font.pixelSize: 13; Layout.fillWidth: true }
                        CheckBox { text: "Remember future scans on this machine"; checked: root.remember; onToggled: root.remember = checked; palette.windowText: root.ink; palette.text: root.ink }
                        RowLayout {
                            Action { text: "Review baseline…"; enabled: root.history.length > 0; onClicked: root.reviewAction("baseline.replace") }
                            Action { text: "Export report"; enabled: !root.busy; onClicked: root.chooseReport() }
                        }
                        ScrollView {
                            id: activityScroll
                            objectName: "activityScroll"
                            Layout.fillWidth: true; Layout.fillHeight: true; clip: true
                            contentWidth: availableWidth
                            ScrollBar.vertical.policy: ScrollBar.AlwaysOn
                            ColumnLayout {
                                width: activityScroll.availableWidth; spacing: 12
                                Copy { objectName: "emptyActivity"; visible: !root.activityData.entries.length; text: "No repairs or app updates recorded yet. Completed actions and incomplete attempts will appear here."; Layout.fillWidth: true; color: root.muted }
                                Repeater {
                                    model: root.activityData.entries
                                    delegate: Rectangle {
                                        id: activityRow
                                        required property var modelData
                                        Layout.fillWidth: true
                                        implicitHeight: activityContent.implicitHeight + 28
                                        radius: 9; color: root.surface
                                        ColumnLayout {
                                            id: activityContent
                                            anchors { left: parent.left; right: parent.right; top: parent.top; margins: 14 }
                                            spacing: 8
                                            RowLayout {
                                                Layout.fillWidth: true
                                                Copy { text: activityRow.modelData.title; Layout.fillWidth: true; font.weight: Font.DemiBold }
                                                Copy { objectName: "activityOutcome_" + activityRow.modelData.id; text: activityRow.modelData.outcome === "verified" ? "Verified at the time" : activityRow.modelData.outcome === "incomplete" ? "No completion record" : "Couldn’t verify"; color: activityRow.modelData.outcome === "verified" ? root.accent : root.amber; font.pixelSize: 13 }
                                            }
                                            Copy { text: activityRow.modelData.target + " · " + (activityRow.modelData.at ? new Date(activityRow.modelData.at).toLocaleString() : "Time not recorded"); Layout.fillWidth: true; color: root.muted; font.pixelSize: 13 }
                                            Copy { visible: !!activityRow.modelData.versions; text: activityRow.modelData.versions; Layout.fillWidth: true; font.pixelSize: 13 }
                                            Copy { text: activityRow.modelData.detail; Layout.fillWidth: true; lineHeight: 1.35; font.pixelSize: 13 }
                                            Copy { visible: !!activityRow.modelData.recovery; text: "Undo / recovery: " + activityRow.modelData.recovery; Layout.fillWidth: true; color: root.muted; lineHeight: 1.35; font.pixelSize: 13 }
                                        }
                                    }
                                }
                                Copy { text: "Saved scans"; font.weight: Font.DemiBold; Layout.topMargin: 8 }
                                Copy { text: root.history.length ? root.history.map(s => new Date(s.collected_at).toLocaleString() + " · " + s.checks + " observations").join("\n\n") : "Saved-history list is off. Previous scans are still gzip-archived when you rescan."; Layout.fillWidth: true; color: root.muted; font.pixelSize: 13 }
                                Copy { visible: root.actionHistory.length > 0; text: "Permission change records\n" + root.actionHistory.map(a => a.receipt + " · " + a.status).join("\n"); Layout.fillWidth: true; color: root.muted; font.pixelSize: 13 }
                            }
                        }
                        RowLayout {
                            Action { text: "Review daily scans…"; quiet: true; onClicked: root.reviewSchedule("enable") }
                            Action { text: "Stop daily scans…"; quiet: true; onClicked: root.reviewSchedule("disable") }
                        }
                        Copy { text: "Ironclad 0.2.36  ·  Zero Day Security LLC\nReview current maintenance in Protection → Updates."; color: root.muted; Layout.fillWidth: true; font.pixelSize: 13; lineHeight: 1.5 }
                    }
                    RowLayout {
                        visible: root.ignoreMessage.length > 0
                        Layout.fillWidth: true
                        Copy { text: root.ignoreMessage; color: root.muted; Layout.fillWidth: true; maximumLineCount: 2; elide: Text.ElideRight }
                        Action { objectName: "undoIgnoreButton"; text: "Undo"; visible: root.undoIgnoreId.length > 0; enabled: !findingPreferences.running; onClicked: root.changeFindingPreference("restore", root.undoIgnoreId) }
                        Action { text: "Dismiss"; quiet: true; onClicked: { root.ignoreMessage = ""; root.undoIgnoreId = "" } }
                    }
                    Rectangle { Layout.fillWidth: true; implicitHeight: 1; color: root.line }
                    Copy { text: root.message; color: root.muted; font.pixelSize: 13; Layout.fillWidth: true; maximumLineCount: 2; elide: Text.ElideRight }
                }
            }
            Rectangle {
                anchors.fill: parent
                visible: root.malwareStage !== "idle"
                color: root.canvas; radius: 13; z: 30
                MouseArea { anchors.fill: parent }
                ColumnLayout {
                    anchors.fill: parent; anchors.margins: 24; spacing: 16
                    RowLayout {
                        Layout.fillWidth: true
                        Copy { text: root.malwareStage === "setup" ? "Setting up scanner…" : root.malwareStage === "setup-done" ? "Scanner setup" : root.malwareStage === "install-review" || root.malwareStage === "signatures-review" ? "Review scanner setup" : root.malwareStage === "review" ? "Review file scan" : root.malwareStage === "scanning" ? "Scanning locally…" : root.malwareResult && root.malwareResult.outcome === "detected" ? "File flagged" : root.malwareResult && root.malwareResult.outcome === "no_detection" ? "No detection in this file" : "File scan"; font.pixelSize: 23; font.weight: Font.DemiBold; Layout.fillWidth: true }
                        Action { objectName: "closeMalwareButton"; visible: !malwareRequest.running; text: "Close"; onClicked: root.dismissMalware() }
                    }
                    Copy { objectName: "malwareMessage"; text: root.malwareMessage; Layout.fillWidth: true; lineHeight: 1.4 }
                    ScrollView {
                        id: malwareScroll
                        Layout.fillWidth: true; Layout.fillHeight: true; clip: true
                        contentWidth: availableWidth
                        ScrollBar.vertical.policy: ScrollBar.AlwaysOn
                        ColumnLayout {
                            width: malwareScroll.availableWidth; spacing: 16
                            Copy { visible: !!root.malwarePlan; text: root.malwarePlan ? root.malwarePlan.name : ""; Layout.fillWidth: true; font.pixelSize: 18; font.weight: Font.DemiBold }
                            Copy { visible: !!root.malwarePlan; text: root.malwarePlan ? root.malwarePlan.path + "\n" + (root.malwarePlan.bytes / 1048576).toFixed(2) + " MiB" : ""; color: root.muted; Layout.fillWidth: true; lineHeight: 1.4 }
                            Copy { visible: !!root.malwarePlan; text: root.malwarePlan ? root.malwarePlan.coverage : ""; Layout.fillWidth: true; lineHeight: 1.4 }
                            Copy { visible: root.malwareStage === "install-review"; text: "Install ClamAV, Bubblewrap isolation and their required package dependencies. An OS authentication prompt may appear. No recurring file scan is enabled. If the package is unavailable, run the normal Omarchy update and try again."; Layout.fillWidth: true; lineHeight: 1.4; color: root.muted }
                            Copy { visible: root.malwareStage === "signatures-review"; text: "Source: database.clamav.net (ClamAV’s official signature service).\n\nThis can download a large database. It updates Ironclad’s private signatures, leaves system scanner configuration unchanged, and does not run a file scan."; Layout.fillWidth: true; lineHeight: 1.4; color: root.muted }
                            Copy { visible: !!root.malwareResult && root.malwareResult.detections.length > 0; text: root.malwareResult ? root.malwareResult.detections.join("\n") : ""; color: root.amber; Layout.fillWidth: true }
                            Copy { visible: !!root.malwareResult && root.malwareResult.outcome === "detected"; text: "What to do: don’t open or run this file. Verify where it came from and seek review; a scanner flag can be a false positive. Ironclad has not deleted or quarantined it."; Layout.fillWidth: true; lineHeight: 1.4 }
                            Copy { text: "File contents stay on this machine. Results are not sent to AI. A scan can miss threats; it does not certify the rest of the machine."; Layout.fillWidth: true; color: root.muted; lineHeight: 1.4 }
                        }
                    }
                    RowLayout {
                        Layout.fillWidth: true
                        Action { objectName: "approveMalwareButton"; visible: root.malwareStage === "review"; text: "Scan selected file"; primary: true; enabled: !root.busy && !root.aiBusy; onClicked: root.approveMalwareScan() }
                        Action { objectName: "approveScannerSetupButton"; visible: root.malwareStage === "install-review" || root.malwareStage === "signatures-review"; text: root.malwareStage === "install-review" ? "Install ClamAV" : "Download signatures"; primary: true; enabled: !root.busy && !root.aiBusy; onClicked: root.approveScannerSetup() }
                        Action { objectName: "cancelMalwareButton"; visible: malwareRequest.running; text: "Stop scan"; onClicked: root.cancelMalwareScan() }
                        Item { Layout.fillWidth: true }
                    }
                }
            }
            Rectangle {
                anchors.fill: parent
                visible: root.fixStage !== "idle"
                color: root.canvas
                radius: 13
                z: 20
                MouseArea { anchors.fill: parent }
                ColumnLayout {
                    anchors.fill: parent; anchors.margins: 24; spacing: 14
                    RowLayout {
                        Layout.fillWidth: true
                        Copy { text: root.repairScanState === "resolved" ? "Finding cleared on rescan" : root.repairScanState === "remaining" ? "Still needs attention" : root.repairScanState === "unknown" ? "Couldn’t verify the finding" : root.fixStage === "done" ? "Repair verified · checking again" : root.fixStage === "error" ? "Fix needs attention" : "Review fix"; font.pixelSize: 23; font.weight: Font.DemiBold; Layout.fillWidth: true }
                        Action { objectName: "closeFixButton"; text: root.fixStage === "done" || root.fixStage === "error" ? "Back to findings" : "Cancel"; enabled: !fixRequest.running && !fixTerminal.running; onClicked: root.dismissFix() }
                    }
                    Copy { text: root.fixCheckId; color: root.muted; font.pixelSize: 13; Layout.fillWidth: true }
                    Copy { text: root.fixMessage; color: root.fixStage === "error" ? root.amber : root.ink; Layout.fillWidth: true; lineHeight: 1.4 }
                    ScrollView {
                        id: fixScroll
                        Layout.fillWidth: true; Layout.fillHeight: true; clip: true
                        contentWidth: availableWidth
                        ScrollBar.vertical.policy: ScrollBar.AlwaysOn
                        ColumnLayout {
                            width: fixScroll.availableWidth; spacing: 16
                            Copy { visible: !!root.fixManual; text: root.fixManual; color: root.amber; Layout.fillWidth: true; lineHeight: 1.4 }
                            Repeater {
                                model: root.fixStage === "choose" ? root.fixPlans : []
                                delegate: ColumnLayout {
                                    id: repairChoice
                                    required property var modelData
                                    Layout.fillWidth: true; spacing: 8
                                    Copy { text: repairChoice.modelData.title; font.weight: Font.DemiBold; Layout.fillWidth: true }
                                    Copy { text: repairChoice.modelData.impact; color: root.muted; Layout.fillWidth: true }
                                    Action { objectName: "chooseFix_" + repairChoice.modelData.action_id + ":" + repairChoice.modelData.target; text: "Review this fix"; onClicked: root.chooseFix(repairChoice.modelData) }
                                }
                            }
                            ColumnLayout {
                                visible: !!root.fixPlan
                                Layout.fillWidth: true; spacing: 12
                                Copy { text: root.fixPlan ? root.fixPlan.title : ""; font.pixelSize: 17; font.weight: Font.DemiBold; Layout.fillWidth: true }
                                Copy { text: root.fixPlan ? "Target: " + root.fixPlan.target + (root.fixPlan.privileged ? "\nAdministrator authentication will be requested in a visible terminal." : "\nRuns as your normal user.") : ""; Layout.fillWidth: true; color: root.muted }
                                Copy { text: "What changes"; font.weight: Font.DemiBold; color: root.accent }
                                Copy { objectName: "fixImpact"; text: root.fixPlan ? root.fixPlan.impact : ""; Layout.fillWidth: true; lineHeight: 1.4 }
                                Copy { text: "Exact operation"; font.weight: Font.DemiBold; color: root.accent }
                                Copy { objectName: "fixCommands"; text: root.fixPlan ? root.fixPlan.commands.length ? root.fixPlan.commands.map(c => (root.fixPlan.privileged ? "sudo " : "") + c.join(" ")).join("\n") : root.fixPlan.implementation : ""; Layout.fillWidth: true; lineHeight: 1.4 }
                                Copy { text: "Undo / recovery"; font.weight: Font.DemiBold; color: root.accent }
                                Copy { text: root.fixPlan ? root.fixPlan.undo : ""; Layout.fillWidth: true; lineHeight: 1.4 }
                                Copy { text: "How it is checked"; font.weight: Font.DemiBold; color: root.accent }
                                Copy { text: root.fixPlan ? root.fixPlan.verification : ""; Layout.fillWidth: true; lineHeight: 1.4 }
                            }
                            Copy { visible: !!root.fixResult && !!root.fixResult.undo_receipt; text: root.fixResult && root.fixResult.undo_receipt ? "Permission undo receipt: " + root.fixResult.undo_receipt : ""; Layout.fillWidth: true; color: root.muted }
                        }
                    }
                    RowLayout {
                        Layout.fillWidth: true
                        Action { objectName: "applyFixButton"; text: "Apply fix"; primary: true; visible: root.fixStage === "review"; enabled: !root.busy && !root.aiBusy; onClicked: root.approveFix() }
                        Action { objectName: "manualFixPlanButton"; text: "Plan the manual steps with AI"; visible: root.fixStage === "manual" || root.fixStage === "error"; enabled: !root.busy && !root.aiBusy; onClicked: { const checkId = root.fixCheckId; const context = root.fixManual; root.dismissFix(); root.planFindingFix(checkId, context) } }
                        Item { Layout.fillWidth: true }
                        Copy { text: root.fixStage === "review" ? "Nothing changes until you click Apply fix." : ""; color: root.muted; font.pixelSize: 13 }
                    }
                }
            }
        }
    }
}
