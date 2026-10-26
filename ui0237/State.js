// Pure data functions: imported by QML, tested with Node without a shell instance.
function validate(result) {
    if (!result || result.schema_version !== "1.0" || typeof result.collected_at !== "string" || !Array.isArray(result.checks) || result.checks.length > 512) throw new Error("schema")
    const states = ["pass", "attention", "critical", "unavailable", "error", "not_applicable", "observed"]
    const levels = ["info", "low", "medium", "high", "critical"]
    const seen = {}
    for (const c of result.checks) {
        if (!c || typeof c.check_id !== "string" || !/^[a-z][a-z0-9_.]{1,100}$/.test(c.check_id) || seen[c.check_id] || states.indexOf(c.status) < 0 || levels.indexOf(c.severity) < 0) throw new Error("check")
        seen[c.check_id] = true
        if (c.remediation_steps !== undefined && (!Array.isArray(c.remediation_steps) || c.remediation_steps.length > 5 || c.remediation_steps.some(s => typeof s !== "string" || s.length > 512))) throw new Error("steps")
        if (c.verification !== undefined && (typeof c.verification !== "string" || c.verification.length > 512)) throw new Error("verification")
        for (const key of ["summary", "recommendation", "confidence", "reversibility"]) if (typeof c[key] !== "string" || c[key].length > 2048) throw new Error("field")
        if (!Array.isArray(c.evidence) || c.evidence.length > 16 || !Array.isArray(c.remediation_action_ids) || c.remediation_action_ids.length > 16) throw new Error("evidence")
        for (const e of c.evidence) if (!e || typeof e.source !== "string" || typeof e.value !== "string" || e.source.length > 2048 || e.value.length > 2048) throw new Error("evidence")
    }
    return result
}
function counts(checks) {
    const result = {review: 0, observed: 0, unavailable: 0, passed: 0, facts: 0, notApplicable: 0, total: checks.length}
    for (const c of checks) {
        if (c.status === "attention" || c.status === "critical" || c.status === "error") result.review++
        if (c.status === "pass" || c.status === "observed") result.observed++
        if (c.status === "pass") result.passed++
        if (c.status === "observed") result.facts++
        if (c.status === "not_applicable") result.notApplicable++
        if (c.status === "unavailable" || c.status === "not_applicable") result.unavailable++
    }
    return result
}
function section(id) {
    if (["sysctl.", "kconfig.", "cpu_mitigation.", "metadata.", "service.", "protection."].some(prefix => id.indexOf(prefix) === 0)) return "Security"
    if (id.indexOf("mount.") === 0) return "Storage"
    if (id.indexOf("listener.") === 0) return "Network"
    if (id.indexOf("performance.") === 0) return "Performance"
    if (id.indexOf("security.") === 0) return "Security"
    if (id.indexOf("storage.") === 0 || id.indexOf("system.disk.") === 0) return "Storage"
    if (id.indexOf("startup.") === 0) return "Startup"
    if (id.indexOf("packages.") === 0) return "Packages"
    if (id.indexOf("network.") === 0) return "Network"
    if (id.indexOf("recovery.") === 0) return "Backups"
    if (id.indexOf("developer.") === 0) return "Developer"
    if (id.indexOf("hardware.") === 0) return "Hardware"
    return "Overview"
}
function filtered(checks, selected, query, reviewOnly) {
    const severity = {critical: 4, high: 3, medium: 2, low: 1, info: 0}
    query = String(query || "").toLowerCase()
    return checks.filter(c => (selected === "Overview" || selected === "Diagnostics" || section(c.check_id) === selected)
        && (selected !== "Overview" || c.status === "attention" || c.status === "critical" || c.status === "error")
        && (!reviewOnly || c.status === "attention" || c.status === "critical" || c.status === "error")
        && (c.check_id + " " + c.summary + " " + c.status).toLowerCase().indexOf(query) >= 0)
        .slice().sort((a,b) => (severity[b.severity] - severity[a.severity]) || a.check_id.localeCompare(b.check_id))
}
function supportedAction(c) {
    const ids = c.remediation_action_ids
    if (!ids || typeof ids.length !== "number" || ids.length > 16) return false
    for (let i = 0; i < ids.length; i++) if (ids[i] === "home.remove_world_write") return true
    return false
}
function evidence(c) {
    const lines = []
    for (let i = 0; i < c.evidence.length; i++) lines.push(c.evidence[i].source + "\n" + c.evidence[i].value)
    return lines.join("\n\n")
}
function software(data) {
    if (!data || data.schema !== 2 || !Array.isArray(data.items) || data.items.length > 2304 || typeof data.observed_at !== "string" || typeof data.fresh !== "boolean" || !Array.isArray(data.limits)) throw new Error("software schema")
    const statuses = ["security review", "update available", "no listed update", "check for updates", "installed version", "manager review", "identify installer"]
    for (const item of data.items) {
        if (!item || typeof item.name !== "string" || typeof item.installed !== "string" || !/^[A-Za-z0-9][A-Za-z0-9@+_.:/~-]{0,159}$/.test(item.name) || !/^[A-Za-z0-9][A-Za-z0-9+_.:~/-]{0,119}$/.test(item.installed) || ["mise", "uv tool", "Flatpak user", "local launcher"].indexOf(item.source) < 0 || statuses.indexOf(item.status) < 0 || !Array.isArray(item.advisories) || item.advisories.length > 256) throw new Error("software item")
        if (item.available !== null && (typeof item.available !== "string" || !/^[A-Za-z0-9][A-Za-z0-9+_.:~/-]{0,119}$/.test(item.available))) throw new Error("software version")
        if (item.security_fixed_versions !== undefined && (!Array.isArray(item.security_fixed_versions) || item.security_fixed_versions.length > 32 || item.security_fixed_versions.some(v => typeof v !== "string" || !/^[0-9][A-Za-z0-9.+_-]{0,79}$/.test(v)))) throw new Error("security fixed release metadata")
        if (item.configured_versions !== undefined && (!Array.isArray(item.configured_versions) || item.configured_versions.length > 64 || item.configured_versions.some(v => typeof v !== "string" || !/^[A-Za-z0-9][A-Za-z0-9+_.:~/-]{0,119}$/.test(v)))) throw new Error("configured version metadata")
        for (const advisory of item.advisories) {
            if (advisory && advisory.known_exploited !== undefined && typeof advisory.known_exploited !== "boolean") throw new Error("exploit evidence")
            if (advisory && advisory.summary !== undefined && (typeof advisory.summary !== "string" || advisory.summary.length > 400)) throw new Error("advisory summary")
            if (!advisory || !/^[A-Za-z0-9][A-Za-z0-9._:-]{1,119}$/.test(advisory.id) || !Array.isArray(advisory.issues) || advisory.issues.length > 64 || ["critical", "high", "medium", "low", "unknown"].indexOf(advisory.severity) < 0 || advisory.issues.some(c => typeof c !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{1,119}$/.test(c))) throw new Error("advisory")
        }
    }
    return data
}
function softwareItems(items, query, updatesOnly) {
    query = String(query || "").toLowerCase()
    return items.filter(i => (!updatesOnly || i.available || i.advisories.length) && (i.name + " " + i.source).toLowerCase().indexOf(query) >= 0)
        .slice().sort((a,b) => (Number(b.advisories.length > 0) - Number(a.advisories.length > 0)) || (Number(!!b.available) - Number(!!a.available)) || a.name.localeCompare(b.name))
}
function highlights(checks) {
    return ["performance.cpu.load", "performance.memory", "system.disk.free_space"].map(id => checks.find(c => c.check_id === id)).filter(c => !!c)
}

function nextSteps(c) { return c.remediation_steps && c.remediation_steps.length ? c.remediation_steps : [c.recommendation] }
function canUpdate(i) { return (i.source === "mise" && i.active && !!i.available) || i.source === "uv tool" || i.source === "Flatpak user" }

function appItems(items, query, mode) {
    const active = {}
    for (const i of items) if (i.source === "mise" && i.active) active[i.name] = true
    return softwareItems(items, query, false).filter(i => mode === "Security" ? i.advisories.length > 0 : mode === "Updates" ? !!i.available && canUpdate(i) : mode === "Unverified" ? i.source === "local launcher" : mode === "All versions" ? true : i.source !== "local launcher" && (i.source !== "mise" || i.active || !active[i.name]))
}

function updatePlan(plan) {
    if (!plan || plan.schema !== 2 || plan.operation !== "user-application-update" || typeof plan.digest !== "string" || !/^[a-f0-9]{64}$/.test(plan.digest) || !Array.isArray(plan.command) || plan.command.length > 16) throw new Error("update plan")
    if (["mise", "uv tool", "Flatpak user"].indexOf(plan.source) < 0 || plan.command[0] !== ({mise:"/usr/bin/mise", "uv tool":"/usr/bin/uv", "Flatpak user":"/usr/bin/flatpak"})[plan.source]) throw new Error("manager")
    for (const k of ["name", "target", "installed", "scope", "impact", "recovery"]) if (typeof plan[k] !== "string" || plan[k].length > 2048) throw new Error("plan field")
    if (plan.target !== plan.source + ":" + plan.name || !/^[A-Za-z0-9][A-Za-z0-9@+_.:/~-]{0,159}$/.test(plan.name)) throw new Error("target")
    for (const arg of plan.command) if (typeof arg !== "string" || arg.length > 512) throw new Error("argument")
    return plan
}

// These inspection commands are fixed by the app, never supplied by AI output.
function inspection(checkId) {
    const commands = {
        "startup.units.system_failed": {label:"Inspect failed services", command:["/usr/bin/systemctl", "--failed", "--no-pager", "--plain"]},
        "startup.units.user_failed": {label:"Inspect failed user services", command:["/usr/bin/systemctl", "--user", "--failed", "--no-pager", "--plain"]},
        "network.listeners": {label:"Inspect listening ports", command:["/usr/bin/ss", "--listening", "--numeric", "--tcp", "--udp"]}
    }
    return commands[checkId] || null
}
function fixQuestion(check, explanation) {
    const instructions = "Give a specific plan in plain English. Identify missing information first. Include exact settings or commands to review, what each changes, how to undo it, and how to verify the outcome. Do not apply changes or assume approval."
    const context = "Help me address this finding: " + check.check_id + " — " + check.summary + ". " + (explanation ? "Current advice: " + explanation.action + ". " : "")
    return instructions + "\n" + context.substring(0, 999 - instructions.length)
}

function repairPlan(plan) {
    const allowed = ["home.remove_world_write", "service.retry-user", "service.retry-system", "network.stop-discovery", "security.enable-aslr", "clock.enable-sync"]
    if (!plan || plan.schema !== 1 || allowed.indexOf(plan.action_id) < 0 || !/^[a-f0-9]{64}$/.test(plan.digest) || typeof plan.privileged !== "boolean" || !Array.isArray(plan.commands) || plan.commands.length > 1) throw new Error("repair plan")
    for (const key of ["check_id", "target", "title", "impact", "undo", "verification", "implementation"]) if (typeof plan[key] !== "string" || plan[key].length > 2048) throw new Error("repair field")
    const command = plan.commands[0]
    if (plan.action_id === "home.remove_world_write") {
        if (plan.commands.length || plan.privileged) throw new Error("home repair")
    } else {
        if (!Array.isArray(command) || command.some(a => typeof a !== "string" || a.length > 256) || command.length > 6) throw new Error("repair command")
        const exact = {"security.enable-aslr":["/usr/bin/sysctl","-w","kernel.randomize_va_space=2"], "clock.enable-sync":["/usr/bin/timedatectl","set-ntp","true"]}
        if (exact[plan.action_id] && JSON.stringify(command) !== JSON.stringify(exact[plan.action_id])) throw new Error("repair command")
        if (plan.action_id.indexOf("service.retry-") === 0) {
            const expected = ["/usr/bin/systemctl"].concat(plan.action_id === "service.retry-user" ? ["--user"] : []).concat(["restart",plan.target])
            if (!/^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,180}\.service$/.test(plan.target) || JSON.stringify(command) !== JSON.stringify(expected)) throw new Error("service repair")
        }
        if (plan.action_id === "network.stop-discovery" && (command[0] !== "/usr/bin/systemctl" || command[1] !== "stop" || command.length < 3 || command.slice(2).some(u => ["avahi-daemon.socket","avahi-daemon.service"].indexOf(u) < 0))) throw new Error("discovery repair")
    }
    return plan
}

function affected(c) {
    if (c.check_id === "network.listeners") {
        const entry = c.evidence.find(e => e.source === "ss protocol/port/scope; first 16 only")
        try {
            const ports = entry ? JSON.parse(entry.value) : []
            if (!Array.isArray(ports) || ports.length > 16) throw new Error("ports")
            const labels = ports.filter(p => ["tcp", "udp"].indexOf(p.protocol) >= 0 && Number.isInteger(p.port) && p.port > 0 && p.port <= 65535 && ["wildcard", "loopback", "specific-address"].indexOf(p.bind_scope) >= 0)
                .map(p => p.protocol.toUpperCase() + " " + p.port + " (" + (p.bind_scope === "wildcard" ? "all network interfaces" : p.bind_scope === "loopback" ? "this machine only" : "one network address") + ")")
            return [...new Set(labels)].join(" · ") || "Listening network ports; owning application has not been identified."
        } catch (_) { return "Listening network ports; inspect locally to identify the application." }
    }
    if (c.check_id.indexOf("startup.units.") === 0 && c.check_id.indexOf("failed") >= 0) {
        const entry = c.evidence.find(e => e.source === "Known failed platform services; instances omitted")
        return entry ? entry.value : "Failed " + (c.check_id.indexOf("user_failed") >= 0 ? "user" : "system") + " services; inspect locally for exact targets."
    }
    const labels = {"security.home.permissions":"Your home folder · permissions", "security.kernel.aslr":"Kernel · address randomization", "security.boot.secure_boot":"Firmware · Secure Boot", "network.clock":"System clock · time synchronization", "security.firewall":"Network firewall · enforcement", "security.process.metadata":"Running applications · executable metadata", "developer.container.access":"Container tools · account access"}
    return labels[c.check_id] || section(c.check_id) + " · " + c.check_id.split(".").slice(1).join(" / ")
}
function followUp(checks, checkId) {
    const check = checks.find(c => c.check_id === checkId)
    if (!check || ["unavailable", "error", "not_applicable", "observed"].indexOf(check.status) >= 0)
        return {state:"unknown", title:"Couldn’t verify the finding", detail:"The fresh scan could not establish this finding’s state. Review the steps and scan again."}
    if (check.status === "pass")
        return {state:"resolved", title:"Finding cleared on rescan", detail:"The fresh scan no longer flags this condition. Check that the affected feature works as intended."}
    return {state:"remaining", title:"Still needs attention", detail:"The fresh scan still flags this finding. A repair may address only one part; review the remaining targets before trying another change."}
}
function activityRows(data) {
    if (!data || !Array.isArray(data.entries) || data.entries.length > 64 || !Array.isArray(data.limits) || data.limits.length > 8) throw new Error("activity")
    for (const row of data.entries) {
        if (!row || ["repair", "update"].indexOf(row.kind) < 0 || ["verified", "unverified", "incomplete"].indexOf(row.outcome) < 0) throw new Error("activity entry")
        for (const key of ["id", "at", "title", "target", "detail", "recovery", "versions", "check_id"]) if (typeof row[key] !== "string" || row[key].length > 2048) throw new Error("activity field")
    }
    if (data.limits.some(v => typeof v !== "string" || v.length > 512)) throw new Error("activity limits")
    return data
}

function canReviewRepair(check) {
    return ["security.home.permissions", "security.kernel.aslr", "network.clock", "network.listeners", "startup.units.system_failed", "startup.units.user_failed"].indexOf(check.check_id) >= 0
}

function protectionRisks(data) {
    const rows = []
    for (const item of data.items) for (const advisory of item.advisories) {
        rows.push({item:item, advisory:advisory, priority:advisory.known_exploited === true ? 4 : advisory.severity === "critical" ? 3 : advisory.severity === "high" ? 2 : 1})
    }
    return rows.sort((a,b) => b.priority - a.priority || a.item.name.localeCompare(b.item.name)).slice(0,64)
}
function automaticMalwareState(data) {
    if (!data || data.schema !== 1 || typeof data.installed !== "boolean" || typeof data.active !== "boolean" || ["notify", "prevent", null].indexOf(data.mode) < 0 || data.scope !== "Downloads" || ["not_installed","not_configured","stopped","starting","unavailable","degraded","protecting","scanning"].indexOf(data.state) < 0) throw new Error("automatic malware state")
    for (const k of ["message","coverage"]) if (typeof data[k] !== "string" || data[k].length > 2048) throw new Error("automatic malware text")
    if (data.active && (!data.installed || ["protecting","scanning"].indexOf(data.state) < 0 || data.mode !== (data.state === "protecting" ? "prevent" : "notify"))) throw new Error("automatic malware readiness")
    if (!Array.isArray(data.events) || data.events.length > 64 || !Number.isSafeInteger(data.scanned) || data.scanned < 0 || !Number.isSafeInteger(data.errors) || data.errors < 0 || typeof data.automatic_signatures !== "boolean") throw new Error("automatic malware events")
    for (const e of data.events) {
        if (!e || !/^[a-f0-9]{24}$/.test(e.id) || typeof e.reviewed !== "boolean") throw new Error("detection record")
        for (const k of ["name","detection","time"]) if (typeof e[k] !== "string" || e[k].length > 200 || /[\x00-\x1f]/.test(e[k])) throw new Error("detection text")
    }
    return data
}
function automaticMalwarePlan(plan) {
    if (!plan || plan.schema !== 1 || !/^[a-f0-9]{64}$/.test(plan.digest) || ["notify","prevent","disable"].indexOf(plan.action) < 0 || plan.scope !== "Downloads" || typeof plan.title !== "string" || plan.title.length > 200 || typeof plan.impact !== "string" || plan.impact.length > 2048) throw new Error("automatic malware plan")
    return plan
}

function protectionState(data) {
    if (!data || data.schema !== 1 || !data.scanner || typeof data.scanner.installed !== "boolean" || typeof data.scanner.ready !== "boolean" || (typeof data.continuous_monitoring !== "boolean" || data.continuous_monitoring && (!data.sensor || data.sensor.monitoring !== true)) || data.zero_day_assurance !== false || !Array.isArray(data.limits) || data.limits.length > 8) throw new Error("protection state")
    for (const key of ["message","coverage"]) if (typeof data.scanner[key] !== "string" || data.scanner[key].length > 2048) throw new Error("scanner state")
    if (data.scanner.sandbox_available !== undefined && typeof data.scanner.sandbox_available !== "boolean") throw new Error("scanner sandbox state")
    if (data.updates) {
        const u = data.updates
        if (typeof u.automatic !== "boolean" || !Array.isArray(u.issues) || u.issues.length > 16 || u.issues.some(v => typeof v !== "string" || v.length > 512) || !Array.isArray(u.engines) || u.engines.length > 2 || typeof u.plugin_update !== "string" || u.plugin_update.length > 1024 || typeof u.policy_version !== "string") throw new Error("update health")
        for (const e of u.engines) if (["clamav","falco"].indexOf(e.name) < 0 || typeof e.update_available !== "boolean" || [e.installed,e.latest].some(v => v !== null && (typeof v !== "string" || !/^[0-9]+\.[0-9]+\.[0-9]+$/.test(v)))) throw new Error("engine health")
    }
    if (data.automatic_malware) automaticMalwareState(data.automatic_malware)
    if (data.rule_updates) {
        const r = data.rule_updates
        if (typeof r.available !== "boolean" || typeof r.installed !== "boolean" || typeof r.enabled !== "boolean" || !Number.isInteger(r.rules) || r.rules < 0 || r.rules > 128 || typeof r.message !== "string" || r.message.length > 1024 || ["unavailable","not_checked","checking","ok","failed","needs_attention"].indexOf(r.state) < 0) throw new Error("Falco rule update health")
    }
    if (data.last_scan) malwareResult(data.last_scan)
    return data
}
function malwarePlan(plan) {
    if (!plan || plan.schema !== 1 || !/^[a-f0-9]{64}$/.test(plan.digest) || typeof plan.path !== "string" || plan.path.length > 4096 || typeof plan.name !== "string" || plan.name.length > 255 || !Number.isInteger(plan.bytes) || plan.bytes <= 0 || plan.bytes > 104857600 || typeof plan.coverage !== "string" || plan.coverage.length > 2048) throw new Error("file scan plan")
    return plan
}
function malwareResult(result) {
    if (!result || result.schema !== 1 || ["no_detection","detected","incomplete","interrupted"].indexOf(result.outcome) < 0 || !Array.isArray(result.detections) || result.detections.length > 16) throw new Error("file scan result")
    for (const key of ["name","message","coverage","finished_at"]) if (typeof result[key] !== "string" || result[key].length > 2048) throw new Error("scan text")
    if (result.detections.some(v => typeof v !== "string" || v.length > 200)) throw new Error("detection text")
    return result
}

function overviewFindings(checks, ignored) {
    return filtered(checks, "Overview", "", false).filter(c => ignored.indexOf(c.check_id) < 0).slice(0, 3)
}
function overviewHealth(capability, monitor) {
    const scanner = capability && capability.scanner
    const updates = capability && capability.updates
    const automatic = capability && capability.automatic_malware
    const active = monitor && monitor.state === "monitoring" && monitor.monitoring === true
    const age = scanner && scanner.signatures_age_hours
    const fresh = scanner && scanner.ready && typeof age === "number" && age >= 0 && age <= 24
    return [
        {id:"monitor",label:"Behavior monitoring",value:!monitor ? "Not verified" : active ? "Monitoring" : monitor.state === "degraded" ? "Coverage gaps" : "Needs attention",detail:!monitor ? "Check status in Protection" : active ? "Fresh sensor activity verified" : "Review the sensor in Protection",warning:!!monitor && !active},
        {id:"signatures",label:"Malware signatures",value:!scanner ? "Not verified" : fresh ? "Fresh" : "Needs attention",detail:!scanner ? "Check scanner status in Protection" : typeof age === "number" ? age + " hours old · selected-file scans" : "Set up the scanner in Protection",warning:!!scanner && !fresh},
        {id:"updates",label:"Protection updates",value:!updates ? "Not verified" : updates.automatic && updates.issues.length === 0 ? "Current" : "Needs attention",detail:!updates ? "Check maintenance status in Protection" : updates.automatic ? (updates.issues.length ? "Update warnings need review" : "Automatic maintenance enabled") : "Automatic maintenance is off",warning:!!updates && (!updates.automatic || updates.issues.length > 0)},
        {id:"malware",label:"Automatic malware",value:!automatic ? "Not verified" : automatic.active ? automatic.mode === "prevent" ? "Protecting Downloads" : "Scanning Downloads" : "Not active",detail:!automatic ? "Check automatic scanning in Protection" : automatic.active ? automatic.mode === "prevent" ? "Detected files denied · errors fail open" : "Alert-only mode · no blocking" : "One-off file scans remain separate",warning:!!automatic && automatic.installed && !automatic.active}
    ]
}

function findingTitle(check) {
    const titles = {
        "security.home.permissions": "Home folder access needs review",
        "network.listeners": "Listening network services need context",
        "startup.units.system_failed": "System services need review",
        "security.boot.secure_boot": "Secure Boot needs a manual check"
    }
    return ["attention", "critical", "error"].indexOf(check.status) >= 0 && titles[check.check_id] ? titles[check.check_id] : check.summary
}
function displayTime(value) {
    const time = new Date(value)
    return isNaN(time.getTime()) ? value : time.toLocaleString()
}

function softwareSecurity(items) {
    const affected = items.filter(i => i.advisories.length > 0)
    const retained = affected.filter(i => i.source === "mise" && i.active === false).length
    const configured = affected.length - retained
    return {total:affected.length, retained:retained, configured:configured,
        text:affected.length ? (configured ? configured + " configured/installed tools" : "") + (configured && retained ? " and " : "") + (retained ? retained + " retained versions" : "") + " need security review" : "No matched software advisories in this inventory"}
}
function securityVersionText(item) {
    return item.source === "mise" ? item.active === false ? "Retained version · projects may still use it" : "Configured global version" : "Installed tool"
}
function fixedReleaseText(item) {
    return item.security_fixed_versions && item.security_fixed_versions.length ? "Publisher fixed releases: " + item.security_fixed_versions.join(", ") : "Fixed release not verified here. Refresh details and review the publisher notice."
}
