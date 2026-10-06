const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const elements = new Map();
const callbacks = new Map();
const alerts = [];
let intervals = 0;
const document = {
    getElementById(id) {
        if (!elements.has(id)) {
            elements.set(id, {disabled: false, checked: false, textContent: "", style: {},
                classList: {visible: false,
                    add() {this.visible = true;}, remove() {this.visible = false;}},
                addEventListener() {}, focus() {document.activeElement = this;}});
        }
        return elements.get(id);
    },
    addEventListener(event, callback) { callbacks.set(event, callback); },
};
const context = vm.createContext({document, console: {error() {}},
    setInterval() { intervals++; return intervals; }, clearInterval() {},
    alert(message) { alerts.push(message); }, fetch: async () => {throw new Error("offline");},
});
vm.runInContext(fs.readFileSync(path.join(__dirname, "../web/static/app.js"), "utf8"), context);

async function run() {
    const dangerous = '<img src=x onerror="alert(1)">';
    let html = context.renderModuleRecord({collection_status: "collected",
        modules: [{path: dangerous}]}, "extended");
    assert(html.includes("&lt;img"));
    assert(!html.includes("<img"));
    html = context.renderModuleRecord({collection_status: "access_denied", error: "Access denied", modules: []}, "extended");
    assert(html.includes("Access denied"));
    assert(!html.includes("Collection succeeded"));
    html = context.renderModuleRecord({modules: []}, "legacy_unknown");
    assert(html.includes("were not verified"));
    assert(context.renderModuleRecord(null, "quick").includes("not requested"));

    html = context.renderExecutable({path: dangerous, size: dangerous, created_time: dangerous,
        signature: {collection_status: "timeout", status: null, error: dangerous}});
    assert(!html.includes("<img"));
    assert(html.includes("timeout"));
    assert(!html.includes("NotSigned"));
    assert.equal(context.formatTimestamp(null), "Unavailable");
    assert.equal(context.formatTimestamp(dangerous), "Unavailable");

    await context.startAnalysis();
    assert.equal(elements.get("analyzeButton").disabled, false);
    assert.equal(elements.get("importButton").disabled, false);
    assert.equal(alerts[0], "offline");

    context.fetch = async () => ({ok: true, json: async () => ({status: "running", stage: "Collecting", progress: 20})});
    await context.updateStatus();
    assert.equal(elements.get("importButton").disabled, true);
    context.fetch = async () => {throw new Error("offline");};
    await context.updateStatus();
    assert.equal(elements.get("analyzeButton").disabled, false);
    assert(elements.get("evidenceWarnings").textContent.includes("Connection interrupted"));

    context.fetch = async url => url === "/api/status"
        ? {ok: true, json: async () => ({status: "running", stage: "Collecting", progress: 40})}
        : {ok: false, status: 404};
    await callbacks.get("DOMContentLoaded")();
    assert.equal(elements.get("analyzeButton").disabled, true);
    assert(intervals > 0, "Reload must resume status polling");
    const summary = {total_processes: 2, affected_process_count: 1,
        issues: [{label: "Command line", process_count: 1}],
        affected_processes: [{pid: 10, name: dangerous, missing: ["Command line"]}]};
    html = context.renderCompletionIssues(summary);
    assert(html.includes("Command line"));
    assert(html.includes("PID 10"));
    assert(!html.includes("<img"));
    assert.equal(context.renderCompletionIssues({affected_process_count: 0}), "");
    const snapshot = {snapshot_name: "new-snapshot", collection_summary: summary,
        processes: [], executable_count: 0, captured_at: null,
        metadata: {warnings: ["processes: incomplete collection; inspect record statuses."]}};
    context.fetch = async url => ({ok: true, json: async () => url === "/api/status"
        ? {status: "complete", stage: "Acquisition complete", progress: 100} : snapshot});
    await context.updateStatus();
    assert(elements.get("completionModal").classList.visible);
    assert(elements.get("completionMessage").textContent.includes("1 of 2"));
    assert.equal(elements.get("evidenceWarnings").textContent, "");
    context.closeCompletionNotice();
    await context.updateStatus();
    assert.equal(elements.get("completionModal").classList.visible, false, "Polling must not reopen the popup");
    await context.loadProcesses();
    assert.equal(elements.get("completionModal").classList.visible, false, "Import/initial load must not reopen the popup");
    context.showCompletionNotice(snapshot);
    assert.equal(elements.get("completionModal").classList.visible, false, "The same snapshot cannot reopen the popup");
    context.showCompletionNotice({...snapshot, snapshot_name: "clean-snapshot", collection_summary: {affected_process_count: 0}});
    assert(elements.get("completionModal").classList.visible);
    assert(!elements.get("completionMessage").textContent.includes("However"));
    console.log("Frontend regression checks passed, including completion popup, missing fields, escaping, and no duplicate notices.");
}
run().catch(error => {console.error(error); process.exitCode = 1;});
