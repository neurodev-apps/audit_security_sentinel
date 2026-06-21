/** @odoo-module **/

import { Component, onWillStart, onMounted, onPatched, onWillUnmount, useState, useRef } from "@odoo/owl";
import { registry } from "@web/core/registry";
import { useService } from "@web/core/utils/hooks";
import { loadBundle } from "@web/core/assets";
import { Dialog } from "@web/core/dialog/dialog";
import { KeepLast } from "@web/core/utils/concurrency";
import { _t } from "@web/core/l10n/translation";
import { user } from "@web/core/user";

const REFRESH_DEFAULT = 60;

/**
 * Format a date/time string to a human-readable locale string.
 * Returns empty string for falsy values.
 */
function _fmtDate(dateStr) {
    if (!dateStr) {
        return "";
    }
    const d = new Date(dateStr + "Z");
    return d.toLocaleString(undefined, {
        year: "numeric",
        month: "short",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
    });
}

/**
 * Format a date/time string to short time only (HH:MM).
 */
function _fmtTime(dateStr) {
    if (!dateStr) {
        return "";
    }
    const d = new Date(dateStr + "Z");
    return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}

/**
 * Return YYYY-MM-DD for a JS Date object.
 */
function _toDateStr(d) {
    const yyyy = d.getFullYear();
    const mm = String(d.getMonth() + 1).padStart(2, "0");
    const dd = String(d.getDate()).padStart(2, "0");
    return `${yyyy}-${mm}-${dd}`;
}

// ---------------------------------------------------------------------------
// Log Detail Dialog — shows visual diff of changes
// ---------------------------------------------------------------------------

class AuditLogDetailDialog extends Component {
    static template = "audit_security_sentinel.AuditLogDetailDialog";
    static components = { Dialog };
    static props = {
        close: Function,
        log: Object,
    };

    setup() {
        this.parsedChanges = [];
        this._parseDetails();
    }

    _parseDetails() {
        const details = this.props.log.details;
        if (!details) {
            return;
        }
        try {
            const parsed = JSON.parse(details);
            const action = parsed.action;
            if (action === "write" && parsed.changes) {
                // Write format: {action: "write", changes: {field: {old, new}}}
                this.parsedChanges = Object.entries(parsed.changes).map(([field, vals]) => ({
                    field,
                    old: vals.old !== undefined ? JSON.stringify(vals.old) : "",
                    new: vals.new !== undefined ? JSON.stringify(vals.new) : "",
                }));
            } else if (action === "create" && parsed.new_values) {
                // Create format: {action: "create", new_values: {field: value}}
                this.parsedChanges = Object.entries(parsed.new_values).map(([field, val]) => ({
                    field,
                    old: "",
                    new: JSON.stringify(val),
                }));
            } else if (action === "unlink" && parsed.deleted_record) {
                // Unlink format: {action: "unlink", deleted_record: {id, name}, key_values: {}}
                const entries = [
                    { field: "id", old: JSON.stringify(parsed.deleted_record.id), new: "(deleted)" },
                    { field: "name", old: JSON.stringify(parsed.deleted_record.name), new: "(deleted)" },
                ];
                if (parsed.key_values) {
                    for (const [field, val] of Object.entries(parsed.key_values)) {
                        entries.push({ field, old: JSON.stringify(val), new: "(deleted)" });
                    }
                }
                this.parsedChanges = entries;
            } else if (typeof parsed === "object") {
                // Fallback: show all top-level keys
                this.parsedChanges = Object.entries(parsed).map(([field, vals]) => ({
                    field,
                    old: "",
                    new: typeof vals === "object" ? JSON.stringify(vals) : String(vals),
                }));
            }
        } catch {
            // If not JSON, show as raw text
            this.parsedChanges = [{ field: "raw", old: "", new: details }];
        }
    }

    get actionLabel() {
        const map = { create: _t("Record Created"), write: _t("Record Modified"), unlink: _t("Record Deleted") };
        return map[this.props.log.action_type] || this.props.log.action_type;
    }

    get actionClass() {
        const map = { create: "asd-badge-success", write: "asd-badge-warning", unlink: "asd-badge-danger" };
        return map[this.props.log.action_type] || "";
    }

    formatValue(val) {
        if (val === null || val === undefined || val === "") {
            return "(empty)";
        }
        if (typeof val === "object") {
            return JSON.stringify(val, null, 2);
        }
        return String(val);
    }
}

// ---------------------------------------------------------------------------
// Main Dashboard Component
// ---------------------------------------------------------------------------

export class AuditDashboard extends Component {
    static template = "audit_security_sentinel.AuditDashboard";
    static props = { "*": true };

    setup() {
        this.orm = useService("orm");
        this.action = useService("action");
        this.dialog = useService("dialog");

        // Canvas refs for Chart.js
        this.activityChartRef = useRef("activityChart");
        this.actionChartRef = useRef("actionChart");
        this.modelsChartRef = useRef("modelsChart");

        // Ref for countdown text — updated imperatively to avoid 60 re-renders/min
        this.countdownRef = useRef("asd-countdown-text");

        // Mount guard — prevents chart renders after unmount
        this._isMounted = false;

        // Chart instances (for cleanup)
        this._activityChart = null;
        this._actionChart = null;
        this._modelsChart = null;

        // Concurrency guard — cancels obsolete in-flight RPC calls (C-06)
        this._keepLast = new KeepLast();

        // Animation frame ID — tracked for cancellation on unmount (C-07)
        this._rafId = null;

        // Flag to trigger chart re-render only after real data loads (C-08)
        this._chartsNeedUpdate = false;

        // Auto-refresh
        this._refreshTimer = null;
        this._countdownTimer = null;

        // Non-reactive countdown value — updated imperatively to avoid per-second re-renders
        this._countdown = REFRESH_DEFAULT;

        // Date range helpers
        const today = new Date();

        this.state = useState({
            isLoading: true,
            error: null,
            rangeKey: "today",
            dateFrom: _toDateStr(today),
            dateTo: _toDateStr(today),
            // Auto-refresh
            autoRefresh: true,
            refreshInterval: REFRESH_DEFAULT,
            // Data from backend
            totalLogs: 0,
            creates: 0,
            writes: 0,
            deletes: 0,
            uniqueUsers: 0,
            totalRules: 0,
            activityByHour: [],
            topModels: [],
            topUsers: [],
            recentLogs: [],
            integrityStatus: { last_check: "Never", tampered_count: 0 },
        });

        onWillStart(async () => {
            await loadBundle("web.chartjs_lib");
            // MD-10: only Compliance Officers see configuration actions
            this.isManager = await user.hasGroup("audit_security_sentinel.group_audit_manager");
            await this.loadDashboardData();
        });

        onMounted(() => {
            this._isMounted = true;
            this._renderCharts();
            this._startAutoRefresh();
        });

        // Re-render charts only when data loading has updated the state (C-08)
        onPatched(() => {
            if (this._chartsNeedUpdate) {
                this._chartsNeedUpdate = false;
                this._renderCharts();
            }
        });

        onWillUnmount(() => {
            this._isMounted = false;
            this._stopAutoRefresh();
            this._destroyCharts();
            // Cancel any pending animation frame to avoid callbacks on unmounted component (C-07)
            if (this._rafId) {
                cancelAnimationFrame(this._rafId);
                this._rafId = null;
            }
        });
    }

    // -----------------------------------------------------------------------
    // Data Loading
    // -----------------------------------------------------------------------

    async loadDashboardData() {
        this.state.isLoading = true;
        try {
            const dateFrom = this.state.dateFrom + " 00:00:00";
            const dateTo = this.state.dateTo + " 23:59:59";
            // KeepLast ensures only the most recent in-flight call is applied (C-06)
            const data = await this._keepLast.add(
                this.orm.call("audit.log", "get_dashboard_data", [dateFrom, dateTo])
            );
            this.state.totalLogs = data.total_logs || 0;
            this.state.creates = data.creates || 0;
            this.state.writes = data.writes || 0;
            this.state.deletes = data.deletes || 0;
            this.state.uniqueUsers = data.unique_users || 0;
            this.state.totalRules = data.total_rules || 0;
            this.state.activityByHour = data.activity_by_hour || [];
            this.state.topModels = data.top_models || [];
            this.state.topUsers = data.top_users || [];
            this.state.recentLogs = data.recent_logs || [];
            this.state.integrityStatus = data.integrity_status || {
                last_check: "Never",
                tampered_count: 0,
            };
            // Signal onPatched to re-render charts after OWL updates the DOM (C-08)
            this._chartsNeedUpdate = true;
        } catch (err) {
            console.error("AuditDashboard: failed to load data", err);
            this.state.error = err.message || String(err);
        }
        this.state.isLoading = false;
    }

    async refreshData() {
        this.state.error = null;
        await this.loadDashboardData();
        // Chart re-rendering is handled by onPatched after state update (C-08)
        this._countdown = this.state.refreshInterval;
        if (this.countdownRef.el) {
            this.countdownRef.el.textContent = this.countdownDisplay;
        }
    }

    // -----------------------------------------------------------------------
    // Date Range
    // -----------------------------------------------------------------------

    setRange(key) {
        const today = new Date();
        let from = new Date();
        switch (key) {
            case "today":
                from = today;
                break;
            case "7days":
                from.setDate(today.getDate() - 7);
                break;
            case "30days":
                from.setDate(today.getDate() - 30);
                break;
            case "custom":
                this.state.rangeKey = "custom";
                return; // Don't reload, user will pick dates
        }
        this.state.rangeKey = key;
        this.state.dateFrom = _toDateStr(from);
        this.state.dateTo = _toDateStr(today);
        this.refreshData();
    }

    onDateFromChange(ev) {
        const val = ev.target.value;
        if (!val) return;
        if (this.state.dateTo && val > this.state.dateTo) {
            // Invalid range — silently reset to current value
            ev.target.value = this.state.dateFrom;
            return;
        }
        this.state.dateFrom = val;
        if (this.state.rangeKey === "custom") {
            this.refreshData();
        }
    }

    onDateToChange(ev) {
        const val = ev.target.value;
        if (!val) return;
        if (this.state.dateFrom && val < this.state.dateFrom) {
            ev.target.value = this.state.dateTo;
            return;
        }
        this.state.dateTo = val;
        if (this.state.rangeKey === "custom") {
            this.refreshData();
        }
    }

    // -----------------------------------------------------------------------
    // Auto-Refresh
    // -----------------------------------------------------------------------

    toggleAutoRefresh() {
        this.state.autoRefresh = !this.state.autoRefresh;
        if (this.state.autoRefresh) {
            this._startAutoRefresh();
        } else {
            this._stopAutoRefresh();
        }
    }

    _startAutoRefresh() {
        this._stopAutoRefresh();
        if (!this.state.autoRefresh) {
            return;
        }
        // Reset non-reactive countdown — updates DOM directly, no OWL re-render
        this._countdown = this.state.refreshInterval;
        if (this.countdownRef.el) {
            this.countdownRef.el.textContent = this.countdownDisplay;
        }
        this._countdownTimer = setInterval(() => {
            this._countdown = Math.max(0, this._countdown - 1);
            if (this.countdownRef.el) {
                this.countdownRef.el.textContent = this.countdownDisplay;
            }
        }, 1000);
        this._refreshTimer = setInterval(async () => {
            await this.refreshData();
        }, this.state.refreshInterval * 1000);
    }

    _stopAutoRefresh() {
        if (this._refreshTimer) {
            clearInterval(this._refreshTimer);
            this._refreshTimer = null;
        }
        if (this._countdownTimer) {
            clearInterval(this._countdownTimer);
            this._countdownTimer = null;
        }
    }

    get countdownDisplay() {
        const m = Math.floor(this._countdown / 60);
        const s = this._countdown % 60;
        return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
    }

    // -----------------------------------------------------------------------
    // Charts
    // -----------------------------------------------------------------------

    _destroyCharts() {
        if (this._activityChart) {
            this._activityChart.destroy();
            this._activityChart = null;
        }
        if (this._actionChart) {
            this._actionChart.destroy();
            this._actionChart = null;
        }
        if (this._modelsChart) {
            this._modelsChart.destroy();
            this._modelsChart = null;
        }
    }

    _renderCharts() {
        if (!this._isMounted) return;
        if (typeof window.Chart === "undefined") {
            console.warn("AuditDashboard: Chart.js not available, skipping charts");
            return;
        }
        // Cancel any pending frame before scheduling a new one (C-07)
        if (this._rafId) {
            cancelAnimationFrame(this._rafId);
        }
        this._rafId = requestAnimationFrame(() => {
            this._rafId = null;
            this._renderActivityChart();
            this._renderActionChart();
            this._renderModelsChart();
        });
    }

    _renderActivityChart() {
        const canvas = this.activityChartRef.el;
        if (!canvas) {
            return;
        }
        if (this._activityChart) {
            this._activityChart.destroy();
        }
        const data = this.state.activityByHour;
        const labels = data.map((d) => _fmtTime(d.hour));
        const values = data.map((d) => d.count);
        this._activityChart = new window.Chart(canvas, {
            type: "line",
            data: {
                labels,
                datasets: [
                    {
                        label: _t("Events"),
                        data: values,
                        borderColor: "#714B67",
                        backgroundColor: "rgba(113, 75, 103, 0.08)",
                        borderWidth: 2,
                        pointRadius: 3,
                        pointBackgroundColor: "#714B67",
                        pointHoverRadius: 5,
                        fill: true,
                        tension: 0.35,
                    },
                ],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: "#2d2d2d",
                        titleFont: { size: 12 },
                        bodyFont: { size: 12 },
                        padding: 10,
                        cornerRadius: 6,
                    },
                },
                scales: {
                    x: {
                        grid: { display: false },
                        ticks: { font: { size: 10 }, maxRotation: 45 },
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: "rgba(0,0,0,0.04)" },
                        ticks: { font: { size: 10 }, precision: 0 },
                    },
                },
            },
        });
    }

    _renderActionChart() {
        const canvas = this.actionChartRef.el;
        if (!canvas) {
            return;
        }
        if (this._actionChart) {
            this._actionChart.destroy();
        }
        const { creates, writes, deletes } = this.state;
        this._actionChart = new window.Chart(canvas, {
            type: "doughnut",
            data: {
                labels: [_t("Creates"), _t("Updates"), _t("Deletes")],
                datasets: [
                    {
                        data: [creates, writes, deletes],
                        backgroundColor: ["#28a745", "#ffc107", "#dc3545"],
                        borderWidth: 0,
                        hoverOffset: 8,
                    },
                ],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: "68%",
                plugins: {
                    legend: {
                        position: "bottom",
                        labels: { padding: 16, usePointStyle: true, pointStyleWidth: 10, font: { size: 12 } },
                    },
                    tooltip: {
                        backgroundColor: "#2d2d2d",
                        padding: 10,
                        cornerRadius: 6,
                    },
                },
            },
        });
    }

    _renderModelsChart() {
        const canvas = this.modelsChartRef.el;
        if (!canvas) {
            return;
        }
        if (this._modelsChart) {
            this._modelsChart.destroy();
        }
        const data = this.state.topModels;
        const labels = data.map((d) => d.model);
        const values = data.map((d) => d.count);
        const palette = [
            "#714B67", "#5b9bd5", "#28a745", "#ffc107", "#dc3545",
            "#17a2b8", "#6f42c1", "#fd7e14", "#20c997", "#e83e8c",
        ];
        this._modelsChart = new window.Chart(canvas, {
            type: "bar",
            data: {
                labels,
                datasets: [
                    {
                        label: _t("Events"),
                        data: values,
                        backgroundColor: palette.slice(0, values.length),
                        borderRadius: 4,
                        maxBarThickness: 28,
                    },
                ],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: "y",
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: "#2d2d2d",
                        padding: 10,
                        cornerRadius: 6,
                    },
                },
                scales: {
                    x: {
                        beginAtZero: true,
                        grid: { color: "rgba(0,0,0,0.04)" },
                        ticks: { precision: 0, font: { size: 10 } },
                    },
                    y: {
                        grid: { display: false },
                        ticks: { font: { size: 11 } },
                    },
                },
            },
        });
    }

    // -----------------------------------------------------------------------
    // Formatting Helpers (called from template)
    // -----------------------------------------------------------------------

    formatDate(dateStr) {
        return _fmtDate(dateStr);
    }

    getActionTypeClass(actionType) {
        switch (actionType) {
            case "create":
                return "asd-badge asd-badge-success";
            case "write":
                return "asd-badge asd-badge-warning";
            case "unlink":
                return "asd-badge asd-badge-danger";
            default:
                return "asd-badge asd-badge-secondary";
        }
    }

    getActionTypeLabel(actionType) {
        switch (actionType) {
            case "create":
                return _t("CREATE");
            case "write":
                return _t("UPDATE");
            case "unlink":
                return _t("DELETE");
            default:
                return actionType ? actionType.toUpperCase() : "";
        }
    }

    get integrityOk() {
        return (this.state.integrityStatus.tampered_count || 0) === 0;
    }

    get topUserMax() {
        if (!this.state.topUsers.length) {
            return 1;
        }
        return this.state.topUsers[0].count || 1;
    }

    userBarWidth(count) {
        return Math.max(4, Math.round((count / this.topUserMax) * 100));
    }

    // -----------------------------------------------------------------------
    // Navigation / Actions
    // -----------------------------------------------------------------------

    openAuditLogs() {
        this.action.doAction({
            type: "ir.actions.act_window",
            name: "Audit Logs",
            res_model: "audit.log",
            view_mode: "list,form",
            views: [[false, "list"], [false, "form"]],
            target: "current",
        });
    }

    openAuditRules() {
        this.action.doAction({
            type: "ir.actions.act_window",
            name: "Audit Rules",
            res_model: "audit.rule",
            view_mode: "list,form",
            views: [[false, "list"], [false, "form"]],
            target: "current",
        });
    }

    openSettings() {
        this.action.doAction({
            type: "ir.actions.act_window",
            name: _t("Settings"),
            res_model: "res.config.settings",
            view_mode: "form",
            views: [[false, "form"]],
            target: "current",
        });
    }

    openLogDetail(log) {
        this.dialog.add(AuditLogDetailDialog, { log });
    }

    openLogForm(logId) {
        this.action.doAction({
            type: "ir.actions.act_window",
            name: "Audit Log",
            res_model: "audit.log",
            res_id: logId,
            view_mode: "form",
            views: [[false, "form"]],
            target: "current",
        });
    }
}

// Register the component as a client action
registry.category("actions").add("audit_security_sentinel.dashboard", AuditDashboard);
