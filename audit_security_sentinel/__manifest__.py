# -*- coding: utf-8 -*-
{
    'name': 'Odoo 17 Security Sentinel: Anti-Fraud & Audit Log',
    'version': '17.0.2.0.0',
    'category': 'Security',
    'summary': 'Immutable SHA-256 audit logging, real-time OWL dashboard, compliance reports, role-based security & automated integrity verification',
    'description': """
Odoo 17 Security Sentinel — Anti-Fraud & Immutable Audit Log
=============================================================

Enterprise-grade security module for Odoo 17:

* **Real-time OWL Dashboard** — live KPIs, Chart.js charts, action breakdown, risk indicators
* **Immutable Audit Logs** — every create/write/delete sealed with SHA-256 hash
* **Automated Integrity Verification** — weekly cron recalculates hashes and alerts on tampering
* **Compliance Reports** — export audit data to PDF or Excel with one click
* **Role-Based Access** — Audit User (read-only) and Compliance Officer (full config)
* **IP Address Tracking** — captures client IP with proxy header support
* **Configurable Rules** — choose models and fields to monitor
* **Detailed Change History** — old/new value diffs for every modification

All audit logs are read-only and cannot be modified or deleted.
    """,
    'author': 'NeuroDev',
    'website': 'https://github.com/neurodev-apps',
    'license': 'OPL-1',
    'price': 149.00,
    'currency': 'USD',
    'images': ['static/description/banner.png'],
    'depends': [
        'base',
        'mail',
        'web',
    ],
    'data': [
        'security/audit_security.xml',
        'security/ir.model.access.csv',
        'views/audit_log_views.xml',
        'views/audit_rule_views.xml',
        'views/audit_dashboard_action.xml',
        'views/res_config_settings_views.xml',
        'wizard/audit_report_wizard_views.xml',
        'report/audit_report.xml',
        'report/audit_report_templates.xml',
        'data/audit_cron.xml',
    ],
    'assets': {
        'web.assets_backend': [
            'audit_security_sentinel/static/src/dashboard/audit_dashboard.css',
            'audit_security_sentinel/static/src/dashboard/audit_dashboard.js',
            'audit_security_sentinel/static/src/dashboard/audit_dashboard.xml',
        ],
    },
    'post_load': 'post_load',
    'uninstall_hook': 'uninstall_hook',
    'installable': True,
    'application': True,
    'auto_install': False,
}
