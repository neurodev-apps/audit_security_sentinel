# -*- coding: utf-8 -*-
{
    'name': 'Odoo 18 Security Sentinel: Anti-Fraud & Audit Log',
    'version': '18.0.2.1.5',
    'category': 'Security',
    'summary': 'Immutable chained HMAC-SHA256 audit logging, sensitive-data masking, role-based detail access, real-time OWL dashboard, compliance reports & automated integrity verification',
    'description': """
Odoo 18 Security Sentinel — Anti-Fraud & Immutable Audit Log
=============================================================

Enterprise-grade security module for Odoo 18:

* **Real-time OWL Dashboard** — live KPIs, Chart.js charts, action breakdown, risk indicators
* **Tamper-Evident Audit Logs** — every create/write/delete sealed with a chained HMAC-SHA256 hash covering user, action, IP, company, resource and details
* **Sensitive-Data Masking** — passwords, tokens, API keys, IBAN/card numbers and other secrets are stored as <redacted>, never in clear text
* **Automated Integrity Verification** — cron recalculates the full hash chain and alerts on tampering, deletion or reordering of any record
* **Compliance Reports** — export audit data to PDF or Excel with one click
* **Role-Based Access** — Audit User sees metadata only; change details and detailed exports are restricted to the Compliance Officer
* **IP Address Tracking** — captures client IP with trusted-proxy header support
* **Configurable Rules** — choose models and fields to monitor

Audit logs are read-only and cannot be modified. Deletion is blocked by default;
an optional retention policy can purge logs older than a configured period, and
only when a Compliance Officer explicitly enables it.
    """,
    'author': 'NeuroDev',
    'website': 'https://neurodev.cl',
    'support': 'contacto@neurodev.cl',
    'license': 'OPL-1',
    'price': 159.00,
    'currency': 'USD',
    'images': ['static/description/banner.png'],
    'depends': [
        'base',
        'mail',
        'web',
    ],
    'external_dependencies': {
        'python': ['xlsxwriter'],
    },
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
