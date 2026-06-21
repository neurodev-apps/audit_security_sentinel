# -*- coding: utf-8 -*-

import base64
import io
import json
import logging
from datetime import timedelta

from odoo import api, fields, models, _
from odoo.exceptions import UserError, ValidationError

_logger = logging.getLogger(__name__)

try:
    import xlsxwriter
except ImportError:
    xlsxwriter = None
    _logger.warning("xlsxwriter not available. Excel export will be disabled.")


class AuditReportWizard(models.TransientModel):
    _name = 'audit.report.wizard'
    _description = 'Compliance Report Wizard'

    # --- Filter fields ---
    date_from = fields.Date(
        string='Date From',
        required=True,
        default=lambda self: fields.Date.context_today(self).replace(day=1),
    )
    date_to = fields.Date(
        string='Date To',
        required=True,
        default=lambda self: fields.Date.context_today(self),
    )
    include_creates = fields.Boolean(
        string='Include Creates',
        default=True,
    )
    include_writes = fields.Boolean(
        string='Include Writes',
        default=True,
    )
    include_deletes = fields.Boolean(
        string='Include Deletes',
        default=True,
    )
    model_ids = fields.Many2many(
        'ir.model',
        'audit_report_wizard_model_rel',
        'wizard_id',
        'model_id',
        string='Models',
        help='Leave empty to include all models.',
    )
    user_ids = fields.Many2many(
        'res.users',
        'audit_report_wizard_user_rel',
        'wizard_id',
        'user_id',
        string='Users',
        help='Leave empty to include all users.',
    )
    export_format = fields.Selection(
        selection=[
            ('pdf', 'PDF Report'),
            ('xlsx', 'Excel Export'),
        ],
        string='Export Format',
        required=True,
        default='xlsx',
    )
    include_details = fields.Boolean(
        string='Include Change Details',
        default=False,
        help='Include field-level change details. Increases file size significantly.',
    )

    # --- Output fields ---
    file_data = fields.Binary(
        string='File',
        readonly=True,
    )
    file_name = fields.Char(
        string='File Name',
        readonly=True,
    )

    # -------------------------------------------------------------------------
    # Constraints
    # -------------------------------------------------------------------------

    @api.constrains('date_from', 'date_to')
    def _check_date_range(self):
        for wizard in self:
            if wizard.date_from and wizard.date_to and wizard.date_from > wizard.date_to:
                raise ValidationError(_('Date From must be earlier than or equal to Date To.'))

    # -------------------------------------------------------------------------
    # Domain helpers
    # -------------------------------------------------------------------------

    def _build_domain(self):
        """Build the search domain for audit.log based on wizard filters."""
        self.ensure_one()

        domain = [
            ('create_date', '>=', fields.Datetime.to_datetime(self.date_from)),
            ('create_date', '<', fields.Datetime.to_datetime(
                self.date_to + timedelta(days=1)
            )),
        ]

        # Action type filter
        action_types = []
        if self.include_creates:
            action_types.append('create')
        if self.include_writes:
            action_types.append('write')
        if self.include_deletes:
            action_types.append('unlink')

        if not action_types:
            raise UserError(_('You must select at least one action type to include in the report.'))

        if len(action_types) < 3:
            domain.append(('action_type', 'in', action_types))

        # Model filter
        if self.model_ids:
            model_names = self.model_ids.mapped('model')
            domain.append(('model_model', 'in', model_names))

        # User filter
        if self.user_ids:
            domain.append(('user_id', 'in', self.user_ids.ids))

        # Company filter — non-managers see only their companies
        manager_group = self.env.ref(
            'audit_security_sentinel.group_audit_manager', raise_if_not_found=False
        )
        if manager_group and not self.env.user.has_group('audit_security_sentinel.group_audit_manager'):
            domain.append(('company_id', 'in', self.env.companies.ids))

        return domain

    def _get_logs(self):
        """Return audit.log recordset matching the current wizard filters.

        Raises UserError if the result exceeds MAX_RECORDS to prevent
        out-of-memory errors on large datasets.
        """
        MAX_RECORDS = 50000
        domain = self._build_domain()
        count = self.env['audit.log'].sudo().search_count(domain)
        if count > MAX_RECORDS:
            raise UserError(_(
                'The report contains %(count)s records which exceeds the '
                'limit of %(max)s. Please narrow the date range or apply '
                'additional filters.',
                count=count,
                max=MAX_RECORDS,
            ))
        return self.env['audit.log'].sudo().search(domain, order='create_date desc')

    def _effective_include_details(self):
        """CR-07: only Compliance Officers may export change details.

        Defence in depth — the wizard field is already hidden from Audit Users
        in the view, but a request could still arrive via RPC with
        ``include_details=True``. This is the single source of truth used by
        both exporters.
        """
        self.ensure_one()
        return bool(self.include_details) and self.env.user.has_group(
            'audit_security_sentinel.group_audit_manager'
        )

    # -------------------------------------------------------------------------
    # Summary statistics
    # -------------------------------------------------------------------------

    def _compute_summary(self, logs):
        """Compute summary statistics from a recordset of audit logs.

        Returns a dict with keys: total, by_action, by_model, by_user.
        """
        by_action = {}
        by_model = {}
        by_user = {}

        for log in logs:
            # By action type
            action_label = dict(
                self.env['audit.log']._fields['action_type'].selection
            ).get(log.action_type, log.action_type)
            by_action[action_label] = by_action.get(action_label, 0) + 1

            # By model
            model_name = log.model_model or _('Unknown')
            by_model[model_name] = by_model.get(model_name, 0) + 1

            # By user
            user_name = log.user_id.name or _('Unknown')
            by_user[user_name] = by_user.get(user_name, 0) + 1

        return {
            'total': len(logs),
            'by_action': dict(sorted(by_action.items(), key=lambda x: x[1], reverse=True)),
            'by_model': dict(sorted(by_model.items(), key=lambda x: x[1], reverse=True)),
            'by_user': dict(sorted(by_user.items(), key=lambda x: x[1], reverse=True)),
        }

    # -------------------------------------------------------------------------
    # Integrity verification
    # -------------------------------------------------------------------------

    def _verify_integrity(self, logs):
        """Verify hash integrity for a set of logs.

        Uses the per-record algorithm via ``_recompute_hash`` (v1 legacy
        SHA-256 or v2 HMAC over the full payload). The full chain-link check —
        which also detects deleted/reordered records — runs over the complete
        table in ``audit.log._cron_verify_integrity``; here the report only
        checks the own hashes of the filtered records.

        Returns a dict with keys: total_checked, passed, failed, failed_ids.
        """
        total = len(logs)
        failed_ids = []

        for log in logs:
            try:
                if log.hash != log._recompute_hash():
                    failed_ids.append(log.id)
            except Exception:
                # If hash verification fails entirely, flag it
                failed_ids.append(log.id)

        return {
            'total_checked': total,
            'passed': total - len(failed_ids),
            'failed': len(failed_ids),
            'failed_ids': failed_ids[:100],  # Cap at 100 for display
        }

    # -------------------------------------------------------------------------
    # Excel export
    # -------------------------------------------------------------------------

    def action_export_xlsx(self):
        """Generate an Excel compliance report and return a download action."""
        self.ensure_one()

        if xlsxwriter is None:
            raise UserError(_(
                'The xlsxwriter library is required for Excel export but is not installed.'
            ))

        logs = self._get_logs()
        summary = self._compute_summary(logs)
        integrity = self._verify_integrity(logs)
        inc_details = self._effective_include_details()  # CR-07

        buffer = io.BytesIO()
        # strings_to_formulas/urls=False prevents formula/CSV injection (CR-08):
        # DB values starting with =, +, - or @ are stored as plain text, not formulas.
        workbook = xlsxwriter.Workbook(buffer, {
            'in_memory': True,
            'strings_to_formulas': False,
            'strings_to_urls': False,
        })

        # --- Formats ---
        fmt_title = workbook.add_format({
            'bold': True, 'font_size': 16, 'font_color': '#1B2A4A',
            'bottom': 2, 'bottom_color': '#1B2A4A',
        })
        fmt_subtitle = workbook.add_format({
            'bold': True, 'font_size': 12, 'font_color': '#333333',
        })
        fmt_header = workbook.add_format({
            'bold': True, 'font_size': 10, 'font_color': '#FFFFFF',
            'bg_color': '#1B2A4A', 'border': 1, 'text_wrap': True,
            'valign': 'vcenter',
        })
        fmt_cell = workbook.add_format({
            'font_size': 10, 'border': 1, 'text_wrap': True,
            'valign': 'vcenter',
        })
        fmt_cell_date = workbook.add_format({
            'font_size': 10, 'border': 1, 'num_format': 'yyyy-mm-dd hh:mm:ss',
            'valign': 'vcenter',
        })
        fmt_number = workbook.add_format({
            'font_size': 10, 'border': 1, 'num_format': '#,##0',
            'valign': 'vcenter',
        })
        fmt_pass = workbook.add_format({
            'font_size': 10, 'border': 1, 'font_color': '#006600',
            'bold': True, 'valign': 'vcenter',
        })
        fmt_fail = workbook.add_format({
            'font_size': 10, 'border': 1, 'font_color': '#CC0000',
            'bold': True, 'valign': 'vcenter',
        })
        fmt_section_header = workbook.add_format({
            'bold': True, 'font_size': 11, 'font_color': '#1B2A4A',
            'bottom': 1, 'bottom_color': '#CCCCCC',
        })

        # =====================================================================
        # Sheet 1: Summary
        # =====================================================================
        ws_summary = workbook.add_worksheet(_('Summary'))
        ws_summary.set_column('A:A', 30)
        ws_summary.set_column('B:B', 20)
        ws_summary.hide_gridlines(2)

        row = 0
        company = self.env.company
        ws_summary.write(row, 0, _('Security Audit Report'), fmt_title)
        row += 1
        ws_summary.write(row, 0, company.name, fmt_subtitle)
        row += 2
        ws_summary.write(row, 0, _('Date Range:'), fmt_section_header)
        row += 1
        ws_summary.write(row, 0, _('From:'))
        ws_summary.write(row, 1, str(self.date_from), fmt_cell)
        row += 1
        ws_summary.write(row, 0, _('To:'))
        ws_summary.write(row, 1, str(self.date_to), fmt_cell)
        row += 1
        ws_summary.write(row, 0, _('Total Records:'))
        ws_summary.write(row, 1, summary['total'], fmt_number)
        row += 2

        # By action type
        ws_summary.write(row, 0, _('Breakdown by Action Type'), fmt_section_header)
        ws_summary.write(row, 1, '', fmt_section_header)
        row += 1
        ws_summary.write(row, 0, _('Action Type'), fmt_header)
        ws_summary.write(row, 1, _('Count'), fmt_header)
        row += 1
        for action_label, count in summary['by_action'].items():
            ws_summary.write(row, 0, action_label, fmt_cell)
            ws_summary.write(row, 1, count, fmt_number)
            row += 1
        row += 1

        # By model
        ws_summary.write(row, 0, _('Breakdown by Model'), fmt_section_header)
        ws_summary.write(row, 1, '', fmt_section_header)
        row += 1
        ws_summary.write(row, 0, _('Model'), fmt_header)
        ws_summary.write(row, 1, _('Count'), fmt_header)
        row += 1
        for model_name, count in summary['by_model'].items():
            ws_summary.write(row, 0, model_name, fmt_cell)
            ws_summary.write(row, 1, count, fmt_number)
            row += 1
        row += 1

        # By user
        ws_summary.write(row, 0, _('Breakdown by User'), fmt_section_header)
        ws_summary.write(row, 1, '', fmt_section_header)
        row += 1
        ws_summary.write(row, 0, _('User'), fmt_header)
        ws_summary.write(row, 1, _('Count'), fmt_header)
        row += 1
        for user_name, count in summary['by_user'].items():
            ws_summary.write(row, 0, user_name, fmt_cell)
            ws_summary.write(row, 1, count, fmt_number)
            row += 1

        # =====================================================================
        # Sheet 2: Audit Logs
        # =====================================================================
        ws_logs = workbook.add_worksheet(_('Audit Logs'))

        headers = [
            (_('Date'), 20),
            (_('User'), 20),
            (_('Action'), 10),
            (_('Model'), 25),
            (_('Resource Name'), 30),
            (_('Resource ID'), 12),
            (_('IP Address'), 16),
        ]
        if inc_details:
            headers.append((_('Details'), 60))

        for col, (header, width) in enumerate(headers):
            ws_logs.set_column(col, col, width)
            ws_logs.write(0, col, header, fmt_header)

        ws_logs.freeze_panes(1, 0)
        ws_logs.autofilter(0, 0, 0, len(headers) - 1)

        action_labels = dict(
            self.env['audit.log']._fields['action_type'].selection
        )

        for row_idx, log in enumerate(logs, start=1):
            # xlsxwriter requires naive datetime objects (no tzinfo)
            ctx_dt = fields.Datetime.context_timestamp(self, log.create_date)
            ws_logs.write_datetime(
                row_idx, 0,
                ctx_dt.replace(tzinfo=None),
                fmt_cell_date,
            )
            ws_logs.write_string(row_idx, 1, log.user_id.name or '', fmt_cell)
            ws_logs.write_string(row_idx, 2, action_labels.get(log.action_type, log.action_type), fmt_cell)
            ws_logs.write_string(row_idx, 3, log.model_model or '', fmt_cell)
            ws_logs.write_string(row_idx, 4, log.name or '', fmt_cell)
            ws_logs.write(row_idx, 5, log.res_id or 0, fmt_number)
            ws_logs.write_string(row_idx, 6, log.ip_address or '', fmt_cell)
            if inc_details:
                details_str = ''
                if log.details:
                    try:
                        details_dict = json.loads(log.details)
                        details_str = json.dumps(details_dict, indent=2, ensure_ascii=False)
                    except (json.JSONDecodeError, TypeError):
                        details_str = log.details or ''
                ws_logs.write_string(row_idx, 7, details_str, fmt_cell)

        # =====================================================================
        # Sheet 3: Integrity
        # =====================================================================
        ws_integrity = workbook.add_worksheet(_('Integrity'))
        ws_integrity.set_column('A:A', 30)
        ws_integrity.set_column('B:B', 20)
        ws_integrity.hide_gridlines(2)

        row = 0
        ws_integrity.write(row, 0, _('Hash Integrity Verification'), fmt_title)
        row += 2
        ws_integrity.write(row, 0, _('Total Records Checked:'))
        ws_integrity.write(row, 1, integrity['total_checked'], fmt_number)
        row += 1
        ws_integrity.write(row, 0, _('Passed:'))
        ws_integrity.write(row, 1, integrity['passed'], fmt_pass)
        row += 1
        ws_integrity.write(row, 0, _('Failed:'))
        ws_integrity.write(
            row, 1, integrity['failed'],
            fmt_fail if integrity['failed'] > 0 else fmt_pass,
        )
        row += 2

        if integrity['failed'] > 0:
            ws_integrity.write(row, 0, _('Status'), fmt_fail)
            ws_integrity.write(row, 1, _('INTEGRITY ALERT: Tampered records detected'), fmt_fail)
            row += 2
            ws_integrity.write(row, 0, _('Tampered Record IDs'), fmt_section_header)
            ws_integrity.write(row, 1, '', fmt_section_header)
            row += 1
            ws_integrity.write(row, 0, _('Log ID'), fmt_header)
            row += 1
            for log_id in integrity['failed_ids']:
                ws_integrity.write(row, 0, log_id, fmt_cell)
                row += 1
        else:
            ws_integrity.write(row, 0, _('Status'), fmt_pass)
            ws_integrity.write(
                row, 1, _('ALL RECORDS PASSED integrity verification'), fmt_pass,
            )

        # Footer
        row += 2
        fmt_footer = workbook.add_format({
            'italic': True, 'font_size': 9, 'font_color': '#888888',
        })
        ws_integrity.write(
            row, 0,
            _('Generated by Security Sentinel — Confidential'),
            fmt_footer,
        )

        workbook.close()

        # Write file to wizard record — bypass the immutability constraint of
        # audit.log by writing directly to our own TransientModel.
        file_name = 'audit_report_%s_%s.xlsx' % (
            self.date_from.strftime('%Y%m%d'),
            self.date_to.strftime('%Y%m%d'),
        )

        self.write({
            'file_data': base64.b64encode(buffer.getvalue()),
            'file_name': file_name,
        })

        return {
            'type': 'ir.actions.act_url',
            'url': (
                '/web/content/?model=audit.report.wizard'
                '&id=%d&field=file_data'
                '&filename_field=file_name&download=true'
            ) % self.id,
            'target': 'new',
        }

    # -------------------------------------------------------------------------
    # PDF export
    # -------------------------------------------------------------------------

    def action_export_pdf(self):
        """Generate a PDF compliance report via QWeb."""
        self.ensure_one()

        logs = self._get_logs()
        summary = self._compute_summary(logs)
        integrity = self._verify_integrity(logs)
        inc_details = self._effective_include_details()  # CR-07

        # Store data in context for the report template
        data = {
            'wizard_id': self.id,
            'date_from': str(self.date_from),
            'date_to': str(self.date_to),
            'company_name': self.env.company.name,
            'summary': summary,
            'integrity': integrity,
            'include_details': inc_details,
            'logs': [{
                'create_date': fields.Datetime.context_timestamp(
                    self, log.create_date
                ).strftime('%Y-%m-%d %H:%M:%S'),
                'user': log.user_id.name or '',
                'action_type': dict(
                    self.env['audit.log']._fields['action_type'].selection
                ).get(log.action_type, log.action_type),
                'model': log.model_model or '',
                'name': log.name or '',
                'res_id': log.res_id or 0,
                'ip_address': log.ip_address or '',
                # CR-07: never ship details in the payload unless the officer asked
                # for them and is allowed to receive them.
                'details': (log.details or '') if inc_details else '',
            } for log in logs[:500]],  # Limit to 500 for PDF readability
            'total_logs': len(logs),
            'logs_truncated': len(logs) > 500,
        }

        return self.env.ref(
            'audit_security_sentinel.action_report_audit'
        ).report_action(self, data=data)
