# -*- coding: utf-8 -*-

import hashlib
import logging
from datetime import timedelta

from odoo import api, fields, models, _
from odoo.exceptions import UserError

_logger = logging.getLogger(__name__)


class AuditLog(models.Model):
    _name = 'audit.log'
    _description = 'Immutable Audit Log'
    _order = 'create_date desc'
    _rec_name = 'name'

    # Core fields
    user_id = fields.Many2one(
        'res.users',
        string='User',
        required=True,
        readonly=True,
        index=True,
        ondelete='restrict',
    )
    name = fields.Char(
        string='Resource Name',
        readonly=True,
        help='Name of the affected resource',
    )
    model_model = fields.Char(
        string='Model',
        readonly=True,
        index=True,
        help='Technical name of the model (e.g., res.partner)',
    )
    res_id = fields.Integer(
        string='Resource ID',
        readonly=True,
        index=True,
        help='Database ID of the affected record',
    )
    ip_address = fields.Char(
        string='IP Address',
        readonly=True,
        help='IP address of the user who performed the action',
    )
    company_id = fields.Many2one(
        'res.company',
        string='Company',
        readonly=True,
        index=True,
        ondelete='restrict',
        help='Company context in which the action was performed.',
    )
    action_type = fields.Selection(
        selection=[
            ('create', 'Create'),
            ('write', 'Write'),
            ('unlink', 'Delete'),
        ],
        string='Action Type',
        readonly=True,
        required=True,
        index=True,
    )
    details = fields.Text(
        string='Change Details',
        readonly=True,
        help='JSON containing old and new values',
    )
    hash = fields.Char(
        string='Integrity Hash',
        readonly=True,
        help='Integrity hash of this entry (HMAC-SHA256 over the full payload, '
             'chained to the previous entry for v2 records).',
    )
    previous_hash = fields.Char(
        string='Previous Hash',
        readonly=True,
        help='Integrity hash of the preceding audit log entry. Links the chain '
             'so that deleting or reordering an intermediate record is detected (CR-02).',
    )
    hash_version = fields.Integer(
        string='Hash Version',
        readonly=True,
        help='Integrity algorithm version. Empty/1 = legacy salted SHA-256; '
             '2 = chained HMAC-SHA256 over the full payload.',
    )

    def init(self):
        """Create composite index for fast lookups on model_model and res_id."""
        self.env.cr.execute("""
            CREATE INDEX IF NOT EXISTS audit_log_model_res_idx
            ON audit_log (model_model, res_id)
        """)
        self.env.cr.execute("""
            CREATE INDEX IF NOT EXISTS audit_log_create_date_idx
            ON audit_log (create_date DESC)
        """)
        self.env.cr.execute("""
            CREATE INDEX IF NOT EXISTS audit_log_user_date_idx
            ON audit_log (user_id, create_date DESC)
        """)

    def unlink(self):
        """Prevent deletion of audit logs to maintain immutability.

        An unlink on an empty recordset is a legitimate no-op: Odoo itself and
        other modules call ``model.browse().unlink()`` generically over every
        model. Only block the operation when there is actually something to
        delete, so the immutability guard never breaks unrelated code.
        """
        if not self:
            return True
        raise UserError(_('Audit logs cannot be deleted. They are immutable for security purposes.'))

    def copy(self, default=None):
        """Prevent duplication of audit logs to maintain integrity."""
        raise UserError(_('Audit logs cannot be duplicated. Each entry is unique and immutable.'))

    def write(self, vals):
        """Prevent modification of audit logs to maintain immutability.

        The only allowed write is setting the integrity hash right after
        creation, signalled by the ``_audit_hash_update`` context flag.
        """
        if self.env.context.get('_audit_hash_update') and list(vals.keys()) == ['hash']:
            return super().write(vals)
        raise UserError(_('Audit logs cannot be modified. They are immutable for security purposes.'))

    @api.model_create_multi
    def create(self, vals_list):
        """Override create to ensure all fields are properly set."""
        return super().create(vals_list)

    def _recompute_hash(self):
        """Recompute the integrity hash of a single log using the algorithm
        recorded in ``hash_version`` (CR-02).

        Version 2 reproduces the chained HMAC-SHA256 over the full payload;
        legacy records (version empty/1) reproduce the original salted SHA-256
        so the historical records keep verifying after the upgrade to 2.1.5.
        Note: this checks the record's own hash, not the chain link — the chain
        is verified by ``_cron_verify_integrity`` / the report wizard.
        """
        from .audit_hook import _get_audit_salt, _compute_audit_hash_v2
        self.ensure_one()
        secret = _get_audit_salt(self.env)
        create_date_str = (
            self.create_date.strftime('%Y-%m-%d %H:%M:%S') if self.create_date else ''
        )
        if (self.hash_version or 1) >= 2:
            return _compute_audit_hash_v2(secret, {
                'user_id': self.user_id.id,
                'model_model': self.model_model,
                'res_id': self.res_id,
                'name': self.name,
                'action_type': self.action_type,
                'ip_address': self.ip_address,
                'company_id': self.company_id.id if self.company_id else False,
                'create_date': create_date_str,
                'details': self.details,
                'previous_hash': self.previous_hash,
            })
        # Legacy v1 salted SHA-256
        hash_string = (
            f"{self.user_id.id}|{self.model_model}|{self.res_id}"
            f"|{create_date_str}|{self.details}|{secret}"
        )
        return hashlib.sha256(hash_string.encode('utf-8')).hexdigest()

    @api.model
    def _cron_verify_integrity(self):
        """Scheduled action: verify hash integrity of recent audit logs.

        Uses raw SQL for reading hashes (much faster for large datasets).
        Processes all audit logs in batches of 1000.
        Sends a summary to Compliance Officers via mail.message.
        """
        from .audit_hook import _get_audit_salt, _compute_audit_hash_v2

        secret = _get_audit_salt(self.env)

        # MD-05: verify the FULL history, not just the last 7 days.
        # Raw SQL + batched fetch keeps this efficient on large datasets.
        # CR-02: fetch every field covered by the v2 payload + the chain link.
        self.env.cr.execute("""
            SELECT id, user_id, model_model, res_id, create_date, details, hash,
                   name, action_type, ip_address, company_id, previous_hash, hash_version
            FROM audit_log
            ORDER BY id ASC
        """)

        total = 0
        tampered_ids = []
        BATCH = 1000
        prev_stored_hash = ''  # hash of the preceding row — used for the chain check

        while True:
            rows = self.env.cr.fetchmany(BATCH)
            if not rows:
                break
            total += len(rows)
            for row in rows:
                (log_id, user_id, model_model, res_id, create_date, details, stored_hash,
                 name, action_type, ip_address, company_id, previous_hash, hash_version) = row
                create_date_str = create_date.strftime('%Y-%m-%d %H:%M:%S') if create_date else ''
                tampered = False
                reason = ''

                if (hash_version or 1) >= 2:
                    expected = _compute_audit_hash_v2(secret, {
                        'user_id': user_id,
                        'model_model': model_model,
                        'res_id': res_id,
                        'name': name,
                        'action_type': action_type,
                        'ip_address': ip_address,
                        'company_id': company_id,
                        'create_date': create_date_str,
                        'details': details,
                        'previous_hash': previous_hash,
                    })
                    # Chain link: previous_hash must equal the prior row's hash.
                    # A break means an intermediate record was deleted, inserted
                    # or reordered (CR-02, AC-05).
                    if (previous_hash or '') != (prev_stored_hash or ''):
                        tampered = True
                        reason = 'chain'
                else:
                    hash_string = "%s|%s|%s|%s|%s|%s" % (
                        user_id, model_model, res_id, create_date_str, details, secret,
                    )
                    expected = hashlib.sha256(hash_string.encode('utf-8')).hexdigest()

                if stored_hash != expected:
                    tampered = True
                    reason = (reason + '+hash') if reason else 'hash'

                if tampered:
                    tampered_ids.append(log_id)
                    _logger.warning(
                        "INTEGRITY ALERT: audit.log id=%s %s mismatch "
                        "(stored=%s, expected=%s)",
                        log_id, reason, stored_hash, expected,
                    )

                prev_stored_hash = stored_hash

        # Persist results for the dashboard
        ICP = self.env['ir.config_parameter'].sudo()
        ICP.set_param(
            'audit_sentinel.last_integrity_check',
            fields.Datetime.to_string(fields.Datetime.now()),
        )
        ICP.set_param(
            'audit_sentinel.last_tampered_count',
            str(len(tampered_ids)),
        )

        # Build summary message
        if tampered_ids:
            body = _(
                "<p><b>⚠ Security Sentinel — Integrity Check</b></p>"
                "<p>Verified <b>%(total)s</b> audit log(s).</p>"
                "<p style='color:red;'><b>%(count)s tampered record(s) detected:</b> "
                "IDs %(ids)s</p>"
                "<p>Investigate immediately.</p>",
                total=total,
                count=len(tampered_ids),
                ids=', '.join(str(i) for i in tampered_ids[:50]),
            )
        else:
            body = _(
                "<p><b>✓ Security Sentinel — Integrity Check</b></p>"
                "<p>Verified <b>%(total)s</b> audit log(s).</p>"
                "<p style='color:green;'>All records passed integrity verification.</p>",
                total=total,
            )

        # Notify Compliance Officers
        manager_group = self.env.ref(
            'audit_security_sentinel.group_audit_manager', raise_if_not_found=False
        )
        if manager_group:
            partner_ids = manager_group.user_ids.mapped('partner_id').ids
            if partner_ids:
                self.env['mail.message'].sudo().create({
                    'subject': _('Security Sentinel: Integrity Report'),
                    'body': body,
                    'message_type': 'notification',
                    'subtype_id': self.env.ref('mail.mt_note').id,
                    'partner_ids': [(6, 0, partner_ids)],
                    'model': self._name,
                })

        _logger.info(
            "Integrity check complete: %s logs verified, %s tampered",
            total, len(tampered_ids),
        )

    @api.model
    def _cron_cleanup_old_logs(self):
        """Scheduled action: purge audit logs older than the configured retention period.

        Reads ``audit_security_sentinel.retention_days`` from system parameters
        (default 365).  If the value is > 0, removes old records via raw SQL to
        bypass the ``unlink`` override — this is intentional for GDPR/storage
        compliance.
        """
        ICP = self.env['ir.config_parameter'].sudo()
        try:
            retention_days = int(ICP.get_param('audit_security_sentinel.retention_days', '365'))
        except (ValueError, TypeError):
            retention_days = 365
            _logger.warning("audit_security_sentinel: Invalid retention_days value, defaulting to 365")

        if retention_days <= 0:
            _logger.info("Audit log cleanup disabled (retention_days=%s)", retention_days)
            return

        cutoff_date = fields.Datetime.now() - timedelta(days=retention_days)

        # Use raw SQL to bypass the unlink() override that blocks deletion.
        # Batch deletes to avoid long-running locks on large tables.
        total_deleted = 0
        BATCH_SIZE = 10000
        while True:
            self.env.cr.execute(
                "DELETE FROM audit_log WHERE id IN ("
                "  SELECT id FROM audit_log WHERE create_date < %s LIMIT %s"
                ")",
                (cutoff_date, BATCH_SIZE),
            )
            batch_count = self.env.cr.rowcount
            total_deleted += batch_count
            if batch_count < BATCH_SIZE:
                break

        # Invalidate ORM cache after raw SQL delete
        self.env.invalidate_all()

        _logger.info(
            "Audit log cleanup complete: %s records older than %s days deleted (cutoff: %s)",
            total_deleted, retention_days, cutoff_date,
        )
