# -*- coding: utf-8 -*-

import logging
import secrets

from odoo import api, fields, models, _
from odoo.exceptions import AccessError, UserError

_logger = logging.getLogger(__name__)


class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    # -- Retention --
    audit_retention_days = fields.Integer(
        string='Log Retention (Days)',
        default=365,
        config_parameter='audit_security_sentinel.retention_days',
        help=(
            'Number of days to keep audit log records. '
            'Logs older than this will be purged by the retention cron.'
        ),
    )

    # -- HMAC key (display only) --
    audit_hash_salt_display = fields.Char(
        string='Current HMAC Key',
        compute='_compute_audit_hash_salt_display',
        help=(
            'First 8 characters of the active HMAC key used for the integrity '
            'hashes, shown for verification purposes. The full key is never exposed.'
        ),
    )

    # -- Dashboard auto-refresh --
    audit_dashboard_refresh = fields.Integer(
        string='Dashboard Refresh Interval (s)',
        default=60,
        config_parameter='audit_security_sentinel.dashboard_refresh_interval',
        help='Auto-refresh interval in seconds for the real-time audit dashboard.',
    )

    # -- Trusted proxies (CR-03) --
    audit_trusted_proxies = fields.Char(
        string='Trusted Proxies',
        config_parameter='audit_security_sentinel.trusted_proxies',
        help=(
            'Comma-separated list of proxy IPs allowed to set the client IP via '
            'X-Forwarded-For / X-Real-IP headers. Leave empty to record only the '
            'direct connection IP (recommended unless Odoo runs behind a proxy).'
        ),
    )

    # -- Sensitive field masking (CR-01) --
    audit_sensitive_field_patterns = fields.Char(
        string='Extra Sensitive Field Patterns',
        config_parameter='audit_security_sentinel.sensitive_field_patterns',
        help=(
            'Comma-separated extra substrings that flag a field name as sensitive. '
            'Matching values are stored as <redacted> in the audit log, dashboard '
            'and reports. These add to the built-in list (password, token, secret, '
            'api_key, private_key, iban, card, account_number, ...).'
        ),
    )

    # -- External integrity anchoring --
    audit_anchor_enabled = fields.Boolean(
        string='External Integrity Anchoring',
        config_parameter='audit_security_sentinel.anchor_enabled',
        help=(
            'Periodically certify the tip of the audit chain on an external '
            'custody service. The HMAC key lives in this database, so anyone '
            'with direct PostgreSQL access could rewrite an entry and recompute '
            'the whole chain. An external anchor cannot be rewritten from here, '
            'so the tampering becomes detectable. No log content is transmitted, '
            'only the last entry ID, its hash and the record count.'
        ),
    )
    audit_anchor_url = fields.Char(
        string='Custody Service URL',
        default='https://www.neurodev.cl/sentinel',
        config_parameter='audit_security_sentinel.anchor_url',
        help='Base URL of the integrity custody service.',
    )
    audit_anchor_instance_display = fields.Char(
        string='Registered Instance',
        compute='_compute_audit_anchor_status',
    )
    audit_anchor_status_display = fields.Char(
        string='Anchor Status',
        compute='_compute_audit_anchor_status',
    )

    # ----------------------------------------------------------------
    # Compute
    # ----------------------------------------------------------------
    @api.depends_context('uid')
    def _compute_audit_anchor_status(self):
        """Show enrolment state and last anchor without exposing the secret."""
        ICP = self.env['ir.config_parameter'].sudo()
        uuid = ICP.get_param('audit_security_sentinel.anchor_instance_uuid', default='')
        health = self.env['audit.anchor'].sudo()._get_anchor_health()

        if not uuid:
            instance = _('Not registered')
            status = _('Register this instance to start anchoring.')
        else:
            instance = f"{uuid[:8]}..."
            if not health['last_anchor']:
                status = _('Registered. No anchor sent yet.')
            elif health['alerts']:
                status = _(
                    'Last anchor %(date)s. %(alerts)s integrity alert(s) recorded.',
                    date=health['last_anchor'], alerts=health['alerts'],
                )
            elif health['pending']:
                status = _(
                    'Last anchor %(date)s. %(pending)s pending delivery '
                    '(deferred anchoring).',
                    date=health['last_anchor'], pending=health['pending'],
                )
            elif health['stale']:
                status = _(
                    'Last anchor %(date)s. No signal for over 2 hours.',
                    date=health['last_anchor'],
                )
            else:
                status = _('Last anchor %(date)s. Chain certified.', date=health['last_anchor'])

        for record in self:
            record.audit_anchor_instance_display = instance
            record.audit_anchor_status_display = status

    @api.depends_context('uid')
    def _compute_audit_hash_salt_display(self):
        """Show a masked preview of the hash salt for verification."""
        ICP = self.env['ir.config_parameter'].sudo()
        salt = ICP.get_param('audit_security_sentinel.hash_salt', default='')
        masked = f"{salt[:8]}..." if len(salt) > 8 else salt or _('Not configured')
        for record in self:
            record.audit_hash_salt_display = masked

    # ----------------------------------------------------------------
    # Actions
    # ----------------------------------------------------------------
    def action_register_anchor(self):
        """Enrol this instance with the custody service and turn anchoring on.

        Self-service on purpose: the module is installed unattended from the
        Odoo Apps Store, so enrolment must never require touching the server.
        """
        self.ensure_one()
        if not self.env.user.has_group('audit_security_sentinel.group_audit_manager'):
            raise AccessError(_('Only Compliance Officers can register the instance.'))

        self.env['audit.anchor'].sudo()._register_instance(
            contact_email=self.env.user.email or '',
        )

        # Turn the anchoring cron on. It ships disabled so that installing the
        # module never sends anything outbound without an explicit decision.
        cron = self.env.ref(
            'audit_security_sentinel.ir_cron_send_anchor', raise_if_not_found=False
        )
        if cron:
            cron.sudo().active = True

        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Instance Registered'),
                'message': _(
                    'External integrity anchoring is active. The chain tip will '
                    'be certified every 15 minutes.'
                ),
                'type': 'success',
                'sticky': False,
                'next': {'type': 'ir.actions.act_window_close'},
            },
        }

    def action_send_anchor_now(self):
        """Send an anchor immediately instead of waiting for the cron."""
        self.ensure_one()
        if not self.env.user.has_group('audit_security_sentinel.group_audit_manager'):
            raise AccessError(_('Only Compliance Officers can send an anchor.'))

        anchor = self.env['audit.anchor'].sudo()._cron_send_anchor()
        if not anchor:
            raise UserError(_(
                'Anchoring is disabled or this instance is not registered yet.'
            ))
        if anchor.state == 'failed':
            raise UserError(_(
                'The anchor could not be delivered: %s', anchor.error_message or '',
            ))
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Anchor Sent'),
                'message': _(
                    'Chain tip certified: %(count)s entries, last ID %(last)s.',
                    count=anchor.event_count, last=anchor.last_log_id,
                ),
                'type': 'success',
                'sticky': False,
            },
        }

    def action_regenerate_salt(self):
        """Generate a new cryptographic salt and store it in system parameters.

        WARNING: This invalidates the integrity hash of every existing
        audit.log record. Use only when strictly necessary.
        Restricted to Compliance Officers (group_audit_manager).
        """
        self.ensure_one()
        if not self.env.user.has_group('audit_security_sentinel.group_audit_manager'):
            raise AccessError(_('Only Compliance Officers can regenerate the hash salt.'))
        new_salt = secrets.token_hex(32)
        self.env['ir.config_parameter'].sudo().set_param(
            'audit_security_sentinel.hash_salt', new_salt,
        )
        # Invalidate in-memory salt cache so the new salt is used immediately
        from .audit_hook import invalidate_salt_cache
        invalidate_salt_cache()
        _logger.warning(
            "Security Sentinel: Hash salt regenerated by uid=%s. "
            "All existing audit hashes are now invalid.",
            self.env.uid,
        )
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Salt Regenerated'),
                'message': _(
                    'A new hash salt has been generated. '
                    'All previously computed integrity hashes are now invalid.'
                ),
                'type': 'warning',
                'sticky': True,
            },
        }
