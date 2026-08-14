# -*- coding: utf-8 -*-
"""External integrity anchoring (NeuroDev Integrity Custody).

Threat model this solves
------------------------
The chained HMAC-SHA256 audit log is immutable *through the ORM*, but the HMAC
key lives in ``ir.config_parameter``, i.e. inside the very database it protects.
An attacker with direct PostgreSQL access holds the key, can rewrite an old
entry and recompute the whole chain forward. ``_cron_verify_integrity`` would
then pass green.

Anchoring moves the proof out of the compromised zone: this agent periodically
ships only the *tip* of the chain (last id, its hash, the record count and the
oldest surviving id) to an external control plane, which seals it with its own
key and timestamp. The attacker may rewrite the local database at will, but
cannot rewrite anchors already stored on the remote server, and the first
divergence pinpoints exactly when tampering happened.

Design notes
------------
* No log **content** ever leaves the customer database — only the tip metadata.
  A few hundred bytes per anchor.
* Anchors are sent even when nothing happened. An empty anchor is a heartbeat:
  "no events" and "no signal" are different states, and only the anchor stream
  can tell them apart.
* ``first_log_id`` is anchored alongside the count precisely so that a legitimate
  retention purge (which deletes the *oldest* rows and therefore raises the
  floor) is not confused with an attacker truncating the *newest* rows.
"""

import hashlib
import hmac
import json
import logging
import secrets
from datetime import timedelta

from odoo import api, fields, models, _
from odoo.exceptions import UserError

_logger = logging.getLogger(__name__)

# Timeout for every call to the control plane. Kept short on purpose: this runs
# inside a cron holding a database cursor, so it must never hang the worker.
ANCHOR_TIMEOUT = 15

PARAM_ENABLED = 'audit_security_sentinel.anchor_enabled'
PARAM_URL = 'audit_security_sentinel.anchor_url'
PARAM_UUID = 'audit_security_sentinel.anchor_instance_uuid'
PARAM_KEY = 'audit_security_sentinel.anchor_instance_key'

DEFAULT_ANCHOR_URL = 'https://www.neurodev.cl/sentinel'


def _sign_payload(key, payload_json):
    """HMAC-SHA256 of the canonical payload, keyed with the instance secret.

    Proves to the control plane that the anchor came from this instance and was
    not forged or replayed with altered numbers by whoever sits on the wire.
    """
    return hmac.new(
        key.encode('utf-8'), payload_json.encode('utf-8'), hashlib.sha256
    ).hexdigest()


class AuditAnchor(models.Model):
    _name = 'audit.anchor'
    _description = 'External Integrity Anchor'
    _order = 'id desc'

    # -- Chain tip being certified ------------------------------------
    last_log_id = fields.Integer(
        string='Last Log ID',
        readonly=True,
        help='Database ID of the newest audit log entry at anchoring time.',
    )
    first_log_id = fields.Integer(
        string='First Log ID',
        readonly=True,
        help='Database ID of the oldest surviving audit log entry. Rises only '
             'through a legitimate retention purge.',
    )
    chain_hash = fields.Char(
        string='Chain Tip Hash',
        readonly=True,
        help='Integrity hash of the newest entry. Certifies every entry before it.',
    )
    event_count = fields.Integer(
        string='Event Count',
        readonly=True,
        help='Total audit log entries present at anchoring time.',
    )

    # -- Transmission -------------------------------------------------
    state = fields.Selection(
        selection=[
            ('pending', 'Pending'),
            ('confirmed', 'Confirmed'),
            ('failed', 'Failed'),
            ('deferred', 'Deferred'),
        ],
        string='Status',
        default='pending',
        readonly=True,
        index=True,
    )
    is_heartbeat = fields.Boolean(
        string='Heartbeat',
        readonly=True,
        help='No new events since the previous anchor. Sent anyway so that a '
             'silent agent is distinguishable from a quiet one.',
    )
    sent_at = fields.Datetime(string='Sent At', readonly=True)
    receipt = fields.Char(
        string='Server Receipt',
        readonly=True,
        help='Signed receipt returned by the control plane. Local proof that '
             'this tip was certified externally at that point in time.',
    )
    receipt_date = fields.Datetime(string='Receipt Date', readonly=True)
    error_message = fields.Text(string='Error', readonly=True)

    # -- Local tamper detection ---------------------------------------
    local_alert = fields.Char(
        string='Local Alert',
        readonly=True,
        help='Set when this anchor regressed against the previous one, which '
             'means entries disappeared without a retention purge.',
    )

    def unlink(self):
        """Anchors are evidence. Never deleted from the ORM."""
        if not self:
            return True
        raise UserError(_('Integrity anchors cannot be deleted. They are evidence.'))

    # ----------------------------------------------------------------
    # Chain tip
    # ----------------------------------------------------------------
    @api.model
    def _read_chain_tip(self):
        """Return the current chain tip straight from SQL.

        Raw SQL rather than the ORM so the reading cannot be intercepted by a
        record rule or an overridden search, and so it stays cheap on large tables.
        """
        self.env.cr.execute("""
            SELECT COUNT(*), MIN(id), MAX(id)
            FROM audit_log
        """)
        count, first_id, last_id = self.env.cr.fetchone()
        chain_hash = ''
        if last_id:
            self.env.cr.execute("SELECT hash FROM audit_log WHERE id = %s", (last_id,))
            row = self.env.cr.fetchone()
            chain_hash = (row[0] if row else '') or ''
        return {
            'event_count': count or 0,
            'first_log_id': first_id or 0,
            'last_log_id': last_id or 0,
            'chain_hash': chain_hash,
        }

    @api.model
    def _detect_local_regression(self, tip, previous):
        """Compare the new tip against the last anchor and flag impossible moves.

        An append-only log can only grow. The legitimate exception is the
        retention cron, which deletes the *oldest* rows: that lowers the count
        but raises ``first_log_id``. Anything else is entries vanishing.
        """
        if not previous:
            return False

        if tip['last_log_id'] < previous.last_log_id:
            return _(
                'Newest entry went backwards (%(now)s < %(before)s). The most '
                'recent entries were deleted.',
                now=tip['last_log_id'], before=previous.last_log_id,
            )

        if tip['event_count'] < previous.event_count:
            # Retention purge raises the floor. If the floor did not move,
            # rows were removed from somewhere they should not have been.
            if tip['first_log_id'] <= previous.first_log_id:
                return _(
                    'Entry count dropped from %(before)s to %(now)s without a '
                    'retention purge. Entries were deleted.',
                    before=previous.event_count, now=tip['event_count'],
                )

        if (tip['last_log_id'] == previous.last_log_id
                and tip['chain_hash'] != previous.chain_hash
                and previous.chain_hash):
            return _(
                'The newest entry keeps its ID but its hash changed. '
                'The entry was rewritten in place.'
            )

        return False

    # ----------------------------------------------------------------
    # Cron entry point
    # ----------------------------------------------------------------
    @api.model
    def _cron_send_anchor(self):
        """Scheduled action: certify the current chain tip externally."""
        ICP = self.env['ir.config_parameter'].sudo()
        if ICP.get_param(PARAM_ENABLED, 'False') not in ('True', 'true', '1'):
            return

        instance_uuid = ICP.get_param(PARAM_UUID)
        instance_key = ICP.get_param(PARAM_KEY)
        if not instance_uuid or not instance_key:
            _logger.warning(
                "Integrity anchoring is enabled but this instance is not registered. "
                "Register it from Settings before anchors can be accepted."
            )
            return

        tip = self._read_chain_tip()
        previous = self.search([('state', '!=', 'failed')], limit=1)

        alert = self._detect_local_regression(tip, previous)
        is_heartbeat = bool(
            previous
            and tip['last_log_id'] == previous.last_log_id
            and tip['event_count'] == previous.event_count
        )

        anchor = self.create({
            'last_log_id': tip['last_log_id'],
            'first_log_id': tip['first_log_id'],
            'chain_hash': tip['chain_hash'],
            'event_count': tip['event_count'],
            'is_heartbeat': is_heartbeat,
            'local_alert': alert or False,
            'state': 'pending',
        })

        if alert:
            _logger.error("INTEGRITY ALERT (local): %s", alert)
            anchor._notify_local_alert(alert)

        anchor._send(instance_uuid, instance_key)
        # Retry anything the network left behind on earlier runs.
        self._retry_pending(instance_uuid, instance_key)
        return anchor

    @api.model
    def _retry_pending(self, instance_uuid, instance_key, limit=50):
        """Reconciliation after a connectivity outage.

        Every unsent anchor is replayed in chronological order so the control
        plane can see the whole sequence and mark the gap as deferred: during an
        outage the integrity of that stretch rested on local security alone, and
        the customer report has to say so.
        """
        pending = self.search(
            [('state', 'in', ('pending', 'failed')), ('receipt', '=', False)],
            order='id asc', limit=limit,
        )
        for anchor in pending:
            anchor._send(instance_uuid, instance_key, deferred=True)

    # ----------------------------------------------------------------
    # Transport
    # ----------------------------------------------------------------
    def _build_payload(self, instance_uuid, deferred=False):
        self.ensure_one()
        module_version = (
            self.env['ir.module.module']
            .sudo()
            .search([('name', '=', 'audit_security_sentinel')], limit=1)
            .installed_version
        ) or ''
        return {
            'instance_uuid': instance_uuid,
            'source': 'audit_security_sentinel',
            'module_version': module_version,
            'db_name': self.env.cr.dbname,
            'anchor_ref': self.id,
            'last_log_id': self.last_log_id,
            'first_log_id': self.first_log_id,
            'event_count': self.event_count,
            'chain_hash': self.chain_hash,
            'is_heartbeat': self.is_heartbeat,
            'local_alert': self.local_alert or '',
            'generated_at': fields.Datetime.to_string(self.create_date or fields.Datetime.now()),
            'deferred': deferred,
        }

    def _send(self, instance_uuid, instance_key, deferred=False):
        """POST the tip to the control plane and store the signed receipt."""
        self.ensure_one()
        import requests  # local import: keeps module import cheap and testable

        ICP = self.env['ir.config_parameter'].sudo()
        base_url = (ICP.get_param(PARAM_URL) or DEFAULT_ANCHOR_URL).rstrip('/')

        payload = self._build_payload(instance_uuid, deferred=deferred)
        payload_json = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        signature = _sign_payload(instance_key, payload_json)

        try:
            response = requests.post(
                f'{base_url}/anchor',
                data=payload_json.encode('utf-8'),
                headers={
                    'Content-Type': 'application/json',
                    'X-Sentinel-Instance': instance_uuid,
                    'X-Sentinel-Signature': signature,
                },
                timeout=ANCHOR_TIMEOUT,
            )
        except Exception as exc:  # noqa: BLE001 - never let the cron die on network
            self.sudo().write({
                'state': 'failed',
                'sent_at': fields.Datetime.now(),
                'error_message': str(exc)[:500],
            })
            _logger.warning("Integrity anchor could not be delivered: %s", exc)
            return False

        if response.status_code != 200:
            self.sudo().write({
                'state': 'failed',
                'sent_at': fields.Datetime.now(),
                'error_message': f'HTTP {response.status_code}: {response.text[:300]}',
            })
            _logger.warning(
                "Control plane rejected the anchor: HTTP %s", response.status_code
            )
            return False

        try:
            body = response.json()
        except ValueError:
            body = {}

        self.sudo().write({
            'state': 'deferred' if deferred else 'confirmed',
            'sent_at': fields.Datetime.now(),
            'receipt': (body.get('receipt') or '')[:255],
            'receipt_date': body.get('received_at') or fields.Datetime.now(),
            'error_message': False,
        })
        return True

    # ----------------------------------------------------------------
    # Notification
    # ----------------------------------------------------------------
    def _notify_local_alert(self, alert):
        """Warn Compliance Officers without waiting for the weekly cron."""
        self.ensure_one()
        manager_group = self.env.ref(
            'audit_security_sentinel.group_audit_manager', raise_if_not_found=False
        )
        if not manager_group:
            return
        partner_ids = manager_group.user_ids.mapped('partner_id').ids
        if not partner_ids:
            return
        self.env['mail.message'].sudo().create({
            'subject': _('Security Sentinel: Integrity Anchor Alert'),
            'body': _(
                "<p><b>⚠ Audit log entries disappeared</b></p>"
                "<p>%(alert)s</p>"
                "<p>The external anchor recorded this. Investigate immediately.</p>",
                alert=alert,
            ),
            'message_type': 'notification',
            'subtype_id': self.env.ref('mail.mt_note').id,
            'partner_ids': [(6, 0, partner_ids)],
            'model': self._name,
            'res_id': self.id,
        })

    # ----------------------------------------------------------------
    # Registration
    # ----------------------------------------------------------------
    @api.model
    def _register_instance(self, contact_email=''):
        """Enrol this instance with the control plane and store its secret.

        Deliberately self-service: the module is sold through the Odoo Apps
        Store and installed unattended, so enrolment cannot require editing a
        docker-compose file or setting an environment variable. The instance
        secret is generated here and never travels again after registration.
        """
        import requests

        ICP = self.env['ir.config_parameter'].sudo()
        base_url = (ICP.get_param(PARAM_URL) or DEFAULT_ANCHOR_URL).rstrip('/')

        instance_uuid = ICP.get_param(PARAM_UUID) or secrets.token_hex(16)
        instance_key = ICP.get_param(PARAM_KEY) or secrets.token_hex(32)

        company = self.env.company
        payload = {
            'instance_uuid': instance_uuid,
            'instance_key': instance_key,
            'source': 'audit_security_sentinel',
            'db_name': self.env.cr.dbname,
            'company_name': company.name or '',
            'company_vat': company.vat or '',
            'contact_email': contact_email or company.email or '',
        }

        try:
            response = requests.post(
                f'{base_url}/register',
                json=payload,
                timeout=ANCHOR_TIMEOUT,
            )
        except Exception as exc:  # noqa: BLE001
            raise UserError(
                _('Could not reach the integrity custody service: %s', exc)
            ) from exc

        if response.status_code != 200:
            raise UserError(_(
                'Registration was rejected (HTTP %(code)s): %(body)s',
                code=response.status_code, body=response.text[:300],
            ))

        ICP.set_param(PARAM_UUID, instance_uuid)
        ICP.set_param(PARAM_KEY, instance_key)
        ICP.set_param(PARAM_ENABLED, 'True')
        _logger.info("Integrity anchoring registered for instance %s", instance_uuid)
        return instance_uuid

    # ----------------------------------------------------------------
    # Health
    # ----------------------------------------------------------------
    @api.model
    def _get_anchor_health(self):
        """Summary for the settings screen and the compliance report."""
        last = self.search([('state', 'in', ('confirmed', 'deferred'))], limit=1)
        pending = self.search_count([('state', 'in', ('pending', 'failed'))])
        alerts = self.search_count([('local_alert', '!=', False)])
        stale = False
        if last and last.sent_at:
            stale = last.sent_at < fields.Datetime.now() - timedelta(hours=2)
        return {
            'last_anchor': last.sent_at,
            'last_receipt': last.receipt if last else '',
            'pending': pending,
            'alerts': alerts,
            'stale': stale,
        }
