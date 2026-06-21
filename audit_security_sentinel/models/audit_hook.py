# -*- coding: utf-8 -*-

import hashlib
import hmac
import json
import logging
import secrets
import threading
from datetime import datetime, date

from odoo import api, fields, models, SUPERUSER_ID
from odoo.http import request

_logger = logging.getLogger(__name__)

# Salt cache keyed by DB name — multi-DB safe
_salt_cache = {}
_salt_lock = threading.Lock()

# Marker stored in place of a sensitive field value (CR-01).
REDACTED = '<redacted>'

# Default substring patterns that flag a field name as sensitive (CR-01).
# Extended at runtime with the comma-separated system parameter
# ``audit_security_sentinel.sensitive_field_patterns``.
DEFAULT_SENSITIVE_FIELD_PATTERNS = (
    'password', 'passwd', 'token', 'secret', 'api_key', 'apikey',
    'private_key', 'access_token', 'refresh_token', 'authorization',
    'signature', 'bank', 'iban', 'card', 'account_number', 'cvv', 'cvc',
)

# Hash algorithm versions stored on each audit.log record (CR-02).
#   None / 1 -> legacy salted SHA-256 (records created before 2.1.5)
#   2        -> HMAC-SHA256 over the full payload + previous_hash (chained)
HASH_VERSION_HMAC_CHAIN = 2

# Fixed key used for the PostgreSQL advisory lock that serialises hash-chain
# writes so concurrent transactions never fork the chain (CR-02).
_CHAIN_LOCK_KEY = 8245723109


def _build_hash_payload_v2(fields):
    """Build the canonical JSON payload hashed by the v2 algorithm (CR-02).

    Centralised so the creation path, ``_recompute_hash``, the integrity cron
    and the report wizard all produce byte-for-byte identical payloads.

    ``company_id`` is normalised to ``int`` or ``False`` (never ``None``) so a
    log created through the ORM and one read back via raw SQL hash identically.
    """
    company_id = fields.get('company_id')
    return json.dumps(
        {
            'user_id': fields.get('user_id'),
            'model_model': fields.get('model_model') or '',
            'res_id': fields.get('res_id'),
            'name': fields.get('name') or '',
            'action_type': fields.get('action_type') or '',
            'ip_address': fields.get('ip_address') or '',
            'company_id': company_id or False,
            'create_date': fields.get('create_date') or '',
            'details': fields.get('details') or '',
            'previous_hash': fields.get('previous_hash') or '',
        },
        sort_keys=True,
        ensure_ascii=False,
        default=str,
    )


def _compute_audit_hash_v2(secret, fields):
    """Return the HMAC-SHA256 of the v2 payload keyed with ``secret`` (CR-02)."""
    payload = _build_hash_payload_v2(fields)
    return hmac.new(
        secret.encode('utf-8'), payload.encode('utf-8'), hashlib.sha256
    ).hexdigest()

# References to original BaseModel methods — stored at module level
# so the uninstall_hook can restore them cleanly.
_original_create = None
_original_write = None
_original_unlink = None


def _get_audit_salt(env):
    """Retrieve the hash salt from ir.config_parameter.

    If the parameter ``audit_security_sentinel.hash_salt`` does not exist,
    a cryptographically-secure random 64-char hex salt is generated, stored
    in the database and returned.

    The result is cached per database name so multi-DB Odoo processes each
    use the correct salt.  Access is serialised with ``_salt_lock`` so that
    concurrent workers never generate two different salts.
    """
    dbname = env.cr.dbname
    with _salt_lock:
        if dbname in _salt_cache:
            return _salt_cache[dbname]

        ICP = env['ir.config_parameter'].sudo()
        salt = ICP.get_param('audit_security_sentinel.hash_salt')
        if not salt:
            salt = secrets.token_hex(32)
            ICP.set_param('audit_security_sentinel.hash_salt', salt)
            _logger.info("Audit Security Sentinel: Generated new hash salt")

        _salt_cache[dbname] = salt
        return salt


def invalidate_salt_cache():
    """Invalidate the salt cache for all databases.

    Called on module upgrade so the salt is re-read from the database.
    """
    with _salt_lock:
        _salt_cache.clear()


def remove_audit_hooks():
    """Restore original BaseModel methods when the module is uninstalled.

    Reverts the monkey-patch applied by ``install_audit_hooks`` so that
    create/write/unlink behave normally after uninstall.
    """
    from odoo import models as odoo_models
    if not getattr(odoo_models.BaseModel, '_audit_sentinel_patched', False):
        _logger.debug("Audit Security Sentinel: No hooks to remove")
        return
    if _original_create:
        odoo_models.BaseModel.create = _original_create
    if _original_write:
        odoo_models.BaseModel.write = _original_write
    if _original_unlink:
        odoo_models.BaseModel.unlink = _original_unlink
    try:
        delattr(odoo_models.BaseModel, '_audit_sentinel_patched')
    except AttributeError:
        pass
    _logger.info("Audit Security Sentinel: Hooks removed successfully")


class BaseModelAuditHook(models.AbstractModel):
    _name = 'base.model.audit.hook'
    _description = 'Audit Hook Mixin'

    # Cache for audit rules — keyed by database name to be multi-DB safe
    _audit_rules_cache = {}
    _audit_cache_timestamps = {}
    _rules_lock = threading.Lock()
    _CACHE_TTL = 300  # 5 minutes cache

    @api.model
    def _get_audit_rule(self, model_name):
        """Get active audit rule for a model with caching (multi-DB safe).

        Caches a plain dict (not a recordset) to avoid stale cursor issues
        when the cache is read across different transactions.  Access is
        serialised with ``_rules_lock`` for thread safety.

        The ORM search only flushes ``audit.rule`` and the fields in its domain
        (it is selective, never global), so it does NOT flush the caller's
        pending records. The premature *global* flush that used to break core
        tests came from the surrounding ``cr.savepoint()`` default of
        ``flush=True`` — the callers now use ``flush=False`` (CR-04).
        """
        now = fields.Datetime.now()  # Always UTC, avoids naive/aware mismatch
        dbname = self.env.cr.dbname

        with self._rules_lock:
            # Invalidate cache if expired for this database
            db_timestamp = self._audit_cache_timestamps.get(dbname)
            if (db_timestamp is None or (now - db_timestamp).total_seconds() > self._CACHE_TTL):
                self._audit_rules_cache[dbname] = {}
                self._audit_cache_timestamps[dbname] = now

            db_cache = self._audit_rules_cache.setdefault(dbname, {})
            if model_name in db_cache:
                return db_cache[model_name]

        # Search outside the lock to avoid holding it during DB queries
        rule = self.env['audit.rule'].sudo().search([
            ('model_id.model', '=', model_name),
            ('active', '=', True),
        ], limit=1)
        if rule:
            result = {
                'id': rule.id,
                'log_create': rule.log_create,
                'log_write': rule.log_write,
                'log_unlink': rule.log_unlink,
                'field_names': rule.get_monitored_fields(),
            }
        else:
            result = False

        with self._rules_lock:
            db_cache = self._audit_rules_cache.setdefault(dbname, {})
            db_cache[model_name] = result

        return result

    @api.model
    def _invalidate_rules_cache(self):
        """Drop the cached audit rules for the current database (MD-02).

        Called from audit.rule create/write/unlink so a rule change takes
        effect immediately instead of waiting up to _CACHE_TTL seconds. In
        multi-worker setups each worker still refreshes within the TTL.
        """
        dbname = self.env.cr.dbname
        with self._rules_lock:
            self._audit_rules_cache.pop(dbname, None)
            self._audit_cache_timestamps.pop(dbname, None)

    def _get_ip_address(self):
        """Extract client IP address from the request.

        CR-03: only trust X-Forwarded-For / X-Real-IP when the direct peer
        (remote_addr) is a configured trusted proxy. Otherwise a client could
        spoof its IP with a forged header. The trusted proxy list is configurable
        via the ``audit_security_sentinel.trusted_proxies`` system parameter
        (comma-separated). Empty by default = trust only the direct remote_addr.
        """
        try:
            if request and hasattr(request, 'httprequest'):
                remote_addr = request.httprequest.remote_addr
                trusted = self.env['ir.config_parameter'].sudo().get_param(
                    'audit_security_sentinel.trusted_proxies', ''
                )
                trusted_proxies = {p.strip() for p in trusted.split(',') if p.strip()}
                if remote_addr in trusted_proxies:
                    forwarded_for = request.httprequest.headers.get('X-Forwarded-For')
                    if forwarded_for:
                        return forwarded_for.split(',')[0].strip()
                    real_ip = request.httprequest.headers.get('X-Real-IP')
                    if real_ip:
                        return real_ip.strip()
                return remote_addr or 'Unknown'
        except Exception:
            pass
        return 'System/Cron'

    def _generate_audit_hash(self, user_id, model, res_id, create_date, details):
        """Generate SHA-256 hash for integrity verification.

        Args:
            user_id: UID of the user who performed the action.
            model: Technical model name (e.g. ``res.partner``).
            res_id: Database ID of the affected record.
            create_date: ``datetime`` or ISO string of when the log entry was created.
            details: JSON string with change details.
        """
        salt = _get_audit_salt(self.env)
        # Use fixed format to avoid isoformat() microsecond inconsistency
        if isinstance(create_date, datetime):
            create_date_str = create_date.strftime('%Y-%m-%d %H:%M:%S')
        elif create_date is None:
            create_date_str = ''
        else:
            create_date_str = str(create_date)[:19]  # Truncate to seconds
        hash_string = f"{user_id}|{model}|{res_id}|{create_date_str}|{details}|{salt}"
        return hashlib.sha256(hash_string.encode('utf-8')).hexdigest()

    def _get_record_display_name(self, record):
        """Safely get display name of a record."""
        try:
            if hasattr(record, 'display_name') and record.display_name:
                return record.display_name
            if hasattr(record, 'name') and record.name:
                return record.name
            return f"ID: {record.id}"
        except Exception:
            return f"ID: {record.id if hasattr(record, 'id') else 'Unknown'}"

    def _serialize_value(self, value):
        """Serialize a field value to a JSON-compatible format."""
        if value is False or value is None:
            return None
        if isinstance(value, models.BaseModel):
            if len(value) == 1:
                return {'id': value.id, 'name': self._get_record_display_name(value)}
            return [{'id': r.id, 'name': self._get_record_display_name(r)} for r in value]
        if isinstance(value, (datetime, date)):
            return value.isoformat()
        if isinstance(value, bytes):
            return '<binary data>'
        return value

    def _get_sensitive_field_patterns(self):
        """Return the active set of sensitive-field substring patterns (CR-01).

        Combines the built-in defaults with the optional comma-separated
        ``audit_security_sentinel.sensitive_field_patterns`` system parameter
        so each deployment can extend the blacklist without code changes.
        """
        patterns = set(DEFAULT_SENSITIVE_FIELD_PATTERNS)
        try:
            extra = self.env['ir.config_parameter'].sudo().get_param(
                'audit_security_sentinel.sensitive_field_patterns', ''
            )
            patterns.update(p.strip().lower() for p in extra.split(',') if p.strip())
        except Exception:
            pass
        return patterns

    def _is_sensitive_field(self, field_name, patterns=None):
        """True if ``field_name`` matches any sensitive pattern (CR-01)."""
        if patterns is None:
            patterns = self._get_sensitive_field_patterns()
        name = (field_name or '').lower()
        return any(pattern in name for pattern in patterns)

    def _create_audit_log(self, action_type, model_name, res_id, name, details_dict, company_id=None):
        """Create an audit log entry with a chained HMAC integrity hash (CR-02).

        The hash is computed AFTER the ORM create so we use the actual
        ``create_date`` stored in the database, guaranteeing that
        ``_recompute_hash`` (and the integrity cron) always reproduce the
        same value.

        A transaction-level PostgreSQL advisory lock serialises the read of the
        previous hash and the insert so concurrent transactions never fork the
        hash chain. All DB operations run inside a savepoint so that a failure
        here never leaves the cursor in InFailedSqlTransaction state — which
        would corrupt the caller's business transaction.
        """
        try:
            with self.env.cr.savepoint():
                details_json = json.dumps(details_dict, ensure_ascii=False, default=str)
                user_id = self.env.uid or SUPERUSER_ID
                ip_address = self._get_ip_address()
                # CR-09: use the affected record's company; fall back to env.company
                if company_id is None:
                    company_id = self.env.company.id if self.env.company else False

                # Serialise chain writes and read the tail hash atomically so
                # concurrent transactions cannot link to the same predecessor.
                self.env.cr.execute('SELECT pg_advisory_xact_lock(%s)', (_CHAIN_LOCK_KEY,))
                self.env.cr.execute('SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1')
                row = self.env.cr.fetchone()
                previous_hash = (row[0] if row else '') or ''

                # Step 1 — create the record without its own hash first
                record = self.env['audit.log'].sudo().create({
                    'user_id': user_id,
                    'name': name or f'{model_name},{res_id}',
                    'model_model': model_name,
                    'res_id': res_id,
                    'ip_address': ip_address,
                    'action_type': action_type,
                    'details': details_json,
                    'hash': '',
                    'previous_hash': previous_hash,
                    'hash_version': HASH_VERSION_HMAC_CHAIN,
                    'company_id': company_id,
                })

                # Step 2 — HMAC over the full payload (CR-02) using the real
                # create_date and stored name from the DB.
                secret = _get_audit_salt(self.env)
                create_date_str = (
                    record.create_date.strftime('%Y-%m-%d %H:%M:%S')
                    if record.create_date else ''
                )
                audit_hash = _compute_audit_hash_v2(secret, {
                    'user_id': user_id,
                    'model_model': model_name,
                    'res_id': res_id,
                    'name': record.name,
                    'action_type': action_type,
                    'ip_address': ip_address,
                    'company_id': company_id,
                    'create_date': create_date_str,
                    'details': details_json,
                    'previous_hash': previous_hash,
                })

                # Step 3 — write hash using context flag to bypass immutability check
                record.with_context(_audit_hash_update=True).write({'hash': audit_hash})
        except Exception as e:
            _logger.critical("Failed to create audit log: %s", e)


class BaseModelExtended(models.AbstractModel):
    """
    This model extends BaseModel behavior for auditing.
    The actual hook is installed via monkey-patching in the module's __init__.py
    """
    _inherit = 'base'

    def _audit_create(self, vals_list, rule):
        """Log creation of records.

        Only logs the fields that were explicitly provided in ``vals_list``
        to avoid iterating over all model fields (which is very slow on
        models with 100+ fields).
        """
        AuditHook = self.env['base.model.audit.hook']
        # CR-10: honour log_field_ids on create, exactly like write does.
        monitored_fields = rule['field_names'] if isinstance(rule, dict) else rule.get_monitored_fields()
        # CR-01: resolve sensitive patterns once per batch.
        sensitive_patterns = AuditHook._get_sensitive_field_patterns()

        for idx, record in enumerate(self):
            details = {
                'action': 'create',
                'new_values': {},
            }

            # Use the original vals for this record instead of iterating all fields
            vals = vals_list[idx] if idx < len(vals_list) else {}
            for field_name in vals:
                if field_name in ('id', 'create_uid', 'create_date', 'write_uid', 'write_date', '__last_update'):
                    continue
                if field_name not in record._fields:
                    continue
                # CR-10: if specific fields are configured, only log those.
                if monitored_fields and field_name not in monitored_fields:
                    continue
                try:
                    field_value = record[field_name]
                    serialized = AuditHook._serialize_value(field_value)
                    if serialized is not None:
                        # CR-01: never store sensitive values in clear text.
                        if AuditHook._is_sensitive_field(field_name, sensitive_patterns):
                            serialized = REDACTED
                        details['new_values'][field_name] = serialized
                except Exception:
                    continue

            log_company = record.company_id.id if 'company_id' in record._fields else None
            AuditHook._create_audit_log(
                'create',
                self._name,
                record.id,
                AuditHook._get_record_display_name(record),
                details,
                company_id=log_company,
            )

    def _audit_write(self, vals, rule, old_values):
        """Log modification of records."""
        AuditHook = self.env['base.model.audit.hook']
        monitored_fields = rule['field_names'] if isinstance(rule, dict) else rule.get_monitored_fields()
        # CR-01: resolve sensitive patterns once per batch.
        sensitive_patterns = AuditHook._get_sensitive_field_patterns()

        for record in self:
            if record.id not in old_values:
                continue

            old_record_values = old_values[record.id]
            changes = {}

            for field_name in vals.keys():
                # Skip system fields
                if field_name in ('write_uid', 'write_date', '__last_update'):
                    continue

                # Check if we should monitor this field
                if monitored_fields and field_name not in monitored_fields:
                    continue

                try:
                    old_val = old_record_values.get(field_name)
                    new_val = record[field_name]

                    old_serialized = AuditHook._serialize_value(old_val)
                    new_serialized = AuditHook._serialize_value(new_val)

                    # Only log if value actually changed
                    if old_serialized != new_serialized:
                        # CR-01: record that a sensitive field changed without
                        # exposing either value.
                        if AuditHook._is_sensitive_field(field_name, sensitive_patterns):
                            changes[field_name] = {'old': REDACTED, 'new': REDACTED}
                        else:
                            changes[field_name] = {
                                'old': old_serialized,
                                'new': new_serialized,
                            }
                except Exception as e:
                    _logger.debug("Could not compare field %s: %s", field_name, e)
                    continue

            # Only create log if there were actual changes
            if changes:
                details = {
                    'action': 'write',
                    'changes': changes,
                }
                log_company = record.company_id.id if 'company_id' in record._fields else None
                AuditHook._create_audit_log(
                    'write',
                    self._name,
                    record.id,
                    AuditHook._get_record_display_name(record),
                    details,
                    company_id=log_company,
                )

    def _audit_unlink(self, rule):
        """Log deletion of records."""
        AuditHook = self.env['base.model.audit.hook']
        # CR-01: resolve sensitive patterns once per batch.
        sensitive_patterns = AuditHook._get_sensitive_field_patterns()

        for record in self:
            details = {
                'action': 'unlink',
                'deleted_record': {
                    'id': record.id,
                    'name': AuditHook._get_record_display_name(record),
                },
            }

            # Capture key field values before deletion
            deleted_values = {}
            for field_name in ('name', 'code', 'ref', 'email', 'partner_id', 'product_id'):
                if field_name in record._fields:
                    try:
                        val = record[field_name]
                        serialized = AuditHook._serialize_value(val)
                        if serialized is not None:
                            # CR-01: never store sensitive values in clear text.
                            if AuditHook._is_sensitive_field(field_name, sensitive_patterns):
                                serialized = REDACTED
                            deleted_values[field_name] = serialized
                    except Exception:
                        continue

            if deleted_values:
                details['key_values'] = deleted_values

            log_company = record.company_id.id if 'company_id' in record._fields else None
            AuditHook._create_audit_log(
                'unlink',
                self._name,
                record.id,
                AuditHook._get_record_display_name(record),
                details,
                company_id=log_company,
            )


def install_audit_hooks():
    """
    Install audit hooks on BaseModel methods.
    This is called from the module's __init__.py
    """
    from odoo import models as odoo_models

    # Guard against double-patching when the module is reloaded
    if getattr(odoo_models.BaseModel, '_audit_sentinel_patched', False):
        _logger.debug("Audit Security Sentinel: Hooks already installed, skipping")
        return

    # Invalidate the salt cache on (re)install so it is re-read from DB
    invalidate_salt_cache()

    global _original_create, _original_write, _original_unlink
    _original_create = odoo_models.BaseModel.create
    _original_write = odoo_models.BaseModel.write
    _original_unlink = odoo_models.BaseModel.unlink

    @api.model_create_multi
    def _audited_create(self, vals_list):
        """Wrapped create method with audit logging.

        Every audit SQL operation runs inside a cr.savepoint() so that
        failures never leave the cursor in InFailedSqlTransaction state.
        """
        # Skip audit for audit models themselves
        if self._name in ('audit.log', 'audit.rule', 'base.model.audit.hook'):
            return _original_create(self, vals_list)

        # Check for active audit rule (savepoint-protected)
        rule = None
        try:
            # flush=False: the rule lookup must NOT force a global flush of the
            # caller's pending records, which would change constraint and
            # notification timing in unrelated modules (CR-04).
            with self.env.cr.savepoint(flush=False):
                AuditHook = self.env['base.model.audit.hook']
                rule = AuditHook._get_audit_rule(self._name)
        except Exception:
            pass

        if not rule or not rule.get('log_create'):
            return _original_create(self, vals_list)

        # Execute original create
        records = _original_create(self, vals_list)

        # Log creation (savepoint-protected)
        try:
            with self.env.cr.savepoint():
                records._audit_create(vals_list, rule)
        except Exception as e:
            _logger.error("Audit create failed for %s: %s", self._name, e)

        return records

    def _audited_write(self, vals):
        """Wrapped write method with audit logging.

        Every audit SQL operation runs inside a cr.savepoint() so that
        failures never leave the cursor in InFailedSqlTransaction state.
        """
        # Skip audit for audit models themselves
        if self._name in ('audit.log', 'audit.rule', 'base.model.audit.hook'):
            return _original_write(self, vals)

        # Check for active audit rule (savepoint-protected)
        rule = None
        try:
            # flush=False: the rule lookup must NOT force a global flush of the
            # caller's pending records, which would change constraint and
            # notification timing in unrelated modules (CR-04).
            with self.env.cr.savepoint(flush=False):
                AuditHook = self.env['base.model.audit.hook']
                rule = AuditHook._get_audit_rule(self._name)
        except Exception:
            pass

        if not rule or not rule.get('log_write'):
            return _original_write(self, vals)

        # Capture old values before write (savepoint-protected)
        old_values = {}
        try:
            with self.env.cr.savepoint():
                monitored_fields = rule['field_names']
                fields_to_read = list(vals.keys())
                if monitored_fields:
                    fields_to_read = [f for f in fields_to_read if f in monitored_fields]

                if fields_to_read:
                    for record in self:
                        old_values[record.id] = {}
                        for field_name in fields_to_read:
                            if field_name in record._fields:
                                try:
                                    old_values[record.id][field_name] = record[field_name]
                                except Exception:
                                    continue
        except Exception as e:
            _logger.debug("Could not capture old values: %s", e)

        # Execute original write
        result = _original_write(self, vals)

        # Log changes (savepoint-protected)
        try:
            with self.env.cr.savepoint():
                if old_values:
                    self._audit_write(vals, rule, old_values)
        except Exception as e:
            _logger.error("Audit write failed for %s: %s", self._name, e)

        return result

    def _audited_unlink(self):
        """Wrapped unlink method with audit logging.

        Every audit SQL operation runs inside a cr.savepoint() so that
        failures never leave the cursor in InFailedSqlTransaction state.
        """
        # Skip audit for audit models themselves
        if self._name in ('audit.log', 'audit.rule', 'base.model.audit.hook'):
            return _original_unlink(self)

        # Check for active audit rule (savepoint-protected)
        rule = None
        try:
            # flush=False: the rule lookup must NOT force a global flush of the
            # caller's pending records, which would change constraint and
            # notification timing in unrelated modules (CR-04).
            with self.env.cr.savepoint(flush=False):
                AuditHook = self.env['base.model.audit.hook']
                rule = AuditHook._get_audit_rule(self._name)
        except Exception:
            pass

        if not rule or not rule.get('log_unlink'):
            return _original_unlink(self)

        # Log deletion before it happens (savepoint-protected)
        try:
            with self.env.cr.savepoint():
                self._audit_unlink(rule)
        except Exception as e:
            _logger.error("Audit unlink failed for %s: %s", self._name, e)

        # Execute original unlink
        return _original_unlink(self)

    # Apply the monkey patches
    odoo_models.BaseModel.create = _audited_create
    odoo_models.BaseModel.write = _audited_write
    odoo_models.BaseModel.unlink = _audited_unlink

    # Mark BaseModel so we never double-patch
    odoo_models.BaseModel._audit_sentinel_patched = True

    _logger.info("Audit Security Sentinel: Hooks installed successfully")
