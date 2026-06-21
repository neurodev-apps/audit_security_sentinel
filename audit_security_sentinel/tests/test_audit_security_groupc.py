# -*- coding: utf-8 -*-
"""Acceptance tests for the client-requested hardening (group C).

Covers the report's acceptance criteria:
  * AC-01 — sensitive field values are never stored in clear text (masking).
  * AC-02 — Audit Users cannot see or export change details; only the
            Compliance Officer can.
  * AC-03 — tampering with name / action_type / ip_address (now part of the
            integrity payload) is detected.
  * AC-05 — deleting an intermediate log breaks the hash chain.
"""

import json

from odoo.tests.common import TransactionCase


class _AuditGroupCBase(TransactionCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        partner_model = cls.env['ir.model'].search(
            [('model', '=', 'res.partner')], limit=1
        )
        cls.audit_rule = cls.env['audit.rule'].sudo().create({
            'name': 'Group C Partner Rule',
            'model_id': partner_model.id,
            'log_create': True,
            'log_write': True,
            'log_unlink': True,
        })
        cls.audit_user = cls.env['res.users'].create({
            'name': 'GroupC Audit User',
            'login': 'groupc_audit_user@test.com',
            'groups_id': [(4, cls.env.ref('audit_security_sentinel.group_audit_user').id)],
        })
        cls.audit_manager = cls.env['res.users'].create({
            'name': 'GroupC Compliance Officer',
            'login': 'groupc_compliance@test.com',
            'groups_id': [(4, cls.env.ref('audit_security_sentinel.group_audit_manager').id)],
        })
        cls._reset_rule_cache()

    @classmethod
    def _reset_rule_cache(cls):
        hook = cls.env['base.model.audit.hook']
        hook._audit_rules_cache.clear()
        hook._audit_cache_timestamps.clear()

    def setUp(self):
        # The hook's rule cache is shared class-level state; reset it before
        # each test so a previous test that cached "res.partner -> no rule"
        # cannot leak in and silently skip auditing here (test isolation).
        super().setUp()
        self._reset_rule_cache()

    def _last_log(self, res_id, action_type):
        return self.env['audit.log'].sudo().search([
            ('model_model', '=', 'res.partner'),
            ('res_id', '=', res_id),
            ('action_type', '=', action_type),
        ], order='id desc', limit=1)


class TestSensitiveMasking(_AuditGroupCBase):
    """CR-01 / AC-01."""

    def test_default_sensitive_patterns(self):
        """The built-in blacklist flags the documented field names."""
        hook = self.env['base.model.audit.hook']
        for name in ('password', 'user_password', 'api_key', 'access_token',
                     'oauth_secret', 'card_number', 'iban', 'private_key'):
            self.assertTrue(hook._is_sensitive_field(name),
                            "%r must be detected as sensitive" % name)
        for name in ('name', 'email', 'street', 'phone'):
            self.assertFalse(hook._is_sensitive_field(name),
                             "%r must NOT be detected as sensitive" % name)

    def test_configured_pattern_masked_on_create(self):
        """A field matching a configured pattern is redacted on create."""
        self.env['ir.config_parameter'].sudo().set_param(
            'audit_security_sentinel.sensitive_field_patterns', 'function'
        )
        partner = self.env['res.partner'].create({
            'name': 'Masking Create',
            'function': 'SECRET-DATA-123',
        })
        log = self._last_log(partner.id, 'create')
        self.assertTrue(log, "create log must exist")
        self.assertNotIn('SECRET-DATA-123', log.details,
                         "sensitive value must never be stored in clear text")
        parsed = json.loads(log.details)
        self.assertEqual(parsed['new_values'].get('function'), '<redacted>')
        # A non-sensitive field is still recorded in clear text.
        self.assertEqual(parsed['new_values'].get('name'), 'Masking Create')

    def test_configured_pattern_masked_on_write(self):
        """A sensitive field change is recorded without exposing either value."""
        self.env['ir.config_parameter'].sudo().set_param(
            'audit_security_sentinel.sensitive_field_patterns', 'function'
        )
        partner = self.env['res.partner'].create({
            'name': 'Masking Write',
            'function': 'OLD-SECRET',
        })
        partner.write({'function': 'NEW-SECRET'})
        log = self._last_log(partner.id, 'write')
        self.assertTrue(log, "write log must exist")
        self.assertNotIn('OLD-SECRET', log.details)
        self.assertNotIn('NEW-SECRET', log.details)
        parsed = json.loads(log.details)
        self.assertEqual(parsed['changes']['function'],
                         {'old': '<redacted>', 'new': '<redacted>'},
                         "both old and new sensitive values must be redacted")


class TestRoleBasedDetailAccess(_AuditGroupCBase):
    """CR-07 / AC-02."""

    def test_dashboard_hides_details_from_audit_user(self):
        """recent_logs must omit details for a plain Audit User."""
        partner = self.env['res.partner'].create({'name': 'Dashboard Role Test'})
        log = self._last_log(partner.id, 'create')
        self.assertTrue(log, "the partner create must have been audited (no log found)")

        # Explicit wide range: fields.Datetime.now() (the default date_to)
        # truncates microseconds, so a log created in the same second as the
        # call would fall just outside the default 'today' window.
        date_from, date_to = '2000-01-01 00:00:00', '2999-12-31 23:59:59'

        data_user = self.env['audit.log'].with_user(self.audit_user).get_dashboard_data(date_from, date_to)
        row = next((r for r in data_user['recent_logs'] if r['id'] == log.id), None)
        self.assertIsNotNone(row, "the log must appear in the dashboard feed")
        self.assertFalse(row['details'],
                         "Audit User must not receive change details")

        data_mgr = self.env['audit.log'].with_user(self.audit_manager).get_dashboard_data(date_from, date_to)
        row_mgr = next((r for r in data_mgr['recent_logs'] if r['id'] == log.id), None)
        self.assertIsNotNone(row_mgr)
        self.assertTrue(row_mgr['details'],
                        "Compliance Officer must receive change details")

    def test_export_details_blocked_for_audit_user(self):
        """_effective_include_details is gated on the Compliance Officer group."""
        wizard_user = self.env['audit.report.wizard'].with_user(
            self.audit_user
        ).create({
            'date_from': self.audit_rule.create_date.date(),
            'date_to': self.audit_rule.create_date.date(),
            'include_details': True,
        })
        self.assertFalse(wizard_user._effective_include_details(),
                         "Audit User must never export change details")

        wizard_mgr = self.env['audit.report.wizard'].with_user(
            self.audit_manager
        ).create({
            'date_from': self.audit_rule.create_date.date(),
            'date_to': self.audit_rule.create_date.date(),
            'include_details': True,
        })
        self.assertTrue(wizard_mgr._effective_include_details(),
                        "Compliance Officer can export change details")


class TestIntegrityAndChain(_AuditGroupCBase):
    """CR-02 / AC-03 / AC-05."""

    def test_v2_hash_covers_metadata(self):
        """Tampering with name / action_type / ip_address is detected (AC-03)."""
        Log = self.env['audit.log'].sudo()
        cases = {
            'name': 'tampered-name',
            'action_type': 'unlink',
            'ip_address': '9.9.9.9',
        }
        for field, value in cases.items():
            partner = self.env['res.partner'].create({'name': 'Meta %s' % field})
            log = self._last_log(partner.id, 'create')
            self.assertTrue(log, "create log must exist for %s" % field)
            self.assertEqual(log.hash, log._recompute_hash(),
                             "untampered v2 hash must verify for %s" % field)
            Log.browse(log.id)  # ensure in cache
            self.env.cr.execute(
                "UPDATE audit_log SET %s = %%s WHERE id = %%s" % field,
                (value, log.id),
            )
            log.invalidate_recordset([field])
            self.assertNotEqual(log.hash, log._recompute_hash(),
                                "tampering with %s must be detected" % field)

    def test_chain_is_continuous_and_breaks_on_delete(self):
        """Consecutive logs are chained; deleting one breaks the link (AC-05)."""
        Log = self.env['audit.log'].sudo()
        before_max = Log.search([], order='id desc', limit=1).id or 0
        for i in range(4):
            self.env['res.partner'].create({'name': 'Chain %s' % i})
        mine = Log.search([('id', '>', before_max)], order='id asc')
        self.assertGreaterEqual(len(mine), 4, "expected at least 4 chained logs")

        # The chain is continuous across consecutive entries.
        records = list(mine)
        for prev, cur in zip(records, records[1:]):
            self.assertEqual(cur.previous_hash, prev.hash,
                             "each log must chain to its predecessor")

        # Delete an intermediate record via raw SQL (bypassing immutability).
        mid = len(records) // 2
        victim = records[mid]
        successor = records[mid + 1]
        predecessor = records[mid - 1]
        self.env.cr.execute("DELETE FROM audit_log WHERE id = %s", (victim.id,))
        successor.invalidate_recordset(['previous_hash'])
        self.assertNotEqual(
            successor.previous_hash, predecessor.hash,
            "deleting an intermediate log must break the chain link",
        )
