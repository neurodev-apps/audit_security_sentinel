# -*- coding: utf-8 -*-

from odoo.tests.common import TransactionCase


class TestAuditHook(TransactionCase):
    """Test that create/write/unlink monkey-patches log correctly.

    These tests create an audit.rule for res.partner and verify that
    CRUD operations on res.partner produce the expected audit.log entries
    with valid SHA-256 hashes.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # Create an audit rule monitoring res.partner
        partner_model = cls.env['ir.model'].search(
            [('model', '=', 'res.partner')], limit=1
        )
        cls.audit_rule = cls.env['audit.rule'].sudo().create({
            'name': 'Test Partner Audit Rule',
            'model_id': partner_model.id,
            'log_create': True,
            'log_write': True,
            'log_unlink': True,
        })
        # Invalidate the audit hook cache so the new rule is picked up
        hook = cls.env['base.model.audit.hook']
        hook._audit_rules_cache.clear()
        hook._audit_cache_timestamps.clear()

    def _get_audit_logs(self, model_model, res_id, action_type=None):
        """Helper: search audit.log for entries matching model, res_id, and optionally action_type."""
        domain = [
            ('model_model', '=', model_model),
            ('res_id', '=', res_id),
        ]
        if action_type:
            domain.append(('action_type', '=', action_type))
        return self.env['audit.log'].sudo().search(domain)

    def test_create_is_logged(self):
        """Creating a res.partner with an active audit rule creates an audit log."""
        partner = self.env['res.partner'].create({'name': 'Audit Test Partner'})
        logs = self._get_audit_logs('res.partner', partner.id, 'create')
        self.assertTrue(
            len(logs) >= 1,
            "At least one 'create' log must be created for a monitored model",
        )

    def test_create_log_contains_name(self):
        """The create audit log must contain the resource name."""
        partner = self.env['res.partner'].create({'name': 'Named Partner Test'})
        logs = self._get_audit_logs('res.partner', partner.id, 'create')
        self.assertTrue(logs, "Must have at least one create log")
        self.assertTrue(logs[0].name, "Audit log name field must not be empty")

    def test_write_is_logged(self):
        """Writing to a monitored res.partner creates a 'write' audit log."""
        partner = self.env['res.partner'].create({'name': 'Write Test Partner'})
        log_count_before = len(
            self._get_audit_logs('res.partner', partner.id, 'write')
        )
        partner.write({'name': 'Write Test Partner Updated'})
        log_count_after = len(
            self._get_audit_logs('res.partner', partner.id, 'write')
        )
        self.assertGreater(
            log_count_after, log_count_before,
            "A 'write' log must be created when a monitored field changes",
        )

    def test_write_no_change_no_log(self):
        """Writing the same value should not create a write log (no actual change)."""
        partner = self.env['res.partner'].create({'name': 'Same Value Partner'})
        log_count_before = len(
            self._get_audit_logs('res.partner', partner.id, 'write')
        )
        # Write the exact same name value
        partner.write({'name': 'Same Value Partner'})
        log_count_after = len(
            self._get_audit_logs('res.partner', partner.id, 'write')
        )
        self.assertEqual(
            log_count_after, log_count_before,
            "Writing the same value should NOT produce a write log",
        )

    def test_unlink_is_logged(self):
        """Deleting a monitored res.partner creates an 'unlink' audit log."""
        partner = self.env['res.partner'].create({'name': 'Delete Test Partner'})
        partner_id = partner.id
        partner.unlink()
        logs = self._get_audit_logs('res.partner', partner_id, 'unlink')
        self.assertTrue(
            len(logs) >= 1,
            "At least one 'unlink' log must be created on deletion",
        )

    def test_hash_is_set(self):
        """Each audit log must have a non-empty SHA-256 hash (64 hex chars)."""
        partner = self.env['res.partner'].create({'name': 'Hash Test Partner'})
        logs = self._get_audit_logs('res.partner', partner.id, 'create')
        self.assertTrue(logs, "Must have at least one create log")
        for log in logs:
            self.assertTrue(log.hash, "Audit log hash must not be empty")
            self.assertEqual(
                len(log.hash), 64,
                "SHA-256 hex digest must be exactly 64 characters",
            )

    def test_hash_integrity_verification(self):
        """Recomputing hash on an untampered log must match the stored hash."""
        partner = self.env['res.partner'].create({'name': 'Integrity Test Partner'})
        logs = self._get_audit_logs('res.partner', partner.id, 'create')
        self.assertTrue(logs, "Must have at least one log")
        log = logs[0]
        recomputed = log._recompute_hash()
        self.assertEqual(
            log.hash, recomputed,
            "Stored hash must match recomputed hash for an untampered record",
        )

    def test_hash_detects_tampering(self):
        """Tampering with audit log data must cause hash verification to fail."""
        partner = self.env['res.partner'].create({'name': 'Tamper Test Partner'})
        logs = self._get_audit_logs('res.partner', partner.id, 'create')
        self.assertTrue(logs, "Must have at least one log")
        log = logs[0]
        original_hash = log.hash
        # Tamper with the details field via raw SQL (bypass immutability)
        self.env.cr.execute(
            "UPDATE audit_log SET details = %s WHERE id = %s",
            ('{"tampered": true}', log.id),
        )
        log.invalidate_recordset(['details'])
        recomputed = log._recompute_hash()
        self.assertNotEqual(
            original_hash, recomputed,
            "Hash must differ after tampering with the details field",
        )

    def test_audit_log_not_logged_recursively(self):
        """Creating an audit.log must NOT trigger another audit.log (no infinite recursion)."""
        initial_count = self.env['audit.log'].sudo().search_count([
            ('model_model', '=', 'audit.log'),
        ])
        # Create a test log directly
        self.env['audit.log'].sudo().create({
            'user_id': self.env.uid,
            'model_model': 'res.partner',
            'res_id': 999,
            'action_type': 'create',
            'name': 'Recursion Test',
            'details': '{}',
            'hash': 'x',
        })
        after_count = self.env['audit.log'].sudo().search_count([
            ('model_model', '=', 'audit.log'),
        ])
        self.assertEqual(
            initial_count, after_count,
            "Creating audit.log must NOT recursively create more audit logs",
        )

    def test_audit_rule_not_logged(self):
        """CRUD on audit.rule must NOT produce audit logs (excluded from hooks)."""
        initial_count = self.env['audit.log'].sudo().search_count([
            ('model_model', '=', 'audit.rule'),
        ])
        model = self.env['ir.model'].search(
            [('model', '=', 'res.users')], limit=1
        )
        rule = self.env['audit.rule'].sudo().create({
            'model_id': model.id,
            'log_create': True,
            'log_write': True,
            'log_unlink': True,
        })
        rule.sudo().unlink()
        after_count = self.env['audit.log'].sudo().search_count([
            ('model_model', '=', 'audit.rule'),
        ])
        self.assertEqual(
            initial_count, after_count,
            "audit.rule CRUD must be excluded from audit logging",
        )

    def test_disabled_rule_does_not_log(self):
        """Deactivating an audit rule must stop logging for that model."""
        # Deactivate the rule
        self.audit_rule.sudo().write({'active': False})
        # Clear cache so the deactivation takes effect
        hook = self.env['base.model.audit.hook']
        hook._audit_rules_cache.clear()
        hook._audit_cache_timestamps.clear()

        partner = self.env['res.partner'].create({'name': 'No Log Partner'})
        logs = self._get_audit_logs('res.partner', partner.id, 'create')
        self.assertEqual(
            len(logs), 0,
            "Deactivated audit rule must not produce audit logs",
        )

        # Reactivate for subsequent tests
        self.audit_rule.sudo().write({'active': True})
        hook._audit_rules_cache.clear()
        hook._audit_cache_timestamps.clear()

    def test_log_details_is_valid_json(self):
        """The details field of an audit log must contain valid JSON."""
        import json
        partner = self.env['res.partner'].create({'name': 'JSON Test Partner'})
        logs = self._get_audit_logs('res.partner', partner.id, 'create')
        self.assertTrue(logs, "Must have at least one log")
        for log in logs:
            if log.details:
                try:
                    parsed = json.loads(log.details)
                except (json.JSONDecodeError, TypeError):
                    self.fail("audit.log details must be valid JSON")
                self.assertIn(
                    'action', parsed,
                    "Parsed details must contain an 'action' key",
                )
