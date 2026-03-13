# -*- coding: utf-8 -*-

from odoo.exceptions import UserError
from odoo.tests.common import TransactionCase


class TestAuditLogImmutability(TransactionCase):
    """Test that audit.log records cannot be modified or deleted.

    The audit.log model enforces immutability by overriding write() and
    unlink() to always raise UserError, regardless of access rights or
    sudo context.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.audit_user = cls.env['res.users'].create({
            'name': 'Test Audit User',
            'login': 'test_audit_user@test.com',
            'groups_id': [(4, cls.env.ref('audit_security_sentinel.group_audit_user').id)],
        })
        cls.audit_manager = cls.env['res.users'].create({
            'name': 'Test Compliance Officer',
            'login': 'test_compliance@test.com',
            'groups_id': [(4, cls.env.ref('audit_security_sentinel.group_audit_manager').id)],
        })

    def _create_test_log(self):
        """Helper: create a minimal audit.log record via sudo to bypass ACL."""
        return self.env['audit.log'].sudo().create({
            'user_id': self.env.uid,
            'model_model': 'res.partner',
            'res_id': 1,
            'action_type': 'write',
            'name': 'Test Partner',
            'details': '{"action": "write", "changes": {}}',
            'hash': 'testhash123',
        })

    def test_write_raises_user_error(self):
        """audit.log.write() must raise UserError (immutability)."""
        log = self._create_test_log()
        with self.assertRaises(UserError):
            log.write({'name': 'Changed'})

    def test_write_raises_even_with_sudo(self):
        """audit.log.write() must raise UserError even with sudo."""
        log = self._create_test_log()
        with self.assertRaises(UserError):
            log.sudo().write({'name': 'Changed via sudo'})

    def test_unlink_raises_user_error(self):
        """audit.log.unlink() must raise UserError (immutability)."""
        log = self._create_test_log()
        with self.assertRaises(UserError):
            log.unlink()

    def test_unlink_raises_even_with_sudo(self):
        """audit.log.unlink() must raise UserError even with sudo."""
        log = self._create_test_log()
        with self.assertRaises(UserError):
            log.sudo().unlink()

    def test_create_sets_required_fields(self):
        """Creating an audit.log must succeed and populate all required fields."""
        log = self._create_test_log()
        self.assertTrue(log.id, "Log must be created with a valid ID")
        self.assertEqual(log.model_model, 'res.partner')
        self.assertEqual(log.action_type, 'write')
        self.assertEqual(log.user_id.id, self.env.uid)
        self.assertTrue(log.name, "Name field must be set")

    def test_create_populates_create_date(self):
        """audit.log.create_date must be auto-populated by the ORM."""
        log = self._create_test_log()
        self.assertTrue(log.create_date, "create_date must be auto-populated")

    def test_audit_user_can_read(self):
        """Users with group_audit_user can read audit logs."""
        log = self._create_test_log()
        logs = self.env['audit.log'].with_user(self.audit_user).search(
            [('id', '=', log.id)]
        )
        self.assertEqual(len(logs), 1)

    def test_audit_user_cannot_create(self):
        """Users with group_audit_user cannot create audit logs (ACL perm_create=0)."""
        from odoo.exceptions import AccessError
        with self.assertRaises(AccessError):
            self.env['audit.log'].with_user(self.audit_user).create({
                'user_id': self.audit_user.id,
                'model_model': 'res.partner',
                'res_id': 1,
                'action_type': 'create',
                'name': 'ACL Bypass Test',
                'details': '{}',
                'hash': 'x',
            })

    def test_audit_user_cannot_write(self):
        """Users with group_audit_user cannot write audit logs."""
        log = self._create_test_log()
        # The model-level write() override raises UserError before ACL check
        with self.assertRaises(UserError):
            log.with_user(self.audit_user).write({'name': 'Hacked'})

    def test_manager_cannot_write(self):
        """Even Compliance Officers cannot modify audit logs."""
        log = self._create_test_log()
        with self.assertRaises(UserError):
            log.with_user(self.audit_manager).write({'name': 'Manager Override'})

    def test_manager_cannot_unlink(self):
        """Even Compliance Officers cannot delete audit logs."""
        log = self._create_test_log()
        with self.assertRaises(UserError):
            log.with_user(self.audit_manager).unlink()

    def test_recompute_hash_method_exists(self):
        """The _recompute_hash() method must exist and return a 64-char hex string."""
        log = self._create_test_log()
        # Set a proper hash via raw SQL so _recompute_hash can work
        self.env.cr.execute(
            "UPDATE audit_log SET hash = 'placeholder' WHERE id = %s",
            (log.id,),
        )
        log.invalidate_recordset(['hash'])
        result = log._recompute_hash()
        self.assertIsInstance(result, str)
        self.assertEqual(len(result), 64, "SHA-256 hex digest must be 64 chars")
