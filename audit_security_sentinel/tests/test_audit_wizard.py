# -*- coding: utf-8 -*-

from datetime import timedelta

from odoo import fields
from odoo.exceptions import UserError, ValidationError
from odoo.tests.common import TransactionCase


class TestAuditReportWizard(TransactionCase):
    """Test the compliance report wizard.

    Verifies date range validation, action type filtering, and domain
    building logic of the audit.report.wizard transient model.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.today = fields.Date.context_today(cls.env['res.partner'])
        cls.first_of_month = cls.today.replace(day=1)

    def _make_wizard(self, date_from=None, date_to=None, **kwargs):
        """Helper: create an audit.report.wizard with sensible defaults."""
        vals = {
            'date_from': date_from or self.first_of_month,
            'date_to': date_to or self.today,
        }
        vals.update(kwargs)
        return self.env['audit.report.wizard'].create(vals)

    def test_wizard_date_range_valid(self):
        """A wizard with date_from <= date_to must be created without error."""
        wizard = self._make_wizard()
        self.assertTrue(wizard.id)
        self.assertEqual(wizard.date_from, self.first_of_month)
        self.assertEqual(wizard.date_to, self.today)

    def test_wizard_same_dates(self):
        """A wizard with date_from == date_to must be valid (single day report)."""
        wizard = self._make_wizard(date_from=self.today, date_to=self.today)
        self.assertTrue(wizard.id)

    def test_wizard_date_range_invalid(self):
        """A wizard with date_from > date_to must raise ValidationError."""
        tomorrow = self.today + timedelta(days=1)
        with self.assertRaises(ValidationError):
            self._make_wizard(date_from=tomorrow, date_to=self.today)

    def test_wizard_no_action_type_raises(self):
        """Generating a report with no action type selected must raise UserError."""
        wizard = self._make_wizard()
        # Deselect all action types — must bypass the write() immutability
        # of audit.log. The wizard itself is a TransientModel, so write works.
        wizard.write({
            'include_creates': False,
            'include_writes': False,
            'include_deletes': False,
        })
        with self.assertRaises(UserError):
            wizard._build_domain()

    def test_wizard_all_action_types(self):
        """With all action types selected, the domain must NOT filter by action_type."""
        wizard = self._make_wizard()
        domain = wizard._build_domain()
        # When all 3 are selected, no action_type filter is appended
        action_type_filters = [d for d in domain if d[0] == 'action_type']
        self.assertEqual(
            len(action_type_filters), 0,
            "When all action types are included, no action_type filter should exist",
        )

    def test_wizard_single_action_type(self):
        """Selecting only 'creates' must add an action_type filter."""
        wizard = self._make_wizard(
            include_creates=True,
            include_writes=False,
            include_deletes=False,
        )
        domain = wizard._build_domain()
        action_type_filters = [d for d in domain if d[0] == 'action_type']
        self.assertEqual(len(action_type_filters), 1)
        self.assertEqual(action_type_filters[0][2], ['create'])

    def test_wizard_two_action_types(self):
        """Selecting two action types must filter with 'in' operator."""
        wizard = self._make_wizard(
            include_creates=True,
            include_writes=True,
            include_deletes=False,
        )
        domain = wizard._build_domain()
        action_type_filters = [d for d in domain if d[0] == 'action_type']
        self.assertEqual(len(action_type_filters), 1)
        self.assertIn('create', action_type_filters[0][2])
        self.assertIn('write', action_type_filters[0][2])

    def test_wizard_domain_date_boundaries(self):
        """The domain must include create_date >= date_from and <= date_to + 1 day."""
        wizard = self._make_wizard()
        domain = wizard._build_domain()
        date_filters = [d for d in domain if d[0] == 'create_date']
        self.assertEqual(
            len(date_filters), 2,
            "Domain must have exactly two create_date conditions",
        )

    def test_wizard_default_export_format(self):
        """Default export format must be 'xlsx'."""
        wizard = self._make_wizard()
        self.assertEqual(wizard.export_format, 'xlsx')

    def test_wizard_defaults_include_all_actions(self):
        """By default, all three action types must be included."""
        wizard = self._make_wizard()
        self.assertTrue(wizard.include_creates)
        self.assertTrue(wizard.include_writes)
        self.assertTrue(wizard.include_deletes)
