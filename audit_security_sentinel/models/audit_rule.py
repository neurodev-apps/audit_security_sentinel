# -*- coding: utf-8 -*-

from odoo import api, fields, models, _
from odoo.exceptions import ValidationError


class AuditRule(models.Model):
    _name = 'audit.rule'
    _description = 'Audit Rule Configuration'
    _order = 'model_id'

    name = fields.Char(
        string='Rule Name',
        compute='_compute_name',
        store=True,
    )
    model_id = fields.Many2one(
        'ir.model',
        string='Model to Monitor',
        required=True,
        ondelete='cascade',
        index=True,
        domain=[
            ('transient', '=', False),
            ('model', 'not like', 'ir.%'),
            ('model', 'not like', 'bus.%'),
            ('model', 'not like', 'base.%'),
            ('model', '!=', 'audit.log'),
            ('model', '!=', 'audit.rule'),
        ],
        help='Select the model you want to audit. System and transient models are excluded.',
    )
    active = fields.Boolean(
        string='Active',
        default=True,
        help='If unchecked, this rule will not be applied.',
    )
    log_create = fields.Boolean(
        string='Log Creations',
        default=True,
        help='Log when new records are created.',
    )
    log_write = fields.Boolean(
        string='Log Updates',
        default=True,
        help='Log when records are modified.',
    )
    log_unlink = fields.Boolean(
        string='Log Deletions',
        default=True,
        help='Log when records are deleted.',
    )
    log_count = fields.Integer(
        string='Audit Logs',
        compute='_compute_log_count',
    )
    log_field_ids = fields.Many2many(
        'ir.model.fields',
        'audit_rule_field_rel',
        'rule_id',
        'field_id',
        string='Fields to Monitor',
        domain="[('model_id', '=', model_id), ('store', '=', True), ('ttype', 'not in', ['one2many', 'binary'])]",
        help='Select specific fields to monitor. Leave empty to monitor all stored fields.',
    )

    def init(self):
        """Create a partial unique index: only one active rule per model."""
        self.env.cr.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS audit_rule_unique_active_model
            ON audit_rule (model_id) WHERE active = true
        """)

    def _compute_log_count(self):
        for rule in self:
            if rule.model_id:
                rule.log_count = self.env['audit.log'].sudo().search_count(
                    [('model_model', '=', rule.model_id.model)]
                )
            else:
                rule.log_count = 0

    @api.depends('model_id', 'model_id.name')
    def _compute_name(self):
        for rule in self:
            if rule.model_id:
                rule.name = _('Audit Rule for %s') % rule.model_id.name
            else:
                rule.name = _('New Audit Rule')

    @api.constrains('model_id')
    def _check_model_not_audit(self):
        """Block rules for system, transient and audit models (MD-01).

        The view domain already hides these, but a rule can still be created
        via RPC or import; this constraint is the real backend guard.
        """
        forbidden_prefixes = ('ir.', 'base.', 'bus.', 'audit.')
        for rule in self:
            if not rule.model_id:
                continue
            model_name = rule.model_id.model
            model_obj = self.env.get(model_name)
            if (model_name.startswith(forbidden_prefixes)
                    or model_name in ('audit.log', 'audit.rule')
                    or (model_obj is not None and model_obj._transient)):
                raise ValidationError(_(
                    'Cannot create audit rules for system, transient or audit '
                    'models (%s).'
                ) % model_name)

    def action_open_audit_logs(self):
        """Open audit logs filtered by this rule's model."""
        self.ensure_one()
        return {
            'type': 'ir.actions.act_window',
            'name': _('Audit Logs - %s') % self.model_id.name,
            'res_model': 'audit.log',
            'view_mode': 'list,form',
            'domain': [('model_model', '=', self.model_id.model)],
            'context': {'search_default_model_model': self.model_id.model},
        }

    def get_monitored_fields(self):
        """Return list of field names to monitor, or empty list for all fields."""
        self.ensure_one()
        if self.log_field_ids:
            return self.log_field_ids.mapped('name')
        return []

    # -------------------------------------------------------------------------
    # Cache invalidation (MD-02) — rule changes must take effect immediately
    # -------------------------------------------------------------------------
    @api.model_create_multi
    def create(self, vals_list):
        rules = super().create(vals_list)
        self.env['base.model.audit.hook']._invalidate_rules_cache()
        return rules

    def write(self, vals):
        res = super().write(vals)
        self.env['base.model.audit.hook']._invalidate_rules_cache()
        return res

    def unlink(self):
        res = super().unlink()
        self.env['base.model.audit.hook']._invalidate_rules_cache()
        return res
