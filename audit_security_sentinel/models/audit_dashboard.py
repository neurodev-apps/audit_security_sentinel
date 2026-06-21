# -*- coding: utf-8 -*-

import logging

from odoo import api, fields, models, _
from odoo.exceptions import AccessError

_logger = logging.getLogger(__name__)


class AuditLogDashboard(models.Model):
    _inherit = 'audit.log'

    @api.model
    def get_dashboard_data(self, date_from=False, date_to=False):
        """Return all dashboard KPIs in a single RPC call.

        Uses raw SQL with aggregation to minimize database round-trips.
        Replaces the previous approach of 5+ separate ORM calls from the
        frontend OWL component.

        :param date_from: Optional start date string 'YYYY-MM-DD HH:MM:SS'.
                          Defaults to today at 00:00:00.
        :param date_to:   Optional end date string 'YYYY-MM-DD HH:MM:SS'.
                          Defaults to now.
        :return: dict with all dashboard data.
        """
        # ---- Access control ----
        if not self.env.user.has_group('audit_security_sentinel.group_audit_user'):
            raise AccessError(_('Access denied. Audit User group required.'))

        # ---- Default date range: today ----
        if not date_from:
            today = fields.Date.context_today(self)
            date_from = '%s 00:00:00' % today
        if not date_to:
            date_to = fields.Datetime.to_string(fields.Datetime.now())

        params = {'date_from': date_from, 'date_to': date_to}

        # ---- Company filter: Compliance Officers see all companies ----
        is_manager = self.env.user.has_group('audit_security_sentinel.group_audit_manager')
        if is_manager:
            # No restriction — Compliance Officers have cross-company visibility
            co_filter = ""
            co_filter_al = ""
            company_domain = []
        else:
            accessible = self.env.user.company_ids.ids or [self.env.company.id]
            params['company_ids'] = accessible
            co_filter = "AND (company_id IS NULL OR company_id = ANY(%(company_ids)s))"
            co_filter_al = "AND (al.company_id IS NULL OR al.company_id = ANY(%(company_ids)s))"
            company_domain = ['|', ('company_id', '=', False), ('company_id', 'in', accessible)]

        # ---- 1. Totals + breakdown by action_type (single query) ----
        self.env.cr.execute("""
            SELECT
                COUNT(*)                                           AS total_logs,
                COUNT(*) FILTER (WHERE action_type = 'create')     AS creates,
                COUNT(*) FILTER (WHERE action_type = 'write')      AS writes,
                COUNT(*) FILTER (WHERE action_type = 'unlink')     AS deletes
            FROM audit_log
            WHERE create_date >= %(date_from)s
              AND create_date <= %(date_to)s
              """ + co_filter, params)
        row = self.env.cr.dictfetchone()
        total_logs = row['total_logs'] or 0
        creates = row['creates'] or 0
        writes = row['writes'] or 0
        deletes = row['deletes'] or 0

        # ---- 2. Unique users ----
        self.env.cr.execute("""
            SELECT COUNT(DISTINCT user_id) AS unique_users
            FROM audit_log
            WHERE create_date >= %(date_from)s
              AND create_date <= %(date_to)s
              """ + co_filter, params)
        unique_users = self.env.cr.dictfetchone()['unique_users'] or 0

        # ---- 3. Activity by hour ----
        self.env.cr.execute("""
            SELECT
                date_trunc('hour', create_date) AS hour,
                COUNT(*)                        AS count
            FROM audit_log
            WHERE create_date >= %(date_from)s
              AND create_date <= %(date_to)s
              """ + co_filter + """
            GROUP BY date_trunc('hour', create_date)
            ORDER BY hour
        """, params)
        activity_by_hour = [
            {
                'hour': fields.Datetime.to_string(r['hour']),
                'count': r['count'],
            }
            for r in self.env.cr.dictfetchall()
        ]

        # ---- 4. Top 10 models ----
        self.env.cr.execute("""
            SELECT
                model_model AS model,
                COUNT(*)    AS count
            FROM audit_log
            WHERE create_date >= %(date_from)s
              AND create_date <= %(date_to)s
              """ + co_filter + """
            GROUP BY model_model
            ORDER BY count DESC
            LIMIT 10
        """, params)
        top_models = [
            {'model': r['model'], 'count': r['count']}
            for r in self.env.cr.dictfetchall()
        ]

        # ---- 5. Top 10 users ----
        self.env.cr.execute("""
            SELECT
                al.user_id   AS user_id,
                rp.name      AS user_name,
                COUNT(*)     AS count
            FROM audit_log al
            JOIN res_users ru ON ru.id = al.user_id
            JOIN res_partner rp ON rp.id = ru.partner_id
            WHERE al.create_date >= %(date_from)s
              AND al.create_date <= %(date_to)s
              """ + co_filter_al + """
            GROUP BY al.user_id, rp.name
            ORDER BY count DESC
            LIMIT 10
        """, params)
        top_users = [
            {
                'user_id': r['user_id'],
                'user_name': r['user_name'],
                'count': r['count'],
            }
            for r in self.env.cr.dictfetchall()
        ]

        # ---- 6. Recent logs (ORM — company_domain enforces multi-company rules) ----
        recent_records = self.sudo().search(
            [
                ('create_date', '>=', date_from),
                ('create_date', '<=', date_to),
            ] + company_domain,
            order='create_date desc',
            limit=20,
        )
        recent_logs = []
        for rec in recent_records:
            recent_logs.append({
                'id': rec.id,
                'create_date': fields.Datetime.to_string(rec.create_date),
                'user_id': rec.user_id.id,
                'user_name': rec.user_id.name,
                'action_type': rec.action_type,
                'model_model': rec.model_model,
                'name': rec.name,
                'ip_address': rec.ip_address,
                # CR-07: only Compliance Officers receive change details.
                'details': rec.details if is_manager else False,
                'res_id': rec.res_id,
            })

        # ---- 7. Integrity status from system parameters ----
        ICP = self.env['ir.config_parameter'].sudo()
        last_integrity_check = ICP.get_param(
            'audit_sentinel.last_integrity_check', default=_('Never')
        )
        last_tampered_count = int(
            ICP.get_param('audit_sentinel.last_tampered_count', default='0')
        )

        # ---- 8. Active audit rules count ----
        total_rules = self.env['audit.rule'].sudo().search_count(
            [('active', '=', True)]
        )

        return {
            'total_logs': total_logs,
            'creates': creates,
            'writes': writes,
            'deletes': deletes,
            'unique_users': unique_users,
            'activity_by_hour': activity_by_hour,
            'top_models': top_models,
            'top_users': top_users,
            'recent_logs': recent_logs,
            'integrity_status': {
                'last_check': last_integrity_check,
                'tampered_count': last_tampered_count,
            },
            'total_rules': total_rules,
        }
