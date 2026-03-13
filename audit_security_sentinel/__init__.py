# -*- coding: utf-8 -*-

from . import models
from . import wizard


def post_load():
    """Called every time Odoo loads the module (startup + upgrade).

    Installs the monkey-patch on BaseModel.create/write/unlink so that
    audit logging is active from the very first request.
    """
    from .models.audit_hook import install_audit_hooks
    install_audit_hooks()


def uninstall_hook(env):
    """Clean up when the module is uninstalled.

    1. Restores the original BaseModel.create/write/unlink methods.
    2. Removes the hash salt from system parameters (it would be invalid anyway).
    3. Clears the in-memory salt cache.

    Note: audit.log and audit.rule records are NOT deleted on uninstall —
    they remain in the database as a permanent compliance record.
    """
    from .models.audit_hook import remove_audit_hooks, invalidate_salt_cache

    # Restore original ORM methods
    remove_audit_hooks()

    # Remove module system parameters
    ICP = env['ir.config_parameter'].sudo()
    for param_key in [
        'audit_security_sentinel.hash_salt',
        'audit_sentinel.last_integrity_check',
        'audit_sentinel.last_tampered_count',
    ]:
        ICP.set_param(param_key, '')

    # Clear in-memory salt cache
    invalidate_salt_cache()
