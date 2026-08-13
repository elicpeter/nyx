"""Private helper reached only from the permissioned `OrderCancel`
mutation (graphene cross-file caller-scope — safe side).

Holds the id-targeted ORM write but has NO inline auth check and NO
in-file caller.  Phase 2 cross-file caller-scope IPA must lift the
mutation's route-level auth onto this helper, so
`missing_ownership_check` must NOT fire here.
"""
from order import models


def cancel_order_rows(order_id):
    return models.Order.objects.filter(pk=order_id).update(status="canceled")
