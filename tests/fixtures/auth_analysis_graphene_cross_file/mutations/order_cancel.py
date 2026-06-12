"""Permissioned graphene mutation (graphene cross-file caller-scope — safe side).

Distilled from saleor `graphql/order/mutations/order_cancel.py` +
`graphql/order/mutations/utils.py`.  `OrderCancel` declares class-level
RBAC via `class Meta: permissions = (...)` and implements the action in a
`perform_mutation` classmethod that delegates the id-targeted ORM write to
the private helper `cancel_order_rows` defined in `helpers/order_ops.py`
(a DIFFERENT file).

The `GrapheneExtractor` marks `perform_mutation` a RouteHandler with a
route-level `Other` (+ token) check; pass-1 caller-scope harvest records
that every caller of `cancel_order_rows` across the index is authorized;
pass-2 `apply_cross_file_caller_scope` lifts the checks onto the helper,
so `missing_ownership_check` / `token_override_without_validation` must
NOT fire in `helpers/order_ops.py`.
"""
import graphene

from helpers.order_ops import cancel_order_rows


class OrderCancel(graphene.Mutation):
    class Arguments:
        id = graphene.ID(required=True)

    class Meta:
        description = "Cancel an order."
        permissions = (OrderPermissions.MANAGE_ORDERS,)

    @classmethod
    def perform_mutation(cls, _root, info, /, *, id):
        return cancel_order_rows(id)
