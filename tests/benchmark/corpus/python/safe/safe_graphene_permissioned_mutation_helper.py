"""Precision guard for the graphene `Meta.permissions` auth recogniser.

Distilled from saleor `graphql/order/mutations/order_cancel.py:34` +
`graphql/order/mutations/utils.py`: a graphene-django mutation declares
class-level RBAC via `class Meta: permissions = (OrderPermissions.MANAGE_ORDERS,)`
and implements the action in a `perform_mutation` classmethod that
delegates the id-targeted ORM write to a private helper.

graphene's metaclass enforces `Meta.permissions` before dispatching to
`perform_mutation`, so the action method and every helper it calls run
under an authenticated, RBAC-authorized actor.  The
`GrapheneExtractor` (`src/auth_analysis/extract/graphene.rs`) marks
`perform_mutation` a `RouteHandler` with a route-level `Other` check, and
the in-file caller-scope pass (`apply_caller_scope_propagation`) lifts
that check onto `_cancel_order_rows`.  Both `missing_ownership_check` and
`token_override_without_validation` must therefore be suppressed.
"""
import graphene

from .types import Order
from ....order import models
from ....permission.enums import OrderPermissions


def _cancel_order_rows(order_id):
    # Reached only from the permissioned `perform_mutation` below; the
    # caller's RBAC gate authorizes this id-targeted write.
    return models.Order.objects.filter(pk=order_id).update(status="canceled")


class OrderCancel(graphene.Mutation):
    order = graphene.Field(Order)

    class Arguments:
        id = graphene.ID(required=True)

    class Meta:
        description = "Cancel an order."
        permissions = (OrderPermissions.MANAGE_ORDERS,)

    @classmethod
    def perform_mutation(cls, _root, info, /, *, id):
        return _cancel_order_rows(id)
