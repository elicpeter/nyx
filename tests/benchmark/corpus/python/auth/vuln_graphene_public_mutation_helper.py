"""Recall counterpart to safe_graphene_permissioned_mutation_helper.py.

Same shape, but the mutation declares NO `Meta.permissions` — it is a
*public* graphene mutation.  Nothing authorizes the action, so the
`GrapheneExtractor` must NOT mark `perform_mutation` authorized, and the
in-file caller-scope pass must refuse to lift onto `_cancel_order_rows`.
`missing_ownership_check` must still fire on the helper's id-targeted
ORM write.

This pins the soundness gate: the recogniser fires only on a non-empty
`Meta.permissions` collection, so removing the permissions tuple (a
public mutation) preserves recall.
"""
import graphene

from .types import Order
from ....order import models


def _cancel_order_rows(order_id):
    return models.Order.objects.filter(pk=order_id).update(status="canceled")


class OrderCancel(graphene.Mutation):
    order = graphene.Field(Order)

    class Arguments:
        id = graphene.ID(required=True)

    class Meta:
        description = "Cancel an order."

    @classmethod
    def perform_mutation(cls, _root, info, /, *, id):
        return _cancel_order_rows(id)
