"""Public graphene mutation (graphene cross-file caller-scope — recall side).

Same delegation shape as `order_cancel.py`, but declares NO
`Meta.permissions` — a public mutation.  The `GrapheneExtractor` must NOT
mark `perform_mutation` authorized, so `export_report_rows` in
`helpers/export_ops.py` has no authorized caller edge, the cross-file
lift is refused, and `missing_ownership_check` must still fire on its
id-targeted ORM write.
"""
import graphene

from helpers.export_ops import export_report_rows


class PublicExport(graphene.Mutation):
    class Arguments:
        report_id = graphene.ID(required=True)

    class Meta:
        description = "Export a report (no permissions)."

    @classmethod
    def perform_mutation(cls, _root, info, /, *, report_id):
        return export_report_rows(report_id)
