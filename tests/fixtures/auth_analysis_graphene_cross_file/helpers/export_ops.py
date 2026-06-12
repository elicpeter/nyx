"""Private helper reached only from the PUBLIC `PublicExport` mutation
(graphene cross-file caller-scope — recall side).

No caller is authorized (the public mutation declares no
`Meta.permissions`), so the cross-file lift is refused and
`missing_ownership_check` must still fire on the id-targeted ORM write.
"""
from report import models


def export_report_rows(report_id):
    return models.Report.objects.filter(pk=report_id).update(exported=True)
