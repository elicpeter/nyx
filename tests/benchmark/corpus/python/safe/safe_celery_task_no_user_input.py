"""py-auth-realrepo-003: Celery `@app.task` with no parameters.

`handle_promotion_toggle()` is invoked by the Celery scheduler — it
takes no arguments and reads no request-shaped state.  The
`Promotion.objects.filter(id__in=promotion_ids)` call has an
id-shaped subject (`promotion_ids` ends with `ids`) but the entire
unit is backend computation: there is no caller-supplied identifier,
no request parameter, no session.  The ownership-gap rule must not
fire.
"""

from saleor.celeryconf import app


@app.task
def handle_promotion_toggle():
    promotions = Promotion.objects.filter(active=True).all()
    promotion_ids = [p.id for p in promotions]
    Promotion.objects.filter(id__in=promotion_ids).update(notified=True)
