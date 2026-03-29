from django.urls import path


class ProjectStore:
    def archive(self, ids):
        return None


project_store = ProjectStore()


def check_membership(user_id, project_id):
    return True


def bulk_archive(request):
    ids = request.POST["ids"]
    check_membership(request.user.id, ids[0])
    project_store.archive(ids)
    return None


urlpatterns = [
    path("projects/archive/", bulk_archive),
]
