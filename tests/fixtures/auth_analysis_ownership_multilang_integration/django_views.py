from django.urls import path


class ProjectStore:
    def fetch(self, project_id):
        return project_id


project_store = ProjectStore()


def load_project(request, project_id):
    return project_store.fetch(project_id)


urlpatterns = [
    path("projects/<int:project_id>/", load_project),
]
