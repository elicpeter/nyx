from django.urls import path


class View:
    @classmethod
    def as_view(cls):
        return cls


class ProjectStore:
    def update_state(self, project_id, state):
        return None


project_store = ProjectStore()


class ProjectStateView(View):
    def post(self, request, project_id):
        project_store.update_state(project_id, request.POST["state"])
        return None


urlpatterns = [
    path("projects/<int:project_id>/state/", ProjectStateView.as_view()),
]
