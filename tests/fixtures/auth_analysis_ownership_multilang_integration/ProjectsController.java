@RestController
@RequestMapping("/projects")
class ProjectsController {
    @GetMapping("/{projectId}")
    public Project showProject(String projectId) {
        return projectService.find(projectId);
    }
}
