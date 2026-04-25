@RestController
@RequestMapping("/admin/projects")
class AdminProjectsController {
    @PostMapping("/publish")
    @PreAuthorize("isAuthenticated()")
    public void publishProject() {
        adminAuditService.publish();
    }
}
