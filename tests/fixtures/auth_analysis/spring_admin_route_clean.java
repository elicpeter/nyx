@RestController
@RequestMapping("/admin/projects")
class SecureAdminProjectsController {
    @PostMapping("/publish")
    @PreAuthorize("hasRole('ADMIN')")
    public void publishProject() {
        adminAuditService.publish();
    }
}
