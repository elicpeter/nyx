import { exec } from 'child_process';

class ApiController {
    // @Injectable and @Get are NestJS routing/DI decorators — NOT auth markers.
    @Injectable()
    @Get("/run")
    handle_request(req: any) {
        exec("ls /tmp");
    }
}
