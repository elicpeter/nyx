import { exec } from 'child_process';

class ApiController {
    @UseGuards(AuthGuard)
    handle_request(req: any) {
        exec("ls /tmp");
    }
}
