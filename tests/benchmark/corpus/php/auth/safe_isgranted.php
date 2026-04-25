<?php
// php-isgranted-001: Symfony `#[IsGranted("ROLE_USER")]` attribute gates
// the controller method.  Auth analysis must recognise the attribute as
// an authentication guard so neither `cfg-auth-gap` nor
// `state-unauthed-access` fires on the privileged FILE_IO sink.
use Symfony\Component\Security\Http\Attribute\IsGranted;
use Symfony\Component\HttpFoundation\Request;

class DownloadController {
    #[IsGranted("ROLE_USER")]
    public function handle(Request $request): string {
        $name = $request->query->get("file");
        if (str_contains($name, "..") || str_starts_with($name, "/") || str_starts_with($name, "\\")) {
            return "denied";
        }
        return file_get_contents("/var/data/" . $name);
    }
}
