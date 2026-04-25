import md5 from 'md5';

export function fingerprint(input: string): string {
    return md5(input);
}
