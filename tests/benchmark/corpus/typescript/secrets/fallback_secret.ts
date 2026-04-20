interface Config { sessionSecret: string }

export function loadConfig(): Config {
    return {
        sessionSecret: process.env.SESSION_SECRET || 'dev-fallback-super-secret-key',
    };
}
