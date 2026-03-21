async function healthCheck(): Promise<string> {
    const response = await fetch("https://api.example.com/health");
    return response.text();
}
