function checkHealth() {
    fetch('https://api.example.com/health').then(function(r) {
        console.log(r.status);
    });
}
