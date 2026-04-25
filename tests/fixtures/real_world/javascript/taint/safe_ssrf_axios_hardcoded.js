var axios = require('axios');

function fetchData() {
    axios("https://api.example.com/data").then(function(response) {
        console.log(response.data);
    });
}
