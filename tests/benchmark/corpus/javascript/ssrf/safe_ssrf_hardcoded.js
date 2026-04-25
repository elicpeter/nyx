const axios = require('axios');

function fetchData() {
    axios("https://api.example.com/data").then(r => console.log(r.data));
}
