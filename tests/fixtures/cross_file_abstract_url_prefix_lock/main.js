const axios = require('axios');
const { asIs } = require('./helper');

function handler(userPath) {
    const url = asIs('https://internal.safe.example.com/api/' + userPath);
    return axios.get(url);
}
module.exports = { handler };
