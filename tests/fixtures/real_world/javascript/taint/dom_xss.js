var params = new URLSearchParams(location.search);
var input = params.get('name');

document.write('<h1>Hello ' + input + '</h1>');

var clean = DOMPurify.sanitize(input);
document.write('<h1>Hello ' + clean + '</h1>');
