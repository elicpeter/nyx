var userInput = document.location;

// Dangerous: href attribute — should fire
var a = document.createElement('a');
a.setAttribute("href", userInput);

// Dangerous: on* prefix — should fire
var div = document.createElement('div');
div.setAttribute("onclick", userInput);

// Safe: class attribute — should NOT fire
var span = document.createElement('span');
span.setAttribute("class", userInput);

// Safe: data-* attribute — should NOT fire
var p = document.createElement('p');
p.setAttribute("data-name", userInput);

// Dynamic: unknown attribute — should fire (conservative)
var el = document.createElement('div');
var attrName = "href";
el.setAttribute(attrName, userInput);

// Payload-arg filtering: dangerous attr + safe (constant) payload — should NOT fire
var el2 = document.createElement('a');
el2.setAttribute("href", "https://example.com");
