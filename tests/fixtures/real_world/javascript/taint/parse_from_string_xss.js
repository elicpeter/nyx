var userInput = document.location;
var parser = new DOMParser();

// Dangerous: text/html MIME type with tainted input — should fire
var doc1 = parser.parseFromString(userInput, "text/html");

// Safe: text/xml MIME type — should NOT fire
var doc2 = parser.parseFromString(userInput, "text/xml");

// Safe: application/xml MIME type — should NOT fire
var doc3 = parser.parseFromString(userInput, "application/xml");

// Dangerous: application/xhtml+xml — should fire
var doc4 = parser.parseFromString(userInput, "application/xhtml+xml");

// Dynamic: unknown MIME type — should fire (conservative)
var mimeType = "text/html";
var doc5 = parser.parseFromString(userInput, mimeType);

// Dangerous MIME but safe (constant) payload — should NOT fire
var doc6 = parser.parseFromString("<p>hello</p>", "text/html");
