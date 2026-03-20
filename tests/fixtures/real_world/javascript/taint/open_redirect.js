var hash = location.hash.substring(1);

location.assign(hash);

var encoded = encodeURIComponent(hash);
location.assign(encoded);
