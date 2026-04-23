// Phase 11 cross-file factory caller: taints an environment variable,
// stores it into a container produced by a cross-file factory helper,
// and sinks a subsequent read of the container through `exec`.
const factory = require('./factory.js');
const child_process = require('child_process');

function run() {
    const bag = factory.makeBag();
    factory.fillBag(bag, process.env.INPUT);
    child_process.exec(bag[0]); // VULN: tainted env value flows through cross-file factory
}

module.exports = { run };
