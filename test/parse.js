const fs = require('fs');
const path = require('path');
const vm = require('vm');

const Packet = require('../packet');

const test = require('tap').test;

const fixtureDir = path.join(__dirname, 'fixtures');

const files = fs.readdirSync(fixtureDir).filter(function(f) {
  return /\.bin$/.test(f);
});

files.forEach(function(file) {
  test('can parse ' + file, function(t) {
    const bin = fs.readFileSync(path.join(fixtureDir, file));
    const jsFile = path.join(fixtureDir, file.replace(/\.bin$/, '.js'));
    let js = 'foo = ' + fs.readFileSync(jsFile, 'utf8');
    js = vm.runInThisContext(js, jsFile);
    const ret = Packet.parse(bin);
    t.equivalent(ret, js);
    t.end();
  });
});
