const fs = require('fs');
const path = require('path');
const vm = require('vm');

const Packet = require('../packet');

const test = require('tap').test;

const fixtureDir = path.join(__dirname, 'fixtures');

const files = fs.readdirSync(fixtureDir).filter(function(f) {
  return /\.js$/.test(f);
});

files.forEach(function(file) {
  test('can parse ' + file, function(t) {
    let js = 'foo = ' + fs.readFileSync(path.join(fixtureDir, file), 'utf8');
    js = vm.runInThisContext(js, file);
    const buff = new Buffer(4096);
    const written = Packet.write(buff, js);
    const binFile = path.join(fixtureDir, file.replace(/\.js$/, '.bin'));
    const bin = fs.readFileSync(binFile);
    const rtrip = Packet.parse(buff.slice(0, written));
    t.equivalent(written, bin.length, null, { testMsgLen: file });
    t.equivalent(buff.slice(0, written), bin, null, { testBin: file });
    t.equivalent(rtrip, js, null, { testObj: file });
    t.end();
  });
});
