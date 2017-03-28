'use strict';
var auth     = require('./lib/auth');
var crypto   = require('lib_crypto');

setTimeout(
  () => {
    console.error('timeout after 30 sec.');
    process.exit(1);
  }, 30000
);

console.info('generating key');
let ks = crypto.KeyStore.generate(2048);
console.info('generating key done');
let ts = new Map();

console.log('keystore ok');

let cia = new auth.CentralInstanceAuthentication(ks, ts);
let sia = new auth.SRBInstanceAuthentication(ks, ts);
let sa  = new auth.ServerAuthentication(ks, ts);
let tests = [];

tests.push(
  cia.issueToken(
    'someSRBInstanceOrClient',
    {isAdmin: true, dummy: true}
  )
);
tests.push(
  sia.issueToken(
    'central',
    {isAdmin: true, dummy: true}
  )
);
tests.push(
  sa.issueToken(
    'central',
    {isAdmin: true, dummy: true}
  )
);
tests.push(
  new Promise(
    (resolve, reject) => {
      sa.issueToken(
        'central',
        {isAdmin: true, dummy: true},
        [],
        '20s',
        'someType'
      ).then(
        token => {
          if (
            (sa.extractIssuer(token) !== ks.publicFingerprint) ||
            (sa.extractTokenType(token) !== 'someType')
          ) {
            reject(new Error('invalid issuer or tokentype'));
            return;
          }
          resolve();
        }
      ).catch(
        err => {
          reject(err);
        }
      )
    }
  )
);
tests.push(
  new Promise(
    (resolve, reject) => {
      sa.issueToken(
        'central',
        {isAdmin: true, dummy: true},
        [],
        '20s',
        'someType'
      ).then(
        token => {
          let v;
          try {
            v = sa.verifyToken(
              token,
              ks.publicFingerprint
            );
          } catch (err) {
            reject(err);
          }
          console.log(token, v);
          if (!v) {
            reject(new Error('invalid token'));
            return;
          }
          resolve();
        }
      ).catch(
        err => {
          reject(err);
        }
      )
    }
  )
);

Promise.all(tests).then(
  () => {
    process.exit(0);
  }
).catch(
  err=> {
    console.error(err);
    process.exit(1);
  }
);
