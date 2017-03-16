const AWS = require('aws-sdk');
const async = require('async');
const encoder = require('./encoder');

AWS.config.credentials = new AWS.ECSCredentials({
  httpOptions: { timeout: 5000 }, // 5 second timeout
  maxRetries: 10, // retry 10 times
  retryDelayOptions: { base: 200 } // see AWS.Config for information
});

if (typeof process.env.AWS_DEFAULT_REGION !== 'undefined') {
  AWS.config.update({region: process.env.AWS_DEFAULT_REGION});
}

function decrypt(key, done) {
  var params = {
    CiphertextBlob: encoder.decode(key)
  };

  return new AWS.KMS().decrypt(params, done);
}

function split(stashes, decryptedKeys, done) {
  var result = stashes.map((stash, index) => {
    stash.keyPlaintext = new Buffer(32);
    stash.hmacPlaintext = new Buffer(32);
    decryptedKeys[index].Plaintext.copy(stash.keyPlaintext, 0, 0, 32);
    decryptedKeys[index].Plaintext.copy(stash.hmacPlaintext, 0, 32);
    return stash;
  });
  return done(null, result);
}

module.exports = {
  decrypt: (stashes, done) => {
    return async.waterfall([
      async.apply(async.map, stashes.map(s => s.key), decrypt),
      async.apply(split, stashes)
    ], done);
  }
};
