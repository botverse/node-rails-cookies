var crypto = require('crypto');

// constant time comparison
function compare(a, b) {
  if ( a.length !== b.length ) {
    return false;
  }

  var result = 0;
  for (var i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }

  return 0 === result;
}

module.exports = function(options) {
  var secret = crypto.pbkdf2Sync(options.base, options.salt, options.iterations, options.keylen / 2)
    , signed_secret = crypto.pbkdf2Sync(options.base, options.signed_salt, options.iterations, options.keylen)
    ;

  return {
    decipher: function(cookie, cipherName) {
      var signed_parts = cookie.split('--')
        , hmac = crypto.createHmac('sha1', signed_secret)
        , digest
        ;

      hmac.update(signed_parts[0]);
      digest = hmac.digest('hex');

      if ( !compare(signed_parts[1], digest) ) return console.log('not valid');

      var message = (new Buffer(signed_parts[0], 'base64').toString())
        , parts = message.split('--').map(function(part) {
            return new Buffer(part, 'base64');
          })
        ;

      var cipher = crypto.createDecipheriv(cipherName, secret, parts[1])
        , part = new Buffer(cipher.update(parts[0])).toString('utf8')
        , final = cipher.final('utf8')
        ;

      return [part, final].join('');
    },

    encipher: function(message, cipherName, callback) {
      crypto.pseudoRandomBytes(16, function(err, iv) {
        if (err) {
          callback(err);
        }

        var cipher = crypto.createCipheriv(cipherName, secret, iv)
          , part = new Buffer(cipher.update(new Buffer(message)))
          , final = cipher.final(),
          encryptedMessage = Buffer.concat([part, final]).toString('base64')
          ;

        var fullMessage = new Buffer([encryptedMessage, iv.toString('base64')].join('--')).toString('base64')
          , hmac = crypto.createHmac('sha1', signed_secret)
          , digest
          ;

        hmac.update(fullMessage);
        digest = hmac.digest('hex');

        var cookie = [fullMessage, digest].join('--');
        callback(null, cookie);
      });
    }
  }
};
