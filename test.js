var parser = require('./parse-cookie');
var BSON = require('bson').BSONPure.BSON;

var cookie = "bEtaTXFvOHlCQjliaVBUUi9BMVB6aFcyeHE5MFJ3YjFaZ1ZHREk5anltUWpxMEgwZkczbHN6ZkFHSW84bURCNFpuVmZuMklJUHJWNU0wTnNObG0ybXVhVXNNL25LL3M4U0FGZ3JZQlhSV00yUFgrdU9sVG9mZGNpUkpZRUhTK2xGZ2hOdVdqb0tVZVIvMlZFZWVodllJRm5jWWhrYnhiUHM1bDhHTmx0Uks2WVlCSzBQbm40Vzhxcy90ZWdsMmZ0YkJGYWV5RWk0ZTRJbDlhTDNqNk9HSk9xSklDSk1ScHF6cFUwTUVib3RFWjlha1ZSd0xWc09ZT1VXSTRNc0piaThDZEI2a0MydHF6c2FnbWEyb0EyZjBMTHZ4UDhzcng2Njk4VXV1azNHZTg2RUpKZG9BZ3Z6M1Z4WXhBMkhRNlFoNXROL2dmem44MkFyZml2b1RRNHNKSFArZGhLZDdDTFZ1MzUvYk1Yb29tY04xeXk2VklhazVRdklLeVhvSEtLdnNNSVdkKzJDTWlJd2Mvb3NuQkp5T2FmSlpLR2FqaStBOTM3Yy9hVm4xUG5yS2piWUxMNWZ2UmdEdERSYjR4a0ljUW1KMjIwR3NFSnQ4a2ozeWc1alVZZ1hJczFZTU9xMjJrSnhoZFNUcVJqN0s4UGdwYjBlVlpFVjQ0dGZQMENSU0c5N1d4bEhjQU9HcmVHdXYzeERBPT0tLTNJNnhIN1ljY0xzNFZFa0JMRWJCR1E9PQ==--93c96ef70cb7a6abaea56b1e17426210d5054ea5"
  , params = {
      base: 'be128db5c11b7c96ba809417f7c1726ee31a4de29e38dfa3567095caef6404294d34bd136708375e5533f4f139b2a20446084b7b57008086a180d4cdf542d600'
    , salt: 'encrypted cookie'
    , signed_salt: 'signed encrypted cookie'
    , iterations: 1000
    , keylen: 64
  }
  , cipher = 'aes-256-cbc'
  ;

/* The original test is broken, even after fixing the usage of the BSON library.
   I'll let the individual author address this. --endotronic

decryptor = parser(params);
message = decryptor(cookie, cipher);
json = BSON.deserialize(message);

console.log(json);*/

var message = 'this is a test';
parser(params).encode(message, cipher, function(err, encodedMessage) {
  var decodedMessage = parser(params).decode(encodedMessage, cipher);
  var success = (decodedMessage == message);
  console.log('encode/decode success: ' + success);
});
