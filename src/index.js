var express = require('express');
var app = express();
var randomstring = require("randomstring");
var crypto = require("crypto");
var bodyParser = require('body-parser');

var keys = {};

var generateKeys = function() {
  for(var i = 0; i < 10; i++) {
    var str = randomstring.generate(10);
    keys["00" + i] = {id : "00" + i, key : str};
  }
}
generateKeys();

var generateHash = function(msg, key) {
  return  crypto.createHmac('sha512', key).update(msg, 'utf8').digest('hex');
}

app.set('port', (process.env.PORT || 5000))
app.use(express.static(__dirname + '/../doc'))
app.use(bodyParser.json());                        
app.use(bodyParser.urlencoded({ extended: true }));

app.get('/', function(request, response) {
  response.send('Hello World!')
});

/**
 * @api {get} /keys Request For Keys
 * @apiName Get Keys
 * @apiGroup Keys
 * @apiVersion 1.0.0
 * @apiSuccess {Array} result key with id.
 */
app.get('/keys', function(request, response) {
  response.send(keys)
});
/**
 * @api {post} /generate Request Generating SHA512 Hash
 * @apiName Generate Signature
 * @apiGroup Keys
 *
 * @apiParam {String} message Message.
 * @apiParam {String} key Key.
 * @apiVersion 1.0.0
 * @apiSuccess {String} signature Get Signature for the message.
 */
app.post('/generate', function(request, response){
  var msg = request.body.message;
  var key = request.body.key;
  response.send(generateHash(msg, key));
});

/**
 * @api {post} /validate Validating message hash
 * @apiName Validate Signature
 * @apiGroup Keys
 * @apiHeader {String} Authorization Signature.
 * @apiParam {String} message Message.
 * @apiParam {String} key Key.
 * @apiVersion 1.0.0
 *
 * @apiSuccess {String} Valid Verified/Invalid.
 */
app.post('/validate', function(request, response){
  var msg = request.body.message;
  var key = request.body.key;
  var signature = request.headers['authorization'];
  var sent = false;

  if(keys.hasOwnProperty(key)) {
    var private = keys[key].key;
    var computedSignature = generateHash(msg, private);
    if(computedSignature === signature) {
      response.send("Verified");
      sent = true;
    }
  } 
  if(!sent) {
    response.send("Invalid");
  }
});

app.listen(app.get('port'), function() {
  console.log("Node app is running at localhost:" + app.get('port'))
});
