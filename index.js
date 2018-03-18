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
app.use(express.static(__dirname + '/public'))
app.use(bodyParser.json());                        
app.use(bodyParser.urlencoded({ extended: true }));

app.get('/', function(request, response) {
  response.send('Hello World!')
});
app.get('/keys', function(request, response) {
  response.send(keys)
});
app.post('/generate', function(request, response){
  var msg = request.body.message;
  var key = request.body.key;
  response.send(generateHash(msg, key));
});
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
