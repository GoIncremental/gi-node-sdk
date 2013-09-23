moment = require 'moment'
crypto = require 'crypto'

uriEscape= (string) ->
  uri = escape(string).replace(/\+/g, '%2B').replace(/\//g, '%2F')
  uri = uri.replace(/%7E/g, '~').replace(/\=/g, '%3D')

encodeProperty = (key, value) ->
  uriEscape(key) + '=' + uriEscape(value)

encodeHeaders = (headers) ->
  result = ""
  if headers['access-key']
    result += encodeProperty('access-key', headers['access-key'])
  if headers['expiry-date']
    result += '&' + encodeProperty('expiry-date', headers['expiry-date'])
  result

stringToSign = (req) ->
  parts = []
  parts.push req.method
  parts.push req.host
  parts.push req.path
  parts.push encodeHeaders(req.headers)
  parts.join '\n'

hmac = (key, string, digest, fn) ->
  if not digest
    digest = 'binary'
  if not fn
    fn = 'sha256'
  crypto.createHmac(fn, new Buffer(key, 'utf8')).update(string).digest(digest)

module.exports = 
  encodeHeaders: encodeHeaders

  signString: (key, string) ->
    hmac key, string, 'base64'
  signRequest: (req, accessKey, secretKey, cb) ->
    req.headers['access-key'] = accessKey
    req.headers['expiry-date'] = moment().add('m', 1).unix()
    sts = stringToSign req
    sig = hmac secretKey, sts, 'base64'
    req.headers.signature = sig
    cb null
