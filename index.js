const jwt = require('jsonwebtoken');

const pub_string = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqr+P33/FqsJKjm3rANWIZpaOJQuHcBDPifHD1ZVN+23G1PRkFc6pgZcIq6BhXZusFUksurx32NSfLMFhA4rkDTQUko7uWO/bKtWRvQQWV/k7gduj+4MwujoyMZXNX/jYT/00+JC2sb8iN1A9SG2cP0wU3IsjVw4Zm1UJ+kBV5qHtyEPUbUMt/OUnRJOdTdQ++riq+7M0kuZ9cf/PXPwtXqHP4OC2f17jUzeSaufNpz60OqK4oVrBhwuG6/qn8ZB3wEpQCiLISX78CPPkbFb95315ORmcgDhAO2LZ5GAnK5DX8zWP4oTmnYvxt5hbP3CXfkFXV+MCJIl2VOxCUIxItwIDAQAB";
function generateJwt(host, consumerId, standard_claims = {}, lp_sdes=[], exp='1h') {
  // sign with RSA SHA256
  let cert = "-----BEGIN RSA PRIVATE KEY-----\n" +
    "MIIEpQIBAAKCAQEAqr+P33/FqsJKjm3rANWIZpaOJQuHcBDPifHD1ZVN+23G1PRk\n" +
    "Fc6pgZcIq6BhXZusFUksurx32NSfLMFhA4rkDTQUko7uWO/bKtWRvQQWV/k7gduj\n" +
    "+4MwujoyMZXNX/jYT/00+JC2sb8iN1A9SG2cP0wU3IsjVw4Zm1UJ+kBV5qHtyEPU\n" +
    "bUMt/OUnRJOdTdQ++riq+7M0kuZ9cf/PXPwtXqHP4OC2f17jUzeSaufNpz60OqK4\n" +
    "oVrBhwuG6/qn8ZB3wEpQCiLISX78CPPkbFb95315ORmcgDhAO2LZ5GAnK5DX8zWP\n" +
    "4oTmnYvxt5hbP3CXfkFXV+MCJIl2VOxCUIxItwIDAQABAoIBAQCVHP+3Li1gh5Z2\n" +
    "tfVB4DjjZl2yalQYAQZNsG3WizHz/hVjCh6RkM4lFtICl+gPyJBKcoH2ffqnyF9N\n" +
    "xX9EibnI8g95QgtSbf1XdfV1PSmKIGTgbgDR9+rI52PIO8uEIZw+lqD45eA2b/Wg\n" +
    "mpk6NEb8XCPnyjbNosmoBmbVPfQGmTu1ITYQOsYQy9qlIGgW0fBHHBJEEPI8CQ3c\n" +
    "UbQg76C2Ge3f2LtcpcWzJKzWnhOHsZcVn2G2FCRPHfGWmAibqIRCfvnLDwOz2Ll7\n" +
    "3zIBM+dvUuBGjY6zq0P116iwfWmpkUolJsg6qXVaD77TKaQo0AUKk6+GD1h78QW/\n" +
    "vBBu0V0pAoGBANq69h9WACXLx7QodbK6fg6TJUzqGZApM2FLAYLRNgH1srvh1zWe\n" +
    "00pKlH3Jcp0Uy/PzSVlRnlWSLvcdbolVzKkOvDUvwcbBfAHqMOpYPx05K4ITkgG/\n" +
    "E1VTMMLCFZDgr39o8//aESILG8bVK7tNMBe82M4mMwuGbqzQgwus1YpLAoGBAMfX\n" +
    "nqBlpX03Bi8TkZ8X9ZdINts5v5SVTho35OLerT5ReG7yE4fkuzurnI39QsdsUgFy\n" +
    "1Bl1vSK5a2N9r+lBreGi7XHEQ/tsAAltqnF9qyfKcK/4oGbAQjr/wsY44jyx7sCn\n" +
    "oVg0R46l+uIJ3DSVrLRmPfUfdfAZZ06lhB4Q0HfFAoGBAK92fYwDtFidkVU/g7Nd\n" +
    "kVPlzG1X+ivAMVxiDBNB+v41eCzp7XcxMrQNAfOqD0xda4MF7hg9tjNU8mH/9TUs\n" +
    "Y+JWVLqh1eO4QN9UW+sR4Ydy3ikZw+2stziiZKJHiX9QDti5e8sJxua1XJHzXYKC\n" +
    "WAsizhUJZbdgHxZ4qjdKbX7jAoGBALTJg19nlUapuJZuBZb/fdXWJoo8u+wXBgkB\n" +
    "97al6+Qsn97+cFzHt/pLTd3F99uhSq60ytwdf3UieNwQoEtMd5lgY55AB6A0G/Rr\n" +
    "mX4CSgw9P6RyL+nElCX7qqDYZRKzhWIURAofgXyy+zvx35xSq2Kn+/T8+Ry0Xpjv\n" +
    "c44fd/hhAoGAfrXCUEhSoL2t71MKnoggg48Vq6pZOq56+ZnVZAohlVVpX5tUsfFx\n" +
    "BVQP/N0EvQuiz/Y5IqymdSPuxkhmQLdfrkOv6iMvQbFxPkF8B9cI6eDNhJ9seynF\n" +
    "Wv5blM4Z2VZGDXFwzZRs78jW8y2y7ahoiOntnR8daTIYZbJPVfi9cWo=\n" +
    "-----END RSA PRIVATE KEY-----";
  
  console.log(`generateJwt() use consumerId: `, consumerId);

  let payload = {
    sub: consumerId,
    iss: host,
    lp_sdes: lp_sdes
  };

  // Compare in list of supported standard claims
  let supported_standard_claims = ['given_name', 'family_name', 'email', 'gender', 'preferred_username', 'phone_number'];
  for (const [key, claim] of Object.entries(standard_claims)) {

    if(supported_standard_claims.includes(key)) {
      console.log(`${key}: ${claim}`);
      payload[key] = claim;
    }
  }

  return jwt.sign(
    payload,
    cert, {
    algorithm: 'RS256',
    expiresIn: exp
  });
}

//=== to run this code locally ====
let eventPayload = {
  headers: {
    "Host": "https://www.avva.com"
  },
  body: {
    consumerId: "example_customer_id",
    lp_sdes: [
        {
            "type": "ctmrinfo",
            "info": {
                "cstatus": "cancelled",
                "ctype": "zzz",
                "customerId": "138766AC",
                "balance": -400.99
            }
        },
        {
            "type": "personal",
            "personal": {
                "firstname": "John",
                "lastname": "Doe",
                "language": "en-US",
                "company": "company"
            }
        }
    ],
    standard_claims: "",
    expiresIn: "24h"
  }
}

function generate_jwt(event){
  let body = event.body;
  let response = {};
  if (!body.consumerId) {
    console.log("'consumerId' not provided");
  } else {

    console.log(JSON.stringify({
      id_token: generateJwt(event.headers.Host, body.consumerId, body.standard_claims, body.lp_sdes, body.expiresIn),
      pub_string
    }))
  }
};

generate_jwt(eventPayload);
//===== end ====


//===== this is only applicable for AWS lambda =====
// module.exports.generate_jwt = (event, context, callback) => {
//   let body = JSON.parse(event.body);
//   let response = {};
//   if (!body.consumerId) {
//     response.statusCode = 500;
//     response.body = JSON.stringify({
//       error: "'consumerId' not provided"
//     })
//   } else {
//     response.statusCode = 200;
//     response.body = JSON.stringify({
//       id_token: generateJwt(event.headers.Host, body.consumerId, body.standard_claims, body.lp_sdes, body.expiresIn),
//       pub_string
//     })
//   }

//   callback(null, response);
// };




