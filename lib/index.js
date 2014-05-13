var jwt = require('jsonwebtoken');
var crypto = require('crypto');

var UnauthorizedError = require('./errors/UnauthorizedError');
var SignatureError = require('./errors/SignatureError');

module.exports = function(options) {
	if (!options || !options.secret) {
		throw new Error('Secret should be set');
	}

	return function(req, res, next) {
    	var token;
    
    	if (req.method === 'OPTIONS' && req.headers.hasOwnProperty('access-control-request-headers')) {
		for (var ctrlReqs = req.headers['access-control-request-headers'].split(','),i=0;i < ctrlReqs.length; i++) {
    			if (ctrlReqs[i].indexOf('authorization') != -1) {
					return next();
				}
			}
    	}
    	/// HERE CARRY ON THE VERIFICATION

		if (req.headers && req.headers.signature) {
			
	    	var data = req.body.toString();
	    	var signature = crypto.createHmac("md5", options.secret).update(data).digest("hex");
	    	
	    	if( req.headers.signature !== signature ) {
	    		return next(new SignatureError('signature_invalid', { message: 'The signature verification for this message has failed (Expected: '+signature+')' }));
	    	}
			
		} else {
			return next(new SignatureError('signature_required', { message: 'Signature is missing for this message' }));
		}
    	
    	
    	/// ==================
    	
    	if (typeof options.skip !== 'undefined') {
      		if (options.skip.indexOf(req.url) > -1) {
        		return next();
      		}
    	} 
    	
		if (req.headers && req.headers.authorization) {
	  		var parts = req.headers.authorization.split(' ');
	      	if (parts.length == 2) {
	        	var scheme = parts[0], credentials = parts[1];
	        	if (/^Bearer$/i.test(scheme)) {
	          		token = credentials;
	        	}
	      	} else {
	        	return next(new UnauthorizedError('credentials_bad_format', { message: 'Format is Authorization: Bearer [token]' }));
	      	}
		} else {
			return next(new UnauthorizedError('credentials_required', { message: 'No Authorization header was found' }));
	    }
	
	    jwt.verify(token, options.secret, options, function(err, decoded) {
			if (err) return next(new UnauthorizedError('invalid_token', err));
	
	  		req.user = decoded;
	      	next();
		});
	
	};
  
};
