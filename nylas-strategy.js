var OAuth2Strategy = require('passport-oauth2')
	, request = require('request')
	, querystring = require('querystring')
	, util = require('util')
	, AuthorizationError = OAuth2Strategy.AuthorizationError
	, InternalOAuthError = OAuth2Strategy.InternalOAuthError
	;

function OAuth2(clientID, clientSecret, authorizationURL, tokenURL, customHeaders) {
	this.clientID = clientID;
	this.clientSecret = clientSecret;
	this.authorizationURL = authorizationURL || "https://api.nylas.com/oauth/authorize";
	this.tokenURL = tokenURL || "https://api.nylas.com/oauth/token";
	this._accessTokenName = "access_token";
	this.customHeaders = customHeaders || {};

	return this;
}

// -- https://api.nylas.com/oauth/authorize
OAuth2.prototype.getAuthorizeUrl = function({ loginHint, trial, ...rest }) {
  const params = rest;

	if (!(this.clientID && this.clientSecret)) {
		throw new Error("getAuthorizeUrl() cannot be called until you provide a client_id and client_secret");
	}
	if (!params.redirect_uri) {
		throw new Error("getAuthorizeUrl() requires a redirect_uri");
  }

  params.loginHint = loginHint || '';
  params.trial =  trial || false;
  params.client_id = this.clientID;

	return this.authorizationURL + "?" + querystring.stringify(params);
}

OAuth2.prototype.setAccessTokenName = function(name) {
	this._accessTokenName = name;
}

OAuth2.prototype.getOAuthAccessToken = function(code, grantType, callback) {
  const qs = {
    client_id: this.clientID,
	  client_secret: this.clientSecret,
    grant_type: grantType,
    code,
  }

	var _oauth = this;

	request({
		method	: 'POST',
		json: true,
		url		: _oauth.tokenURL,
		qs
	}, function(error, response, body) {
		if (error) { return callback(error, null) }
		if (response.statusCode === 403) {return callback(403, null) }

		var email_address = body["email_address"];
		var access_token = body["access_token"];
		//var provider = results["provider"];
		//var account_id = results["account_id"]; -- both should be available in the results object
		return callback(null, email_address, access_token, body);
	});
}

/**
* Strategy constructor.
*
* The Nylas authentication strategy authenticates requests by delegating to
* Nylas using the OAuth 2.0 protocol.

* Applications must provide a `verify` callback which accepts an `email`,
* `accessToken`, and `nylas` object, containing addiditional info.
* callback will then call the `done` callback supplying a `user`, which is
* set to `false` if the credentials are invalid. `err` would be set if an exception occured.
*
*
* Options:
*	- `clientID`		your Nylas application's clientID
*	- `clientSecret`	your Nylas application's clientSecret
*	- `callbackURL`		your Nylas application's callbackURL -- URL to redirect to after successful authorization


* @param {Object} options
* @param {Function} verify
* @api public
*/
function Strategy(options, verify) {
	options = options || {};
	options.sessionKey = options.sessionKey || 'oauth2:nylas';
	/*options.authorizationURL = options.authorizationURL || 'https://api.nylas.com/oauth/authorize';
	options.tokenURL = options.tokenURL || 'https://api.nylas.com/oauth/token';
	options.clientID = options.clientID;
	options.clientSecret = options.clientSecret;
	options.scopes = options.scopes;
	*/

	if (!verify) {throw new TypeError('OAuth2Strategy requires a verify callback'); }
	//if (!options.authorizationURL) {throw new TypeError('OAuth2Strategy requires an authorizationURL option'); }
	//if (!options.tokenURL) {throw new TypeError('OAuth2Strategy requires a tokenURL option'); }
	//if (!options.clientID) {throw new TypeError('OAuth2Strategy requires a clientID option'); }

	//this._options = options
	this._verify = verify;
	this._oauth2 = new OAuth2(options.clientID, options.clientSecret, options.authorizationURL, options.tokenURL, options.customHeaders);
	this._scopes = options.scopes;
	this._callbackURL = options.callbackURL;


	this.name = 'nylas';
}

util.inherits(Strategy, OAuth2Strategy);


/**
* Authenticating request using the OAuth 2.0 protocol
* @param {Object} req
* @api protected
*/

Strategy.prototype.authenticate = function(req, options = {}) {
	if (req.query && req.query.error) {
		if (req.query.error == 'access_denied') {
			return this.fail({ message: req.query.error_description});
		} else {
			return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
		}
	}

	var self = this;

	if (req.query.code) {
		function verified(err, user, info) {
			if (err) {
        return self.error(err);
      }

			if (!user) {
        return self.fail(info);
      }

			info = info || {};
			self.success(user, info);
		}

		this._oauth2.getOAuthAccessToken(req.query.code, 'authorization_code', function(err, email, accessToken, body) {
				if (err) {
          return self.error(new InternalOAuthError('failed to obtain access token', err));
        }

				//Additional nylas boject returned
				const nylas = {};
				nylas.provider = body.provider || null;
				nylas.account_id = body.account_id || null;
				nylas.token_type = body.token_type || null;
				nylas.scopes = body.scopes || null;
				nylas.email = email || null;

				self._verify(req, accessToken, nylas, verified);
			}
		);
	} else {
		const location = this._oauth2.getAuthorizeUrl({
      response_type: 'code',
      redirect_uri: this._callbackURL,
      loginHint: req.query.login_hint,
      scopes: this._scopes || 'email.read_only',
      state: options.state || req.query.state,
    });

		this.redirect(location);
	}
};

/* Authorize URL = "/oauth/authorize?client_id=" +
	this.clientID +
	"&trial=" + options.trial +
	"&response_type=code&scopes=email&login_hint=" +
	options.loginHint +
	"&redirect_uri=" + options.redirectURI;
*/


/*
* Override OAuth authorizeParams method to allow passing additional parms
* per "pre-fill" Nylas feature
* Return extra parameters to be included in the authorization request.
*/
Strategy.prototype.authorizationParams = function(options) {
	return options;
};

/*
* Override OAuth authorizeParams method to allow passing additional parms
* per "pre-fill" Nylas feature
* Return extra parameters to be included in the token request.
*/
Strategy.prototype.tokenParams = function(options) {
	return options;
};

module.exports = Strategy;
