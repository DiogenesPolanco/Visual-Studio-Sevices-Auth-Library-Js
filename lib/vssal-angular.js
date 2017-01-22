// vssalJS v0.2

var ContextVssal = (function() {
    'use strict';

    /**
     * Configuration options for Authentication Context.
     * @class config
     *  @property {string} clientID - Client ID assigned to your app by Visual Studio Online.
     *  @property {string} redirectUri - Endpoint at which you expect to receive tokens.Defaults to `window.location.href`.
     *  @property {string} instance - Visual Studio Online Instance.Defaults to `https://app.vssps.visualstudio.com/`.
     *  @property {string} localLoginUrl - Set this to redirect the user to a custom login page.
     *  @property {function} displayCall - User defined function of handling the navigation to Visual Studio authorization endpoint in case of login. Defaults to 'null'.
     *  @property {string} postLogoutRedirectUri - Redirects the user to postLogoutRedirectUri after logout. Defaults to 'null'.
     *  @property {string} cacheLocation - Sets browser storage to either 'localStorage' or sessionStorage'. Defaults to 'sessionStorage'.
     *  @property {number} expireOffsetSeconds If the cached token is about to be expired in the expireOffsetSeconds (in seconds), vssal will renew the token instead of using the cached token. Defaults to 120 seconds.
     *  @property {string} correlationId Unique identifier used to map the request with the response. Defaults to RFC4122 version 4 guid (128 bits).
     */

    /**
     * Creates a new ContextVssal object.
     * @constructor
     * @param {config}  config               Configuration options for ContextVssal
     */

    ContextVssal = function(config) {
        /**
         * Enum for storage constants
         * @enum {string}
         */
        this.CONSTANTS = {

            ACCESS_TOKEN: 'access_token',
            TOKEN_TYPE: 'token_type',
            EXPIRES_IN: 'expires_in',
            REFRESH_TOKEN: 'refresh_token',
            CODE: 'code',
            SCOPE: 'scope',
            ERROR: 'Error',
            ERROR_DESCRIPTION: 'ErrorDescription',

            STORAGE: {
                ACCESS_TOKEN: 'vssal.access.token.key',
                REFRESH_TOKEN: 'vssal.access.refreshtoken.key',
                EXPIRATION_KEY: 'vssal.expiration.key',
                SCOPE: 'vssal.scope',
                ERROR: 'vssal.error',
                ERROR_DESCRIPTION: 'vssal.error.description'
            },
            LOADFRAME_TIMEOUT: '6000',
            TOKEN_RENEW_STATUS_CANCELED: 'Canceled',
            TOKEN_RENEW_STATUS_COMPLETED: 'Completed',
            TOKEN_RENEW_STATUS_IN_PROGRESS: 'In Progress',
            LOGGING_LEVEL: {
                ERROR: 0,
                WARN: 1,
                INFO: 2,
                VERBOSE: 3
            },
            LEVEL_STRING_MAP: {
                0: 'ERROR:',
                1: 'WARNING:',
                2: 'INFO:',
                3: 'VERBOSE:'
            },
            POPUP_WIDTH: 483,
            POPUP_HEIGHT: 600
        };

        if (ContextVssal.prototype._singletonInstance) {
            return ContextVssal.prototype._singletonInstance;
        }
        ContextVssal.prototype._singletonInstance = this;

        // public
        this.instance = 'https://app.vssps.visualstudio.com/';
        this.config = {};
        this.callback = null;
        this.popUp = false;
        this.isAngular = false;

        // private
        this._user = null;
        this._activeRenewals = {};
        this._loginInProgress = false;
        this._renewStates = [];

        window.callBackMappedToRenewStates = {};
        window.callBacksMappedToRenewStates = {};

        if (!config.clientId) {
            throw new Error('clientId is required');
        }

        if (!config.scope) {
            throw new Error('scope is required');
        }

        if (!config.client_assertion) {
            throw new Error('client Assertion is required');
        }

        this.config = this._cloneConfig(config);
        this.config.baseUrlResource = this.instance;
        if (this.config.callback && typeof this.config.callback === 'function')
            this.callback = this.config.callback;

        if (!config.client_assertion_type) {
            this.config.client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
        }

        if (!config.grant_type) {
            this.config.grant_type = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
        }

        if (!this.config.redirectUri) {
            this.config.redirectUri = this.getRedirectUri();
        }

        if (this.config.isAngular) {
            this.isAngular = this.config.isAngular;
        }
        if (this.config.auto && this.isCallback()) {
            this.acquireToken();
        }
    };

    window.Logging = {
        level: 0,
        log: function(message) {}
    };
    ContextVssal.prototype.getRedirectUri = function() {
        return location.protocol + "//" + location.host;
    }
    ContextVssal.prototype.getUrlResourceTenant = function() {
            return location.protocol + '//' + this.config.tenant + '.visualstudio.com/';
        }
        /**
         * Initiates the login process by redirecting the user to Visual Studio authorization endpoint.
         */
    ContextVssal.prototype.login = function() {
        // Token is not present and user needs to login
        if (this._loginInProgress) {
            this.info("Login in progress");
            return;
        }
        this._saveItem(this.CONSTANTS.STORAGE.ERROR, '');
        this._saveItem(this.CONSTANTS.STORAGE.ERROR_DESCRIPTION, '');
        var urlNavigate = this._getNavigateUrl('Assertion', null);
        this._loginInProgress = true;
        if (this.config.displayCall) {
            // User defined way of handling the navigation
            this.config.displayCall(urlNavigate);
        } else {
            this.promptUser(urlNavigate);
        }
    };

    /**
     * Checks if login is in progress.
     * @returns {Boolean} true if login is in progress, false otherwise.
     */
    ContextVssal.prototype.loginInProgress = function() {
        return this._loginInProgress;
    };

    /**      
     * @returns {string} token if if it exists and not expired, otherwise null.
     */
    ContextVssal.prototype.getCachedToken = function() {
        var self = this;
        var token = self._getItem(self.CONSTANTS.STORAGE.ACCESS_TOKEN);
        var expired = self._getItem(self.CONSTANTS.STORAGE.EXPIRATION_KEY);

        // If expiration is within offset, it will force renew
        var offset = self.config.expireOffsetSeconds || 120;

        if (expired && (expired > self._now() + offset)) {
            return self.promise(undefined, token);
        } else {
            self._saveItem(self.CONSTANTS.STORAGE.ACCESS_TOKEN, '');
            self._saveItem(self.CONSTANTS.STORAGE.EXPIRATION_KEY, 0);
            return self.promise(undefined, null);
        }
    };

    /**
     * User information from idtoken.
     *  @class User
     *  @property {string} userName - username assigned from upn or email.
     *  @property {object} profile - properties parsed from idtoken.
     */

    /**
     * If user object exists, returns it. Else creates a new user object by decoding token from the cache.
     * @returns {User} user object
     */
    ContextVssal.prototype.getCachedUser = function() {
        var self = this;
        if (self._user) {
            return self.promise(undefined, self._user);
        } else {
            return self._createUser();
        }
    };

    ContextVssal.prototype._getQueryString = function(field, url) {
        var href = url ? url : window.location.href;
        var reg = new RegExp('[?&]' + field + '=([^&#]*)', 'i');
        var string = reg.exec(href);
        return string ? string[1] : null;
    };
    // var errorResponse = {error:'', error_description:''};
    // var token = 'string token';
    // callback(errorResponse, token)
    // with callback
    /**
     * Acquires access token with hidden iframe
     * @ignore
     */
    ContextVssal.prototype._newToken = function(callback) {
        var self = this;
        var request = self.promise({
            method: 'post',
            url: self.instance + 'oauth2/token',
            data: {
                client_assertion_type: self.config.client_assertion_type,
                client_assertion: self.config.client_assertion,
                grant_type: self.config.grant_type,
                assertion: self._getQueryString('code'),
                redirect_uri: self.getRedirectUri()
            }
        }).then(function(response) {
            self.verbose('Renew token ');
            return self.saveToken(response);
        });
        return request;
    };

    /**
     * Checks if the authorization endpoint URL contains query string parameters
     * @ignore
     */
    ContextVssal.prototype._urlContainsQueryStringParameter = function(name, url) {
        // regex to detect pattern of a ? or & followed by the name parameter and an equals character
        var regex = new RegExp("[\\?&]" + name + "=");
        return regex.test(url);
    }

    /**
     * @callback tokenCallback
     * @param {string} error error message returned from VSO if token request fails.
     * @param {string} token token returned from VSO if token request is successful.
     */

    /**
     * Acquires token from the cache if it is not expired. Otherwise sends request to VSO to obtain a new token.
     * @param {tokenCallback} callback -  The callback provided by the caller. It will be called with token or error.
     */
    ContextVssal.prototype.acquireToken = function() {
        var self = this;
        var request = this.getCachedToken().then(function(token) {
            if (token) {
                self.info('Token is already in cache');
                return self.promise(undefined, token);
            } else if (self.isCallback()) {
                return self._newToken();
            } else {
                self.login();
            }
        });
        return request;
    };

    /**
     * Redirects the browser to Visual Studio authorization endpoint.
     * @param {string}   urlNavigate  Url of the authorization endpoint.
     */
    ContextVssal.prototype.promptUser = function(urlNavigate) {
        if (urlNavigate) {
            this.info('Navigate to:' + urlNavigate);
            window.location.replace(urlNavigate);
        } else {
            this.info('Navigate url is empty');
        }
    };

    /**
     * Clears cache items.
     */
    ContextVssal.prototype.clearCache = function() {
        this._saveItem(this.CONSTANTS.STORAGE.SCOPE, '');
        this._saveItem(this.CONSTANTS.STORAGE.ACCESS_TOKEN, '');
        this._saveItem(this.CONSTANTS.STORAGE.EXPIRATION_KEY, 0);
        this._saveItem(this.CONSTANTS.STORAGE.ERROR, '');
        this._saveItem(this.CONSTANTS.STORAGE.ERROR_DESCRIPTION, '');
    };

    /**
     * Redirects user to logout endpoint.
     * After logout, it will redirect to postLogoutRedirectUri if added as a property on the config object.
     */
    ContextVssal.prototype.logOut = function() {
        this.clearCache();
        this._user = null;
        var urlNavigate;

        if (this.config.logOutUri) {
            urlNavigate = this.config.logOutUri;
        } else {
            var logout = '';
            if (this.config.redirectUri) {
                logout = 'redirectUrl=' + encodeURIComponent(this.getRedirectUri());
            }
            urlNavigate = this.instance + '_signout?' + logout;
        }
        this.info('Logout navigate to: ' + urlNavigate);
        this.promptUser(urlNavigate);
    };

    ContextVssal.prototype._isEmpty = function(str) {
        return (typeof str === 'undefined' || !str || 0 === str.length);
    };

    /**
     * @callback userCallback
     * @param {string} error error message if user info is not available.
     * @param {User} user user object retrieved from the cache.
     */

    /**
     * Calls the passed in callback with the user object or error message related to the user.
     * @param {userCallback} callback - The callback provided by the caller. It will be called with user or error.
     */
    ContextVssal.prototype.getUser = function(callback) {
        var self = this;
        // IDToken is first call
        if (typeof callback !== 'function') {
            throw new Error('callback is not a function');
        }

        // user in memory
        if (self._user) {
            callback(null, self._user);
            return;
        }

        // frame is used to get idtoken
        var user = self.getCachedUser();
        if (!self._isEmpty(user)) {
            self.info('User exists in cache ');
            self._createUser().then(function() {
                callback(null, self._user);
            });
        } else {
            self.warn('User information is not available');
            callback('User information is not available', null);
        }
    };
    ContextVssal.prototype.promise = function(params, manualresponse) {
            var self = this;
            var promise = new Promise(
                function(resolve, reject) {
                    if (params === undefined) {
                        resolve(manualresponse);
                    } else {
                        self.getCachedToken().then(function(token) {
                            if (params.AutoAuth) {
                                params.headers = {
                                    'Content-Type': 'application/json',
                                    'Authorization': 'Bearer ' + token
                                };
                            }
                            ajax(params)
                                .then(function(response) {
                                    resolve(response);
                                })
                                .catch(function(error) {
                                    reject(error);
                                })
                                .always(function(response) {
                                    resolve(response);
                                });
                        });
                    }
                }
            );
            return promise;
        }
        /**
         * Creates a user object by decoding the token
         * @ignore
         */
    ContextVssal.prototype._createUser = function() {
        var user = null;
        var self = this;
        var request = self.promise({
            AutoAuth: true,
            method: 'get',
            url: self.instance + '_apis/profile/profiles/me'
        }).then(function(response) {
            if (response && response.hasOwnProperty('displayName')) {
                user = {
                    userName: '',
                    profile: response
                };
                if (response.hasOwnProperty('emailAddress')) {
                    user.userName = response.emailAddress;
                }
                self._user = user;
            } else {
                self.warn('displayName has invalid aud field');
            }
            return self._user;
        });
        return request;
    };

    /**
     * Returns the anchor part(#) of the URL
     * @ignore
     */
    ContextVssal.prototype._getHash = function(hash) {
        if (hash.indexOf('#/') > -1) {
            hash = hash.substring(hash.indexOf('#/') + 2);
        } else if (hash.indexOf('#') > -1) {
            hash = hash.substring(1);
        }

        return hash;
    };

    /**
     * Checks if the URL fragment contains access token, id token or error_description.
     * @param {string} hash  -  Hash passed from redirect page
     * @returns {Boolean} true if response contains token, access_token or error, false otherwise.
     */
    ContextVssal.prototype.isCallback = function(hash) {
        var self = this;
        hash = self._getHash(hash === undefined ? window.location.hash : hash);
        var parameters = self._deserialize(hash);
        if (hash === "") {
            parameters = { code: self._getQueryString('code') };
        }
        return parameters.hasOwnProperty(self.CONSTANTS.CODE) && parameters.code !== null;
    };

    /**
     * Gets login error
     * @returns {string} error message related to login.
     */
    ContextVssal.prototype.getLoginError = function() {
        return this._getItem(this.CONSTANTS.STORAGE.LOGIN_ERROR);
    };

    /**
     * Saves token or error received in the response from VSO in the cache. In case of token, it also creates the user object.
     */
    ContextVssal.prototype.saveToken = function(requestInfo) {
        var self = this;
        self._saveItem(self.CONSTANTS.STORAGE.ERROR, '');
        self._saveItem(self.CONSTANTS.STORAGE.ERROR_DESCRIPTION, '');
        // Record error 
        if (requestInfo.hasOwnProperty(self.CONSTANTS.ERROR_DESCRIPTION)) {
            self.info('Error :' + requestInfo[self.CONSTANTS.ERROR] + '; Error description:' + requestInfo[self.CONSTANTS.ERROR_DESCRIPTION]);
            self._saveItem(self.CONSTANTS.STORAGE.ERROR, requestInfo[self.CONSTANTS.ERROR]);
            self._saveItem(self.CONSTANTS.STORAGE.ERROR_DESCRIPTION, requestInfo[self.CONSTANTS.ERROR_DESCRIPTION]);

            self._saveItem(self.CONSTANTS.STORAGE.SCOPE, '');
            self._saveItem(self.CONSTANTS.STORAGE.ACCESS_TOKEN, '');
            self._saveItem(self.CONSTANTS.STORAGE.EXPIRATION_KEY, 0);
        }
        if (requestInfo.hasOwnProperty(self.CONSTANTS.ACCESS_TOKEN)) {
            self.info('Fragment has access token');
            self._saveItem(self.CONSTANTS.STORAGE.SCOPE, requestInfo[self.CONSTANTS.SCOPE]);
            self._saveItem(self.CONSTANTS.STORAGE.ACCESS_TOKEN, requestInfo[self.CONSTANTS.ACCESS_TOKEN]);
            self._saveItem(self.CONSTANTS.STORAGE.EXPIRATION_KEY, self._expiresIn(requestInfo[self.CONSTANTS.EXPIRES_IN]));
            return self.promise(undefined, requestInfo[self.CONSTANTS.ACCESS_TOKEN]);
        } else {
            return self.promise(undefined, null);
        }
    }

    /**
     * Strips the protocol part of the URL and returns it.
     * @ignore
     */
    ContextVssal.prototype._getHostFromUri = function(uri) {
        // remove http:// or https:// from uri
        var extractedUri = String(uri).replace(/^(https?:)\/\//, '');

        extractedUri = extractedUri.split('/')[0];
        return extractedUri;
    };

    /**
     * Constructs the authorization endpoint URL and returns it.
     * @ignore
     */
    ContextVssal.prototype._getNavigateUrl = function(responseType, scope) {
        var urlNavigate = '';
        if (responseType === 'Assertion') {
            urlNavigate = this.instance + 'oauth2/authorize' + this._serialize(responseType, this.config, scope);
        }
        this.info('Navigate url:' + urlNavigate);
        return urlNavigate;
    };

    /**
     * Decodes a string of data which has been encoded using base-64 encoding.
     * @ignore
     */
    ContextVssal.prototype._base64DecodeStringUrlSafe = function(base64IdToken) {
        // html5 should support atob function for decoding
        base64IdToken = base64IdToken.replace(/-/g, '+').replace(/_/g, '/');
        if (window.atob) {
            return decodeURIComponent(escape(window.atob(base64IdToken))); // jshint ignore:line
        } else {
            return decodeURIComponent(escape(this._decode(base64IdToken)));
        }
    };

    ContextVssal.prototype._decode = function(base64IdToken) {
        var codes = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
        base64IdToken = String(base64IdToken).replace(/=+$/, '');

        var length = base64IdToken.length;
        if (length % 4 === 1) {
            throw new Error('The token to be decoded is not correctly encoded.');
        }

        var h1, h2, h3, h4, bits, c1, c2, c3, decoded = '';
        for (var i = 0; i < length; i += 4) {
            //Every 4 base64 encoded character will be converted to 3 byte string, which is 24 bits
            // then 6 bits per base64 encoded character
            h1 = codes.indexOf(base64IdToken.charAt(i));
            h2 = codes.indexOf(base64IdToken.charAt(i + 1));
            h3 = codes.indexOf(base64IdToken.charAt(i + 2));
            h4 = codes.indexOf(base64IdToken.charAt(i + 3));

            // For padding, if last two are '='
            if (i + 2 === length - 1) {
                bits = h1 << 18 | h2 << 12 | h3 << 6;
                c1 = bits >> 16 & 255;
                c2 = bits >> 8 & 255;
                decoded += String.fromCharCode(c1, c2);
                break;
            }
            // if last one is '='
            else if (i + 1 === length - 1) {
                bits = h1 << 18 | h2 << 12
                c1 = bits >> 16 & 255;
                decoded += String.fromCharCode(c1);
                break;
            }

            bits = h1 << 18 | h2 << 12 | h3 << 6 | h4;

            // then convert to 3 byte chars
            c1 = bits >> 16 & 255;
            c2 = bits >> 8 & 255;
            c3 = bits & 255;

            decoded += String.fromCharCode(c1, c2, c3);
        }

        return decoded;
    };

    /**
     * Converts string to represent binary data in ASCII string format by translating it into a radix-64 representation and returns it
     * @ignore
     */
    ContextVssal.prototype._convertUrlSafeToRegularBase64EncodedString = function(str) {
        return str.replace('-', '+').replace('_', '/');
    };

    /**
     * Serializes the parameters for the authorization endpoint URL and returns the serialized uri string.
     * @ignore
     */
    ContextVssal.prototype._serialize = function(responseType, obj, scope) {
        var str = [];
        if (obj !== null) {
            str.push('?response_type=' + responseType);
            str.push('client_id=' + encodeURIComponent(obj.clientId));
            if (scope) {
                str.push('scope=' + encodeURIComponent(scope));
            } else {
                str.push('scope=' + encodeURIComponent(obj.scope));
            }
            str.push('redirect_uri=' + encodeURIComponent(this.getRedirectUri()));
            if (obj.state) {
                str.push('state=' + encodeURIComponent(obj.state));
            }
        }
        return str.join('&');
    };

    /**
     * Parses the query string parameters into a key-value pair object.
     * @ignore
     */
    ContextVssal.prototype._deserialize = function(query) {
        var match,
            pl = /\+/g, // Regex for replacing addition symbol with a space
            search = /([^&=]+)=([^&]*)/g,
            decode = function(s) {
                return decodeURIComponent(s.replace(pl, ' '));
            },
            obj = {};
        match = search.exec(query);
        while (match) {
            obj[decode(match[1])] = decode(match[2]);
            match = search.exec(query);
        }

        return obj;
    };

    /**
     * Converts decimal value to hex equivalent
     * @ignore
     */
    ContextVssal.prototype._decimalToHex = function(number) {
        var hex = number.toString(16);
        while (hex.length < 2) {
            hex = '0' + hex;
        }
        return hex;
    }

    /* jshint ignore:end */

    /**
     * Calculates the expires in value in milliseconds for the acquired token
     * @ignore
     */
    ContextVssal.prototype._expiresIn = function(expires) {
        return this._now() + parseInt(expires, 10);
    };

    /**
     * Return the number of milliseconds since 1970/01/01
     * @ignore
     */
    ContextVssal.prototype._now = function() {
        return Math.round(new Date().getTime() / 1000.0);
    };
    /**
     * Saves the key-value pair in the cache
     * @ignore
     */
    ContextVssal.prototype._saveItem = function(key, obj) {

        if (this.config && this.config.cacheLocation && this.config.cacheLocation === 'localStorage') {

            if (!this._supportsLocalStorage()) {
                this.info('Local storage is not supported');
                return false;
            }

            localStorage.setItem(key, obj);

            return true;
        }

        // Default as session storage
        if (!this._supportsSessionStorage()) {
            this.info('Session storage is not supported');
            return false;
        }

        sessionStorage.setItem(key, obj);
        return true;
    };

    /**
     * Searches the value for the given key in the cache
     * @ignore
     */
    ContextVssal.prototype._getItem = function(key) {

        if (this.config && this.config.cacheLocation && this.config.cacheLocation === 'localStorage') {

            if (!this._supportsLocalStorage()) {
                this.info('Local storage is not supported');
                return null;
            }

            return localStorage.getItem(key);
        }

        // Default as session storage
        if (!this._supportsSessionStorage()) {
            this.info('Session storage is not supported');
            return null;
        }

        return sessionStorage.getItem(key);
    };

    /**
     * Returns true if browser supports localStorage, false otherwise.
     * @ignore
     */
    ContextVssal.prototype._supportsLocalStorage = function() {
        try {
            var supportsLocalStorage = 'localStorage' in window && window['localStorage'];
            if (supportsLocalStorage) {
                window.localStorage.setItem('storageTest', '');
                window.localStorage.removeItem('storageTest');
            }
            return supportsLocalStorage;
        } catch (e) {
            return false;
        }
    };

    /**
     * Returns true if browser supports sessionStorage, false otherwise.
     * @ignore
     */
    ContextVssal.prototype._supportsSessionStorage = function() {
        try {
            var supportsSessionStorage = 'sessionStorage' in window && window['sessionStorage'];
            if (supportsSessionStorage) {
                window.sessionStorage.setItem('storageTest', '');
                window.sessionStorage.removeItem('storageTest');
            }
            return supportsSessionStorage;
        } catch (e) {
            return false;
        }
    };

    /**
     * Returns a cloned copy of the passed object.
     * @ignore
     */
    ContextVssal.prototype._cloneConfig = function(obj) {
        if (null === obj || 'object' !== typeof obj) {
            return obj;
        }

        var copy = {};
        for (var attr in obj) {
            if (obj.hasOwnProperty(attr)) {
                copy[attr] = obj[attr];
            }
        }
        return copy;
    };

    /**
     * Checks the Logging Level, constructs the Log message and logs it. Users need to implement/override this method to turn on Logging. 
     * @param {number} level  -  Level can be set 0,1,2 and 3 which turns on 'error', 'warning', 'info' or 'verbose' level logging respectively.
     * @param {string} message  -  Message to log.
     * @param {string} error  -  Error to log.
     */
    ContextVssal.prototype.log = function(level, message, error) {
        if (level <= Logging.level) {
            var timestamp = new Date().toUTCString();
            var formattedMessage = '';

            if (this.config.correlationId)
                formattedMessage = timestamp + ':' + this.config.correlationId + '-' + this._libVersion() + '-' + this.CONSTANTS.LEVEL_STRING_MAP[level] + ' ' + message;
            else
                formattedMessage = timestamp + ':' + this._libVersion() + '-' + this.CONSTANTS.LEVEL_STRING_MAP[level] + ' ' + message;

            if (error) {
                formattedMessage += '\nstack:\n' + error.stack;
            }

            Logging.log(formattedMessage);
        }
    };

    /**
     * Logs messages when Logging Level is set to 0.
     * @param {string} message  -  Message to log.
     * @param {string} error  -  Error to log.
     */
    ContextVssal.prototype.error = function(message, error) {
        this.log(this.CONSTANTS.LOGGING_LEVEL.ERROR, message, error);
    };

    /**
     * Logs messages when Logging Level is set to 1.
     * @param {string} message  -  Message to log.
     */
    ContextVssal.prototype.warn = function(message) {
        this.log(this.CONSTANTS.LOGGING_LEVEL.WARN, message, null);
    };

    /**
     * Logs messages when Logging Level is set to 2.
     * @param {string} message  -  Message to log.
     */
    ContextVssal.prototype.info = function(message) {
        this.log(this.CONSTANTS.LOGGING_LEVEL.INFO, message, null);
    };

    /**
     * Logs messages when Logging Level is set to 3.
     * @param {string} message  -  Message to log.
     */
    ContextVssal.prototype.verbose = function(message) {
        this.log(this.CONSTANTS.LOGGING_LEVEL.VERBOSE, message, null);
    };

    /**
     * Returns the library version.
     * @ignore
     */
    ContextVssal.prototype._libVersion = function() {
        return '0.0.1';
    };

    /**
     * Returns a reference of Authentication Context as a result of a require call.
     * @ignore
     */
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = ContextVssal;
        module.exports.inject = function(conf) {
            return new ContextVssal(conf);
        };
    }

    return ContextVssal;

}());

(function(root, factory) {
    'use strict'
    /* istanbul ignore next */
    if (typeof define === 'function' && define.amd) {
        define('ajax', factory)
    } else if (typeof exports === 'object') {
        exports = module.exports = factory()
    } else {
        root.ajax = factory()
    }
})(this, function() {
    'use strict'

    function ajax(options) {
        var methods = ['get', 'post', 'put', 'delete']
        options = options || {}
        options.baseUrl = options.baseUrl || ''
        if (options.method && options.url) {
            return xhrConnection(
                options.method,
                options.baseUrl + options.url,
                maybeData(options.data),
                options
            )
        }
        return methods.reduce(function(acc, method) {
            acc[method] = function(url, data) {
                return xhrConnection(
                    method,
                    options.baseUrl + url,
                    maybeData(data),
                    options
                )
            }
            return acc
        }, {})
    }

    function maybeData(data) {
        return data || null
    }

    function xhrConnection(type, url, data, options) {
        var returnMethods = ['then', 'catch', 'always']
        var promiseMethods = returnMethods.reduce(function(promise, method) {
            promise[method] = function(callback) {
                promise[method] = callback
                return promise
            }
            return promise
        }, {})
        var xhr = new XMLHttpRequest()
        xhr.open(type, url, true)
        xhr.withCredentials = options.hasOwnProperty('withCredentials')
        setHeaders(xhr, options.headers)
        xhr.addEventListener('readystatechange', ready(promiseMethods, xhr), false)
        xhr.send(objectToQueryString(data))
        promiseMethods.abort = function() {
            return xhr.abort()
        }
        return promiseMethods
    }

    function setHeaders(xhr, headers) {
        headers = headers || {}
        if (!hasContentType(headers)) {
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        }
        Object.keys(headers).forEach(function(name) {
            (headers[name] && xhr.setRequestHeader(name, headers[name]))
        })
    }

    function hasContentType(headers) {
        return Object.keys(headers).some(function(name) {
            return name.toLowerCase() === 'content-type'
        })
    }

    function ready(promiseMethods, xhr) {
        return function handleReady() {
            if (xhr.readyState === xhr.DONE) {
                xhr.removeEventListener('readystatechange', handleReady, false)
                promiseMethods.always.apply(promiseMethods, parseResponse(xhr))

                if (xhr.status >= 200 && xhr.status < 300) {
                    promiseMethods.then.apply(promiseMethods, parseResponse(xhr))
                } else {
                    promiseMethods.catch.apply(promiseMethods, parseResponse(xhr))
                }
            }
        }
    }

    function parseResponse(xhr) {
        var result
        try {
            result = JSON.parse(xhr.responseText)
        } catch (e) {
            result = xhr.responseText
        }
        return [result, xhr]
    }

    function objectToQueryString(data) {
        return isObject(data) ? getQueryString(data) : data
    }

    function isObject(data) {
        return Object.prototype.toString.call(data) === '[object Object]'
    }

    function getQueryString(object) {
        return Object.keys(object).reduce(function(acc, item) {
            var prefix = !acc ? '' : acc + '&'
            return prefix + encode(item) + '=' + encode(object[item])
        }, '')
    }

    function encode(value) {
        return encodeURIComponent(value)
    }

    return ajax
});

(function() {
    // ============= Angular modules- Start =============
    'use strict';

    if (typeof module !== 'undefined' && module.exports) {
        module.exports.inject = function(conf) {
            return new ContextVssal(conf);
        };
    }

    if (angular) {

        var vssalModule = angular.module('vssalAngular', []);

        vssalModule.provider('vssalAuthenticationService', function() {
            var _vssal = null;
            var _oauthData = { isAuthenticated: false, userName: '', loginError: '', profile: '' };

            var updateDataFromCache = function() {
                // only cache lookup here to not interrupt with events
                _vssal.getCachedToken().then(function(token) {
                    _oauthData.isAuthenticated = token !== null && token.length > 0;
                    if (_oauthData.isAuthenticated)
                        _vssal.getCachedUser().then(function(CachedUser) {
                            var user = CachedUser || { userName: '' };
                            _oauthData.userName = user.userName;
                            _oauthData.profile = user.profile;
                        });
                });
            };

            this.init = function(configOptions, httpProvider) {
                if (configOptions) {
                    // redirect and logout_redirect are set to current location by default
                    var existingHash = window.location.hash;
                    var pathDefault = window.location.href;
                    if (existingHash) {
                        pathDefault = pathDefault.replace(existingHash, '');
                    }
                    configOptions.redirectUri = configOptions.redirectUri || pathDefault;
                    configOptions.postLogoutRedirectUri = configOptions.postLogoutRedirectUri || pathDefault;
                    configOptions.isAngular = true;

                    if (httpProvider && httpProvider.interceptors) {
                        httpProvider.interceptors.push('ProtectedResourceInterceptor');
                    }

                    // create instance with given config
                    _vssal = new ContextVssal(configOptions);
                } else {
                    throw new Error('You must set configOptions, when calling init');
                }
                updateDataFromCache();
            };

            // special function that exposes methods in Angular controller
            // $rootScope, $window, $q, $location, $timeout are injected by Angular
            this.$get = ['$rootScope', '$window', '$q', '$location', '$timeout', '$injector', function($rootScope, $window, $q, $location, $timeout, $injector) {

                var locationChangeHandler = function(event, newUrl, oldUrl) {

                    _vssal.verbose('Location change event from ' + oldUrl + ' to ' + newUrl);
                    var hash = $window.location.hash;

                    if (_vssal.isCallback(hash)) {

                        // callback can come from login or iframe request
                        _vssal.verbose('Processing the hash: ' + hash);

                        if (!_oauthData.isAuthenticated) {

                            // id_token is expired or not present
                            var self = $injector.get('vssalAuthenticationService');
                            self.acquireToken().then(function(token) {
                                if (token && _oauthData.userName) {
                                    _oauthData.isAuthenticated = true;
                                    $rootScope.$broadcast('vssal:loginSuccess', _vssal._getItem(_vssal.CONSTANTS.STORAGE.ACCESS_TOKEN));
                                } else {
                                    $rootScope.$broadcast('vssal:loginFailure', _vssal._getItem(_vssal.CONSTANTS.STORAGE.ERROR_DESCRIPTION), _vssal._getItem(_vssal.CONSTANTS.STORAGE.ERROR));
                                }
                            });
                        }
                    }
                };

                var loginHandler = function() {
                    _vssal.info('Login event for:' + $location.$$url);
                    if (_vssal.config && _vssal.config.localLoginUrl) {
                        $location.path(_vssal.config.localLoginUrl);
                    } else {
                        // directly start login flow
                        _vssal.info('Start login at:' + window.location.href);
                        $rootScope.$broadcast('vssal:loginRedirect');
                        _vssal.login();
                    }
                };

                function isVSOLoginRequired(route, global) {
                    return global.requireVSOLogin ? route.requireVSOLogin !== false : !!route.requireVSOLogin;
                }

                function getStates(toState) {
                    var state = null;
                    var states = [];
                    if (toState.hasOwnProperty('parent')) {
                        state = toState;
                        while (state) {
                            states.unshift(state);
                            state = $injector.get('$state').get(state.parent);
                        }
                    } else {
                        var stateNames = toState.name.split('.');
                        for (var i = 0, stateName = stateNames[0]; i < stateNames.length; i++) {
                            state = $injector.get('$state').get(stateName);
                            if (state) {
                                states.push(state);
                            }
                            stateName += '.' + stateNames[i + 1];
                        }
                    }
                    return states;
                }

                var routeChangeHandler = function(e, nextRoute) {
                    if (nextRoute && nextRoute.$$route) {
                        if (isVSOLoginRequired(nextRoute.$$route, _vssal.config)) {
                            if (!_oauthData.isAuthenticated) {
                                if (!_vssal.loginInProgress()) {
                                    _vssal.info('Route change event for:' + $location.$$url);
                                    loginHandler();
                                }
                            }
                        } else {
                            var nextRouteUrl;
                            if (typeof nextRoute.$$route.templateUrl === "function") {
                                nextRouteUrl = nextRoute.$$route.templateUrl(nextRoute.params);
                            } else {
                                nextRouteUrl = nextRoute.$$route.templateUrl;
                            }
                        }
                    }
                };

                var stateChangeHandler = function(e, toState, toParams, fromState, fromParams) {
                    if (toState) {
                        var states = getStates(toState);
                        var state = null;
                        for (var i = 0; i < states.length; i++) {
                            state = states[i];
                            if (isVSOLoginRequired(state, _vssal.config)) {
                                if (!_oauthData.isAuthenticated) {
                                    if (!_vssal._renewActive && !_vssal.loginInProgress()) {
                                        _vssal.info('State change event for:' + $location.$$url);
                                        loginHandler();
                                    }
                                }
                            } else if (state.templateUrl) {
                                var nextStateUrl;
                                if (typeof state.templateUrl === 'function') {
                                    nextStateUrl = state.templateUrl(toParams);
                                } else {
                                    nextStateUrl = state.templateUrl;
                                }
                            }
                        }
                    }
                };

                var stateChangeErrorHandler = function(event, toState, toParams, fromState, fromParams, error) {
                    _vssal.verbose("State change error occured. Error: " + JSON.stringify(error));

                    // vssal interceptor sets the error on config.data property. If it is set, it means state change is rejected by vssal,
                    // in which case set the defaultPrevented to true to avoid url update as that sometimesleads to infinte loop.
                    if (error && error.data) {
                        _vssal.info("Setting defaultPrevented to true if state change error occured because vssal rejected a request. Error: " + error.data);
                        event.preventDefault();
                    }
                };

                // Route change event tracking to receive fragment and also auto renew tokens
                $rootScope.$on('$routeChangeStart', routeChangeHandler);

                $rootScope.$on('$stateChangeStart', stateChangeHandler);

                $rootScope.$on('$locationChangeStart', locationChangeHandler);

                $rootScope.$on('$stateChangeError', stateChangeErrorHandler);

                $rootScope.userInfo = _oauthData;

                return {
                    // public methods will be here that are accessible from Controller
                    config: _vssal.config,
                    promise: _vssal.promise,
                    getUrlResourceTenant: function() {
                        return _vssal.getUrlResourceTenant();
                    },
                    login: function() {
                        _vssal.login();
                    },
                    loginInProgress: function() {
                        return _vssal.loginInProgress();
                    },
                    logOut: function() {
                        _vssal.logOut();
                        //call signout related method
                    },
                    getCachedToken: function() {
                        return _vssal.getCachedToken();
                    },
                    userInfo: _oauthData,
                    acquireToken: function() {
                        // automated token request call
                        var deferred = $q.defer();
                        _vssal.acquireToken().then(function(tokenOut) {
                            if (!tokenOut) {
                                $rootScope.$broadcast('vssal:acquireTokenFailure');
                                _vssal.error('Error when acquiring token');
                                deferred.reject("Error when acquiring token");
                            } else {
                                $rootScope.$broadcast('vssal:acquireTokenSuccess', tokenOut);
                                deferred.resolve(tokenOut);
                            }
                        });
                        return deferred.promise;
                    },
                    getUser: function() {
                        var deferred = $q.defer();
                        _vssal.getUser(function(error, user) {
                            if (error) {
                                _vssal.error('Error when getting user', error);
                                deferred.reject(error);
                            } else {
                                deferred.resolve(user);
                            }
                        });
                        return deferred.promise;
                    },
                    clearCache: function() {
                        _vssal.clearCache();
                    },
                    info: function(message) {
                        _vssal.info(message);
                    },
                    verbose: function(message) {
                        _vssal.verbose(message);
                    }
                };
            }];
        });

        vssalModule.provider('vssalVisualStudioService', function() {
            // special function that exposes methods in Angular controller
            // $rootScope, $window, $q, $location, $timeout are injected by Angular
            this.$get = ['$rootScope', '$window', '$q', '$http', '$location', '$timeout', '$injector', 'vssalAuthenticationService', function($rootScope, $window, $q, $http, $location, $timeout, $injector, vssalAuthenticationService) {
                var _vssalVisualStudioService = {};
                _vssalVisualStudioService.GetMyProfile = function() {
                    return vssalAuthenticationService.getUser();
                };
                _vssalVisualStudioService.GetProjects = function() {
                    return vssalAuthenticationService.promise({
                        AutoAuth: true,
                        method: 'get',
                        url: vssalAuthenticationService.getUrlResourceTenant() + 'DefaultCollection/_apis/projects'
                    });
                };

                return {
                    // public methods will be here that are accessible from Controller
                    GetMyProfile: function() {
                        return _vssalVisualStudioService.GetMyProfile();
                    },
                    GetProjects: function() {
                        return _vssalVisualStudioService.GetProjects();
                    }
                };
            }];
        });

        // Interceptor for http if needed
        vssalModule.factory('ProtectedResourceInterceptor', ['vssalAuthenticationService', '$q', '$rootScope', function(authService, $q, $rootScope) {

            return {
                request: function(config) {
                    if (config) {
                        config.headers = config.headers || {};

                        var tokenStored = authService.getCachedToken();
                        if (tokenStored) {
                            authService.info('Token is available for this url ' + config.url);
                            // check endpoint mapping if provided
                            config.headers.Authorization = 'Bearer ' + tokenStored;
                            return config;
                        } else {
                            // Cancel request if login is starting
                            if (authService.loginInProgress()) {
                                authService.info('login is in progress.');
                                config.data = 'login in progress, cancelling the request for ' + config.url;
                                return $q.reject(config);
                            } else {
                                // delayed request to return after iframe completes
                                var delayedRequest = $q.defer();
                                authService.acquireToken().then(function(token) {
                                    if (token && _oauthData.userName) {
                                        authService.verbose('Token is available');
                                        config.headers.Authorization = 'Bearer ' + token;
                                        delayedRequest.resolve(config);
                                    } else {
                                        delayedRequest.reject(config);
                                    }
                                });

                                return delayedRequest.promise;
                            }
                        }
                    }
                },
                responseError: function(rejection) {
                    authService.info('Getting error in the response: ' + JSON.stringify(rejection));
                    if (rejection) {
                        if (rejection.status === 401) {
                            $rootScope.$broadcast('vssal:notAuthorized', rejection);
                        } else {
                            $rootScope.$broadcast('vssal:errorResponse', rejection);
                        }
                        return $q.reject(rejection);
                    }
                }
            };
        }]);
    } else {
        console.error('Angular.JS is not included');
    }
}());