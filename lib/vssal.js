// vssalJS v0.0.1 

var ContextVssal = (function() {

    'use strict';

    /**
     * Configuration options for Authentication Context.
     * @class config
     *  @property {string} tenant - Your target tenant.
     *  @property {string} clientID - Client ID assigned to your app by Azure Active Directory.
     *  @property {string} redirectUri - Endpoint at which you expect to receive tokens.Defaults to `window.location.href`.
     *  @property {string} instance - Azure Active Directory Instance.Defaults to `https://login.microsoftonline.com/`.
     *  @property {Array} endpoints - Collection of {Endpoint-ResourceId} used for automatically attaching tokens in webApi calls.
     *  @property {Boolean} popUp - Set this to true to enable login in a popup winodow instead of a full redirect.Defaults to `false`.
     *  @property {string} localLoginUrl - Set this to redirect the user to a custom login page.
     *  @property {function} displayCall - User defined function of handling the navigation to Azure AD authorization endpoint in case of login. Defaults to 'null'.
     *  @property {string} postLogoutRedirectUri - Redirects the user to postLogoutRedirectUri after logout. Defaults to 'null'.
     *  @property {string} cacheLocation - Sets browser storage to either 'localStorage' or sessionStorage'. Defaults to 'sessionStorage'.
     *  @property {Array.<string>} anonymousEndpoints Array of keywords or URI's. vssal will not attach a token to outgoing requests that have these keywords or uri. Defaults to 'null'.
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
         * Enum for request type
         * @enum {string}
         */
        this.REQUEST_TYPE = {
            LOGIN: 'LOGIN',
            RENEW_TOKEN: 'RENEW_TOKEN',
            UNKNOWN: 'UNKNOWN'
        };

        /**
         * Enum for storage constants
         * @enum {string}
         */
        this.CONSTANTS = {

            ACCESS_TOKEN: 'access_token',
            TOKEN_TYPE: 'token_type',
            EXPIRES_IN: 'expires_in',
            REFRESH_TOKEN: 'refresh_token',
            SCOPE: 'scope',


            TOKEN: 'token',
            ERROR_DESCRIPTION: 'error_description',
            SESSION_STATE: 'session_state',
            STORAGE: {
                TOKEN_KEYS: 'vssal.token.keys',
                ACCESS_TOKEN_KEY: 'vssal.access.token.key',
                EXPIRATION_KEY: 'vssal.expiration.key',
                STATE_LOGIN: 'vssal.state.login',
                STATE_RENEW: 'vssal.state.renew',
                NONCE_IDTOKEN: 'vssal.nonce.idtoken',
                SESSION_STATE: 'vssal.session.state',
                USERNAME: 'vssal.username',
                IDTOKEN: 'vssal.idtoken',
                ERROR: 'vssal.error',
                ERROR_DESCRIPTION: 'vssal.error.description',
                LOGIN_REQUEST: 'vssal.login.request',
                LOGIN_ERROR: 'vssal.login.error',
                RENEW_STATUS: 'vssal.token.renew.status'
            },
            RESOURCE_DELIMETER: ' ',
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

        // validate before constructor assignments
        if (config.displayCall && typeof config.displayCall !== 'function') {
            throw new Error('displayCall is not a function');
        }

        if (!config.clientId) {
            throw new Error('clientId is required');
        }

        this.config = this._cloneConfig(config);

        if (this.config.popUp)
            this.popUp = true;

        if (this.config.callback && typeof this.config.callback === 'function')
            this.callback = this.config.callback;

        if (this.config.instance) {
            this.instance = this.config.instance;
        }

        // App can request idtoken for itself using clientid as resource
        if (!this.config.loginResource) {
            this.config.loginResource = this.config.clientId;
        }

        if (!this.config.redirectUri) {
            this.config.redirectUri = window.location.href;
        }

        if (!this.config.anonymousEndpoints) {
            this.config.anonymousEndpoints = [];
        }

        if (this.config.isAngular) {
            this.isAngular = this.config.isAngular;
        }
    };

    window.Logging = {
        level: 0,
        log: function(message) {}
    };

    /**
     * Initiates the login process by redirecting the user to Azure AD authorization endpoint.
     */
    ContextVssal.prototype.login = function() {
        // Token is not present and user needs to login
        if (this._loginInProgress) {
            this.info("Login in progress");
            return;
        }
        var expectedState = this._guid();
        this.config.state = expectedState;
        this._idTokenNonce = this._guid();
        this.verbose('Expected state: ' + expectedState + ' startPage:' + window.location);
        this._saveItem(this.CONSTANTS.STORAGE.LOGIN_REQUEST, window.location);
        this._saveItem(this.CONSTANTS.STORAGE.LOGIN_ERROR, '');
        this._saveItem(this.CONSTANTS.STORAGE.STATE_LOGIN, expectedState);
        this._saveItem(this.CONSTANTS.STORAGE.NONCE_IDTOKEN, this._idTokenNonce);
        this._saveItem(this.CONSTANTS.STORAGE.ERROR, '');
        this._saveItem(this.CONSTANTS.STORAGE.ERROR_DESCRIPTION, '');
        var urlNavigate = this._getNavigateUrl('Assertion', null) + '&nonce=' + encodeURIComponent(this._idTokenNonce);
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
     * Checks for the resource in the cache. By default, cache location is Session Storage
     * @ignore
     * @returns {Boolean} 'true' if login is in progress, else returns 'false'.
     */
    ContextVssal.prototype._hasResource = function(key) {
        var keys = this._getItem(this.CONSTANTS.STORAGE.TOKEN_KEYS);
        return keys && !this._isEmpty(keys) && (keys.indexOf(key + this.CONSTANTS.RESOURCE_DELIMETER) > -1);
    };

    /**
     * Gets token for the specified resource from the cache.
     * @param {string}   resource A URI that identifies the resource for which the token is requested.
     * @returns {string} token if if it exists and not expired, otherwise null.
     */
    ContextVssal.prototype.getCachedToken = function(resource) {
        if (!this._hasResource(resource)) {
            return null;
        }

        var token = this._getItem(this.CONSTANTS.STORAGE.ACCESS_TOKEN_KEY + resource);
        var expired = this._getItem(this.CONSTANTS.STORAGE.EXPIRATION_KEY + resource);

        // If expiration is within offset, it will force renew
        var offset = this.config.expireOffsetSeconds || 120;

        if (expired && (expired > this._now() + offset)) {
            return token;
        } else {
            this._saveItem(this.CONSTANTS.STORAGE.ACCESS_TOKEN_KEY + resource, '');
            this._saveItem(this.CONSTANTS.STORAGE.EXPIRATION_KEY + resource, 0);
            return null;
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
        if (this._user) {
            return this._user;
        }

        var idtoken = this._getItem(this.CONSTANTS.STORAGE.IDTOKEN);
        this._user = this._createUser(idtoken);
        return this._user;
    };

    /**
     * Adds the passed callback to the array of callbacks for the specified resource and puts the array on the window object. 
     * @param {string}   resource A URI that identifies the resource for which the token is requested.
     * @param {string}   expectedState A unique identifier (guid).
     * @param {tokenCallback} callback - The callback provided by the caller. It will be called with token or error.
     */
    ContextVssal.prototype.registerCallback = function(expectedState, resource, callback) {
        this._activeRenewals[resource] = expectedState;
        if (!window.callBacksMappedToRenewStates[expectedState]) {
            window.callBacksMappedToRenewStates[expectedState] = [];
        }
        var self = this;
        window.callBacksMappedToRenewStates[expectedState].push(callback);
        if (!window.callBackMappedToRenewStates[expectedState]) {
            window.callBackMappedToRenewStates[expectedState] = function(errorDesc, token, error) {
                for (var i = 0; i < window.callBacksMappedToRenewStates[expectedState].length; ++i) {
                    try {
                        window.callBacksMappedToRenewStates[expectedState][i](errorDesc, token, error);
                    } catch (error) {
                        self.warn(error);
                    }
                }
                self._activeRenewals[resource] = null;
                window.callBacksMappedToRenewStates[expectedState] = null;
                window.callBackMappedToRenewStates[expectedState] = null;
            };
        }
    };

    // var errorResponse = {error:'', error_description:''};
    // var token = 'string token';
    // callback(errorResponse, token)
    // with callback
    /**
     * Acquires access token with hidden iframe
     * @ignore
     */
    ContextVssal.prototype._renewToken = function(resource, callback) {
        // use iframe to try refresh token
        // use given resource to create new authz url
        this.info('renewToken is called for resource:' + resource);

        var expectedState = this._guid() + '|' + resource;
        this.config.state = expectedState;
        // renew happens in iframe, so it keeps javascript context
        this._renewStates.push(expectedState);

        this.verbose('Renew token Expected state: ' + expectedState);
        var urlNavigate = this._getNavigateUrl('token', resource);

        this.registerCallback(expectedState, resource, callback);
        this.verbose('Navigate to:' + urlNavigate);
        frameHandle.src = 'about:blank';
        this._loadFrameTimeout(urlNavigate, 'vssalRenewFrame' + resource, resource);

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
     * @param {string} error error message returned from AAD if token request fails.
     * @param {string} token token returned from AAD if token request is successful.
     */

    /**
     * Acquires token from the cache if it is not expired. Otherwise sends request to AAD to obtain a new token.
     * @param {string}   resource  ResourceUri identifying the target resource
     * @param {tokenCallback} callback -  The callback provided by the caller. It will be called with token or error.
     */
    ContextVssal.prototype.acquireToken = function(resource, callback) {
        if (this._isEmpty(resource)) {
            this.warn('resource is required');
            callback('resource is required', null, 'resource is required');
            return;
        }

        var token = this.getCachedToken(resource);
        if (token) {
            this.info('Token is already in cache for resource:' + resource);
            callback(null, token, null);
            return;
        }

        if (!this._user) {
            this.warn('User login is required');
            callback('User login is required', null, 'login required');
            return;
        }

        // refresh attept with iframe
        //Already renewing for this resource, callback when we get the token.
        if (this._activeRenewals[resource]) {
            //Active renewals contains the state for each renewal.
            this.registerCallback(this._activeRenewals[resource], resource, callback);
        } else {
            if (resource === this.config.clientId) {
                // App uses idtoken to send to api endpoints
                // Default resource is tracked as clientid to store this token 
                this._renewToken(resource, callback);
            }
        }
    };

    /**
     * Redirects the browser to Azure AD authorization endpoint.
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
        this._saveItem(this.CONSTANTS.STORAGE.ACCESS_TOKEN_KEY, '');
        this._saveItem(this.CONSTANTS.STORAGE.EXPIRATION_KEY, 0);
        this._saveItem(this.CONSTANTS.STORAGE.SESSION_STATE, '');
        this._saveItem(this.CONSTANTS.STORAGE.STATE_LOGIN, '');
        this._renewStates = [];
        this._saveItem(this.CONSTANTS.STORAGE.USERNAME, '');
        this._saveItem(this.CONSTANTS.STORAGE.IDTOKEN, '');
        this._saveItem(this.CONSTANTS.STORAGE.ERROR, '');
        this._saveItem(this.CONSTANTS.STORAGE.ERROR_DESCRIPTION, '');
        var keys = this._getItem(this.CONSTANTS.STORAGE.TOKEN_KEYS);

        if (!this._isEmpty(keys)) {
            keys = keys.split(this.CONSTANTS.RESOURCE_DELIMETER);
            for (var i = 0; i < keys.length; i++) {
                this._saveItem(this.CONSTANTS.STORAGE.ACCESS_TOKEN_KEY + keys[i], '');
                this._saveItem(this.CONSTANTS.STORAGE.EXPIRATION_KEY + keys[i], 0);
            }
        }
        this._saveItem(this.CONSTANTS.STORAGE.TOKEN_KEYS, '');
    };

    /**
     * Clears cache items for a given resource.
     * @param {string}  resource a URI that identifies the resource.
     */
    ContextVssal.prototype.clearCacheForResource = function(resource) {
        this._saveItem(this.CONSTANTS.STORAGE.STATE_RENEW, '');
        this._saveItem(this.CONSTANTS.STORAGE.ERROR, '');
        this._saveItem(this.CONSTANTS.STORAGE.ERROR_DESCRIPTION, '');
        if (this._hasResource(resource)) {
            this._saveItem(this.CONSTANTS.STORAGE.ACCESS_TOKEN_KEY + resource, '');
            this._saveItem(this.CONSTANTS.STORAGE.EXPIRATION_KEY + resource, 0);
        }
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
            urlNavigate = 'https://app.vsaex.visualstudio.com/_signout';
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
        // IDToken is first call
        if (typeof callback !== 'function') {
            throw new Error('callback is not a function');
        }

        // user in memory
        if (this._user) {
            callback(null, this._user);
            return;
        }

        // frame is used to get idtoken
        var idtoken = this._getItem(this.CONSTANTS.STORAGE.IDTOKEN);
        if (!this._isEmpty(idtoken)) {
            this.info('User exists in cache: ');
            this._user = this._createUser(idtoken);
            callback(null, this._user);
        } else {
            this.warn('User information is not available');
            callback('User information is not available', null);
        }
    };


    /**
     * Creates a user object by decoding the token
     * @ignore
     */
    ContextVssal.prototype._createUser = function(idToken) {
        var user = null;
        var parsedJson = this._extractToken(idToken);
        if (parsedJson && parsedJson.hasOwnProperty('aud')) {
            if (parsedJson.aud.toLowerCase() === this.config.clientId.toLowerCase()) {

                user = {
                    userName: '',
                    profile: parsedJson
                };

                if (parsedJson.hasOwnProperty('upn')) {
                    user.userName = parsedJson.upn;
                } else if (parsedJson.hasOwnProperty('email')) {
                    user.userName = parsedJson.email;
                }
            } else {
                this.warn('IdToken has invalid aud field');
            }

        }

        return user;
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
        hash = this._getHash(hash);
        var parameters = this._deserialize(hash);
        return (
            parameters.hasOwnProperty(this.CONSTANTS.ERROR_DESCRIPTION) ||
            parameters.hasOwnProperty(this.CONSTANTS.ACCESS_TOKEN) ||
            parameters.hasOwnProperty(this.CONSTANTS.TOKEN)
        );
    };

    /**
     * Gets login error
     * @returns {string} error message related to login.
     */
    ContextVssal.prototype.getLoginError = function() {
        return this._getItem(this.CONSTANTS.STORAGE.LOGIN_ERROR);
    };

    /**
     * Request info object created from the response received from AAD.
     *  @class RequestInfo
     *  @property {object} parameters - object comprising of fields such as token/error, session_state, state, e.t.c.
     *  @property {REQUEST_TYPE} requestType - either LOGIN, RENEW_TOKEN or UNKNOWN.
     *  @property {boolean} stateMatch - true if state is valid, false otherwise.
     *  @property {string} stateResponse - unique guid used to match the response with the request.
     *  @property {boolean} valid - true if requestType contains token, access_token or error, false otherwise.
     */

    /**
     * Creates a requestInfo object from the URL fragment and returns it.
     * @returns {RequestInfo} an object created from the redirect response from AAD comprising of the keys - parameters, requestType, stateMatch, stateResponse and valid.
     */
    ContextVssal.prototype.getRequestInfo = function(hash) {
        hash = this._getHash(hash);
        var parameters = this._deserialize(hash);
        var requestInfo = {
            valid: false,
            parameters: {},
            stateMatch: false,
            stateResponse: '',
            requestType: this.REQUEST_TYPE.UNKNOWN
        };
        if (parameters) {
            requestInfo.parameters = parameters;
            if (parameters.hasOwnProperty(this.CONSTANTS.ERROR_DESCRIPTION) ||
                parameters.hasOwnProperty(this.CONSTANTS.ACCESS_TOKEN) ||
                parameters.hasOwnProperty(this.CONSTANTS.REFRESH_TOKEN)) {

                requestInfo.valid = true;
                requestInfo.requestType = this.REQUEST_TYPE.LOGIN;
                return requestInfo;
            }
        }

        return requestInfo;
    };

    /**
     * Extracts resource value from state.
     * @ignore
     */
    ContextVssal.prototype._getResourceFromState = function(state) {
        if (state) {
            var splitIndex = state.indexOf('|');
            if (splitIndex > -1 && splitIndex + 1 < state.length) {
                return state.substring(splitIndex + 1);
            }
        }

        return '';
    };

    /**
     * Saves token or error received in the response from AAD in the cache. In case of token, it also creates the user object.
     */
    ContextVssal.prototype.saveTokenFromHash = function(requestInfo) {
        this.info('State status:' + requestInfo.stateMatch + '; Request type:' + requestInfo.requestType);
        this._saveItem(this.CONSTANTS.STORAGE.ERROR, '');
        this._saveItem(this.CONSTANTS.STORAGE.ERROR_DESCRIPTION, '');

        var resource = this._getResourceFromState(requestInfo.stateResponse);

        // Record error
        if (requestInfo.parameters.hasOwnProperty(this.CONSTANTS.ERROR_DESCRIPTION)) {
            this.info('Error :' + requestInfo.parameters.error + '; Error description:' + requestInfo.parameters[this.CONSTANTS.ERROR_DESCRIPTION]);
            this._saveItem(this.CONSTANTS.STORAGE.ERROR, requestInfo.parameters.error);
            this._saveItem(this.CONSTANTS.STORAGE.ERROR_DESCRIPTION, requestInfo.parameters[this.CONSTANTS.ERROR_DESCRIPTION]);

            if (requestInfo.requestType === this.REQUEST_TYPE.LOGIN) {
                this._loginInProgress = false;
                this._saveItem(this.CONSTANTS.STORAGE.LOGIN_ERROR, requestInfo.parameters.error_description);
            }
        } else {
            // It must verify the state from redirect
            if (requestInfo.stateMatch) {
                // record tokens to storage if exists
                this.info('State is right');
                if (requestInfo.parameters.hasOwnProperty(this.CONSTANTS.SESSION_STATE)) {
                    this._saveItem(this.CONSTANTS.STORAGE.SESSION_STATE, requestInfo.parameters[this.CONSTANTS.SESSION_STATE]);
                }

                var keys;

                if (requestInfo.parameters.hasOwnProperty(this.CONSTANTS.ACCESS_TOKEN)) {
                    this.info('Fragment has access token');

                    if (!this._hasResource(resource)) {
                        keys = this._getItem(this.CONSTANTS.STORAGE.TOKEN_KEYS) || '';
                        this._saveItem(this.CONSTANTS.STORAGE.TOKEN_KEYS, keys + resource + this.CONSTANTS.RESOURCE_DELIMETER);
                    }
                    // save token with related resource
                    this._saveItem(this.CONSTANTS.STORAGE.ACCESS_TOKEN_KEY + resource, requestInfo.parameters[this.CONSTANTS.ACCESS_TOKEN]);
                    this._saveItem(this.CONSTANTS.STORAGE.EXPIRATION_KEY + resource, this._expiresIn(requestInfo.parameters[this.CONSTANTS.EXPIRES_IN]));
                }

                if (requestInfo.parameters.hasOwnProperty(this.CONSTANTS.TOKEN)) {
                    this.info('Fragment has id token');
                    this._loginInProgress = false;

                    this._user = this._createUser(requestInfo.parameters[this.CONSTANTS.TOKEN]);

                    if (this._user && this._user.profile) {
                        if (this._user.profile.nonce !== this._getItem(this.CONSTANTS.STORAGE.NONCE_IDTOKEN)) {
                            this._user = null;
                            this._saveItem(this.CONSTANTS.STORAGE.LOGIN_ERROR, 'Nonce is not same as ' + this._idTokenNonce);
                        } else {
                            this._saveItem(this.CONSTANTS.STORAGE.IDTOKEN, requestInfo.parameters[this.CONSTANTS.TOKEN]);

                            // Save idtoken as access token for app itself
                            resource = this.config.loginResource ? this.config.loginResource : this.config.clientId;

                            if (!this._hasResource(resource)) {
                                keys = this._getItem(this.CONSTANTS.STORAGE.TOKEN_KEYS) || '';
                                this._saveItem(this.CONSTANTS.STORAGE.TOKEN_KEYS, keys + resource + this.CONSTANTS.RESOURCE_DELIMETER);
                            }
                            this._saveItem(this.CONSTANTS.STORAGE.ACCESS_TOKEN_KEY + resource, requestInfo.parameters[this.CONSTANTS.TOKEN]);
                            this._saveItem(this.CONSTANTS.STORAGE.EXPIRATION_KEY + resource, this._user.profile.exp);
                        }
                    } else {
                        this._saveItem(this.CONSTANTS.STORAGE.ERROR, 'invalid token');
                        this._saveItem(this.CONSTANTS.STORAGE.ERROR_DESCRIPTION, 'Invalid token. token: ' + requestInfo.parameters[this.CONSTANTS.TOKEN]);
                    }
                }
            } else {
                this._saveItem(this.CONSTANTS.STORAGE.ERROR, 'Invalid_state');
                this._saveItem(this.CONSTANTS.STORAGE.ERROR_DESCRIPTION, 'Invalid_state. state: ' + requestInfo.stateResponse);
            }
        }
        this._saveItem(this.CONSTANTS.STORAGE.RENEW_STATUS + resource, this.CONSTANTS.TOKEN_RENEW_STATUS_COMPLETED);
    };

    /**
     * Gets resource for given endpoint if mapping is provided with config.
     * @param {string} endpoint  -  The URI for which the resource Id is requested.
     * @returns {string} resource for this API endpoint.
     */
    ContextVssal.prototype.getResourceForEndpoint = function(endpoint) {
        if (this.config && this.config.endpoints) {
            for (var configEndpoint in this.config.endpoints) {
                // configEndpoint is like /api/Todo requested endpoint can be /api/Todo/1
                if (endpoint.indexOf(configEndpoint) > -1) {
                    return this.config.endpoints[configEndpoint];
                }
            }
        }

        // default resource will be clientid if nothing specified
        // App will use idtoken for calls to itself
        // check if it's staring from http or https, needs to match with app host
        if (endpoint.indexOf('http://') > -1 || endpoint.indexOf('https://') > -1) {
            if (this._getHostFromUri(endpoint) === this._getHostFromUri(this.config.redirectUri)) {
                return this.config.loginResource;
            }
        }
        // in angular level, the url for $http interceptor call could be relative url,
        // if it's relative call, we'll treat it as app backend call.
        else {
            // if user specified list of anonymous endpoints, no need to send token to these endpoints, return null.
            if (this.config && this.config.anonymousEndpoints) {
                for (var i = 0; i < this.config.anonymousEndpoints.length; i++) {
                    if (endpoint.indexOf(this.config.anonymousEndpoints[i]) > -1) {
                        return null;
                    }
                }
            }
            // all other app's backend calls are secured.
            return this.config.loginResource;
        }

        // if not the app's own backend or not a domain listed in the endpoints structure
        return null;
    };

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
     * This method must be called for processing the response received from AAD. It extracts the hash, processes the token or error, saves it in the cache and calls the registered callbacks with the result.
     * @param {string} [hash=window.location.hash] - Hash fragment of Url.
     */
    ContextVssal.prototype.handleWindowCallback = function(hash) {
        // This is for regular javascript usage for redirect handling
        // need to make sure this is for callback
        if (hash == null)
            hash = window.location.hash;
        if (this.isCallback(hash)) {
            var requestInfo = this.getRequestInfo(hash);
            this.info('Returned from redirect url');
            this.saveTokenFromHash(requestInfo);
            var callback = null;
            if (requestInfo.requestType === this.REQUEST_TYPE.LOGIN) {
                callback = this.callback;
                if (callback)
                    callback(this._getItem(this.CONSTANTS.STORAGE.ERROR_DESCRIPTION), requestInfo.parameters[this.CONSTANTS.ACCESS_TOKEN], this._getItem(this.CONSTANTS.STORAGE.ERROR));
            }
            if (!this.popUp) // No need to redirect user in case of popup
                window.location = this._getItem(this.CONSTANTS.STORAGE.LOGIN_REQUEST);
        }
    };

    /**
     * Constructs the authorization endpoint URL and returns it.
     * @ignore
     */
    ContextVssal.prototype._getNavigateUrl = function(responseType, scope) {
        var urlNavigate = this.instance + '/oauth2/authorize' + this._serialize(responseType, this.config, scope);
        this.info('Navigate url:' + urlNavigate);
        return urlNavigate;
    };

    /**
     * Returns the decoded token.
     * @ignore
     */
    ContextVssal.prototype._extractToken = function(encodedIdToken) {
        // id token will be decoded to get the username
        var decodedToken = this._decodeJwt(encodedIdToken);
        if (!decodedToken) {
            return null;
        }

        try {
            var base64IdToken = decodedToken.JWSPayload;
            var base64Decoded = this._base64DecodeStringUrlSafe(base64IdToken);
            if (!base64Decoded) {
                this.info('The returned token could not be base64 url safe decoded.');
                return null;
            }

            // ECMA script has JSON built-in support
            return JSON.parse(base64Decoded);
        } catch (err) {
            this.error('The returned token could not be decoded', err);
        }

        return null;
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

    //Take https://cdnjs.cloudflare.com/ajax/libs/Base64/0.3.0/base64.js and https://en.wikipedia.org/wiki/Base64 as reference. 
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
     * Decodes an id token into an object with header, payload and signature fields.
     * @ignore
     */
    // vssal.node js crack function
    ContextVssal.prototype._decodeJwt = function(jwtToken) {
        if (this._isEmpty(jwtToken)) {
            return null;
        };

        var PartsRegex = /^([^\.\s]*)\.([^\.\s]+)\.([^\.\s]*)$/;

        var matches = PartsRegex.exec(jwtToken);
        if (!matches || matches.length < 4) {
            this.warn('The returned token is not parseable.');
            return null;
        }

        var crackedToken = {
            header: matches[1],
            JWSPayload: matches[2],
            JWSSig: matches[3]
        };

        return crackedToken;
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
            }
            str.push('redirect_uri=' + encodeURIComponent(obj.redirectUri));
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

    /**
     * Generates RFC4122 version 4 guid (128 bits)
     * @ignore
     */
    /* jshint ignore:start */
    ContextVssal.prototype._guid = function() {
        // RFC4122: The version 4 UUID is meant for generating UUIDs from truly-random or
        // pseudo-random numbers.
        // The algorithm is as follows:
        //     Set the two most significant bits (bits 6 and 7) of the
        //        clock_seq_hi_and_reserved to zero and one, respectively.
        //     Set the four most significant bits (bits 12 through 15) of the
        //        time_hi_and_version field to the 4-bit version number from
        //        Section 4.1.3. Version4
        //     Set all the other bits to randomly (or pseudo-randomly) chosen
        //     values.
        // UUID                   = time-low "-" time-mid "-"time-high-and-version "-"clock-seq-reserved and low(2hexOctet)"-" node
        // time-low               = 4hexOctet
        // time-mid               = 2hexOctet
        // time-high-and-version  = 2hexOctet
        // clock-seq-and-reserved = hexOctet:
        // clock-seq-low          = hexOctet
        // node                   = 6hexOctet
        // Format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
        // y could be 1000, 1001, 1010, 1011 since most significant two bits needs to be 10
        // y values are 8, 9, A, B
        var cryptoObj = window.crypto || window.msCrypto; // for IE 11
        if (cryptoObj && cryptoObj.getRandomValues) {
            var buffer = new Uint8Array(16);
            cryptoObj.getRandomValues(buffer);
            //buffer[6] and buffer[7] represents the time_hi_and_version field. We will set the four most significant bits (4 through 7) of buffer[6] to represent decimal number 4 (UUID version number).
            buffer[6] |= 0x40; //buffer[6] | 01000000 will set the 6 bit to 1.
            buffer[6] &= 0x4f; //buffer[6] & 01001111 will set the 4, 5, and 7 bit to 0 such that bits 4-7 == 0100 = "4".
            //buffer[8] represents the clock_seq_hi_and_reserved field. We will set the two most significant bits (6 and 7) of the clock_seq_hi_and_reserved to zero and one, respectively.
            buffer[8] |= 0x80; //buffer[8] | 10000000 will set the 7 bit to 1.
            buffer[8] &= 0xbf; //buffer[8] & 10111111 will set the 6 bit to 0.
            return this._decimalToHex(buffer[0]) + this._decimalToHex(buffer[1]) + this._decimalToHex(buffer[2]) + this._decimalToHex(buffer[3]) + '-' + this._decimalToHex(buffer[4]) + this._decimalToHex(buffer[5]) + '-' + this._decimalToHex(buffer[6]) + this._decimalToHex(buffer[7]) + '-' +
                this._decimalToHex(buffer[8]) + this._decimalToHex(buffer[9]) + '-' + this._decimalToHex(buffer[10]) + this._decimalToHex(buffer[11]) + this._decimalToHex(buffer[12]) + this._decimalToHex(buffer[13]) + this._decimalToHex(buffer[14]) + this._decimalToHex(buffer[15]);
        } else {
            var guidHolder = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx';
            var hex = '0123456789abcdef';
            var r = 0;
            var guidResponse = "";
            for (var i = 0; i < 36; i++) {
                if (guidHolder[i] !== '-' && guidHolder[i] !== '4') {
                    // each x and y needs to be random
                    r = Math.random() * 16 | 0;
                }
                if (guidHolder[i] === 'x') {
                    guidResponse += hex[r];
                } else if (guidHolder[i] === 'y') {
                    // clock-seq-and-reserved first hex is filtered and remaining hex values are random
                    r &= 0x3; // bit and with 0011 to set pos 2 to zero ?0??
                    r |= 0x8; // set pos 3 to 1 as 1???
                    guidResponse += hex[r];
                } else {
                    guidResponse += guidHolder[i];
                }
            }
            return guidResponse;
        }
    };
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