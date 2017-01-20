// vssalJS v0.0.1

(function() {
    // ============= Angular modules- Start =============
    'use strict';

    if (typeof module !== 'undefined' && module.exports) {
        module.exports.inject = function(conf) {
            return new Context(conf);
        };
    }

    if (angular) {

        var vssalModule = angular.module('vssalAngular', []);

        vssalModule.provider('vssalAuthenticationService', function() {
            var _vssal = null;
            var _oauthData = { isAuthenticated: false, userName: '', loginError: '', profile: '' };

            var updateDataFromCache = function(resource) {
                // only cache lookup here to not interrupt with events
                var token = _vssal.getCachedToken(resource);
                _oauthData.isAuthenticated = token !== null && token.length > 0;
                var user = _vssal.getCachedUser() || { userName: '' };
                _oauthData.userName = user.userName;
                _oauthData.profile = user.profile;
                _oauthData.loginError = _vssal.getLoginError();
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
                    _vssal = new Context(configOptions);
                } else {
                    throw new Error('You must set configOptions, when calling init');
                }

                // loginResource is used to set authenticated status
                updateDataFromCache(_vssal.config.loginResource);
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
                        var requestInfo = _vssal.getRequestInfo(hash);
                        _vssal.saveTokenFromHash(requestInfo);

                        // Return to callback if it is sent from iframe
                        if (requestInfo.stateMatch) {
                            if (requestInfo.requestType === _vssal.REQUEST_TYPE.RENEW_TOKEN) {
                                var callback = $window.parent.callBackMappedToRenewStates[requestInfo.stateResponse];
                                // since this is a token renewal request in iFrame, we don't need to proceed with the location change.
                                event.preventDefault();

                                // Call within the same context without full page redirect keeps the callback
                                if (callback && typeof callback === 'function') {
                                    // id_token or access_token can be renewed
                                    if (requestInfo.parameters['access_token']) {
                                        callback(_vssal._getItem(_vssal.CONSTANTS.STORAGE.ERROR_DESCRIPTION), requestInfo.parameters['access_token'], _vssal._getItem(_vssal.CONSTANTS.STORAGE.ERROR));
                                        return;
                                    } else if (requestInfo.parameters['id_token']) {
                                        callback(_vssal._getItem(_vssal.CONSTANTS.STORAGE.ERROR_DESCRIPTION), requestInfo.parameters['id_token'], _vssal._getItem(_vssal.CONSTANTS.STORAGE.ERROR));
                                        return;
                                    } else if (requestInfo.parameters['error']) {
                                        callback(_vssal._getItem(_vssal.CONSTANTS.STORAGE.ERROR_DESCRIPTION), null, _vssal._getItem(_vssal.CONSTANTS.STORAGE.ERROR));
                                        return;
                                    }
                                }
                            } else if (requestInfo.requestType === _vssal.REQUEST_TYPE.LOGIN) {
                                // normal full login redirect happened on the page
                                updateDataFromCache(_vssal.config.loginResource);
                                if (_oauthData.userName) {
                                    $timeout(function() {
                                        // id_token is added as token for the app
                                        updateDataFromCache(_vssal.config.loginResource);
                                        $rootScope.userInfo = _oauthData;
                                    }, 1);

                                    $rootScope.$broadcast('vssal:loginSuccess', _vssal._getItem(_vssal.CONSTANTS.STORAGE.IDTOKEN));
                                } else {
                                    $rootScope.$broadcast('vssal:loginFailure', _vssal._getItem(_vssal.CONSTANTS.STORAGE.ERROR_DESCRIPTION), _vssal._getItem(_vssal.CONSTANTS.STORAGE.ERROR));
                                }

                                if (_vssal.callback && typeof _vssal.callback === 'function')
                                    _vssal.callback(_vssal._getItem(_vssal.CONSTANTS.STORAGE.ERROR_DESCRIPTION), _vssal._getItem(_vssal.CONSTANTS.STORAGE.IDTOKEN), _vssal._getItem(_vssal.CONSTANTS.STORAGE.ERROR));

                                // redirect to login start page
                                if (!_vssal.popUp) {
                                    var loginStartPage = _vssal._getItem(_vssal.CONSTANTS.STORAGE.LOGIN_REQUEST);
                                    if (typeof loginStartPage !== 'undefined' && loginStartPage && loginStartPage.length !== 0) {
                                        // prevent the current location change and redirect the user back to the login start page
                                        _vssal.verbose('Redirecting to start page: ' + loginStartPage);
                                        if (!$location.$$html5 && loginStartPage.indexOf('#') > -1) {
                                            $location.url(loginStartPage.substring(loginStartPage.indexOf('#') + 1));
                                        }
                                        $window.location = loginStartPage;
                                    }
                                } else
                                    event.preventDefault();
                            }
                        } else {
                            // state did not match, broadcast an error
                            $rootScope.$broadcast('vssal:stateMismatch', _vssal._getItem(_vssal.CONSTANTS.STORAGE.ERROR_DESCRIPTION), _vssal._getItem(_vssal.CONSTANTS.STORAGE.ERROR));
                        }
                    } else {
                        // No callback. App resumes after closing or moving to new page.
                        // Check token and username
                        updateDataFromCache(_vssal.config.loginResource);
                        if (!_oauthData.isAuthenticated && _oauthData.userName && !_vssal._renewActive) {
                            // id_token is expired or not present
                            var self = $injector.get('vssalAuthenticationService');
                            self.acquireToken(_vssal.config.loginResource).then(function(token) {
                                if (token) {
                                    _oauthData.isAuthenticated = true;
                                }
                            }, function(error) {
                                var errorParts = error.split('|');
                                $rootScope.$broadcast('vssal:loginFailure', errorParts[0], errorParts[1]);
                            });
                        }
                    }

                    $timeout(function() {
                        updateDataFromCache(_vssal.config.loginResource);
                        $rootScope.userInfo = _oauthData;
                    }, 1);
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

                function isADLoginRequired(route, global) {
                    return global.requireVSOLogin ? route.requireVSOLogin !== false : !!route.requireVSOLogin;
                }

                function isAnonymousEndpoint(url) {
                    if (_vssal.config && _vssal.config.anonymousEndpoints) {
                        for (var i = 0; i < _vssal.config.anonymousEndpoints.length; i++) {
                            if (url.indexOf(_vssal.config.anonymousEndpoints[i]) > -1) {
                                return true;
                            }
                        }
                    }
                    return false;
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
                        if (isADLoginRequired(nextRoute.$$route, _vssal.config)) {
                            if (!_oauthData.isAuthenticated) {
                                if (!_vssal._renewActive && !_vssal.loginInProgress()) {
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
                            if (nextRouteUrl && !isAnonymousEndpoint(nextRouteUrl)) {
                                _vssal.config.anonymousEndpoints.push(nextRouteUrl);
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
                            if (isADLoginRequired(state, _vssal.config)) {
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
                                if (nextStateUrl && !isAnonymousEndpoint(nextStateUrl)) {
                                    _vssal.config.anonymousEndpoints.push(nextStateUrl);
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

                updateDataFromCache(_vssal.config.loginResource);
                $rootScope.userInfo = _oauthData;

                return {
                    // public methods will be here that are accessible from Controller
                    config: _vssal.config,
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
                    getCachedToken: function(resource) {
                        return _vssal.getCachedToken(resource);
                    },
                    userInfo: _oauthData,
                    acquireToken: function(resource) {
                        // automated token request call
                        var deferred = $q.defer();
                        _vssal._renewActive = true;
                        _vssal.acquireToken(resource, function(errorDesc, tokenOut, error) {
                            _vssal._renewActive = false;
                            if (error) {
                                $rootScope.$broadcast('vssal:acquireTokenFailure', errorDesc, error);
                                _vssal.error('Error when acquiring token for resource: ' + resource, error);
                                deferred.reject(errorDesc + "|" + error);
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
                    getResourceForEndpoint: function(endpoint) {
                        return _vssal.getResourceForEndpoint(endpoint);
                    },
                    clearCache: function() {
                        _vssal.clearCache();
                    },
                    clearCacheForResource: function(resource) {
                        _vssal.clearCacheForResource(resource);
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

        // Interceptor for http if needed
        vssalModule.factory('ProtectedResourceInterceptor', ['vssalAuthenticationService', '$q', '$rootScope', function(authService, $q, $rootScope) {

            return {
                request: function(config) {
                    if (config) {

                        config.headers = config.headers || {};
                        var resource = authService.getResourceForEndpoint(config.url);
                        authService.verbose('Url: ' + config.url + ' maps to resource: ' + resource);
                        if (resource === null) {
                            return config;
                        }
                        var tokenStored = authService.getCachedToken(resource);
                        if (tokenStored) {
                            authService.info('Token is available for this url ' + config.url);
                            // check endpoint mapping if provided
                            config.headers.Authorization = 'Bearer ' + tokenStored;
                            return config;
                        } else {
                            // Cancel request if login is starting
                            if (authService.loginInProgress()) {
                                if (authService.config.popUp) {
                                    authService.info('Url: ' + config.url + ' will be loaded after login is successful');
                                    var delayedRequest = $q.defer();
                                    $rootScope.$on('vssal:loginSuccess', function(event, token) {
                                        if (token) {
                                            authService.info('Login completed, sending request for ' + config.url);
                                            config.headers.Authorization = 'Bearer ' + tokenStored;
                                            delayedRequest.resolve(config);
                                        }
                                    });
                                    return delayedRequest.promise;
                                } else {
                                    authService.info('login is in progress.');
                                    config.data = 'login in progress, cancelling the request for ' + config.url;
                                    return $q.reject(config);
                                }
                            } else {
                                // delayed request to return after iframe completes
                                var delayedRequest = $q.defer();
                                authService.acquireToken(resource).then(function(token) {
                                    authService.verbose('Token is available');
                                    config.headers.Authorization = 'Bearer ' + token;
                                    delayedRequest.resolve(config);
                                }, function(errDesc, error) {
                                    config.data = errDesc + "|" + error;
                                    delayedRequest.reject(config);
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
                            var resource = authService.getResourceForEndpoint(rejection.config.url);
                            authService.clearCacheForResource(resource);
                            $rootScope.$broadcast('vssal:notAuthorized', rejection, resource);
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