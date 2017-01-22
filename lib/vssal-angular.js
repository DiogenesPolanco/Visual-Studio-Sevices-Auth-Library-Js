// vssalJS v0.0.1

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