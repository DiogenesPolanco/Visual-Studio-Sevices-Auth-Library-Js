/*! vssal-angular v0.2 2017-01-22 */
var ContextVssal=function(){"use strict";return ContextVssal=function(a){if(this.CONSTANTS={ACCESS_TOKEN:"access_token",TOKEN_TYPE:"token_type",EXPIRES_IN:"expires_in",REFRESH_TOKEN:"refresh_token",CODE:"code",SCOPE:"scope",ERROR:"Error",ERROR_DESCRIPTION:"ErrorDescription",STORAGE:{ACCESS_TOKEN:"vssal.access.token.key",REFRESH_TOKEN:"vssal.access.refreshtoken.key",EXPIRATION_KEY:"vssal.expiration.key",SCOPE:"vssal.scope",ERROR:"vssal.error",ERROR_DESCRIPTION:"vssal.error.description"},LOADFRAME_TIMEOUT:"6000",TOKEN_RENEW_STATUS_CANCELED:"Canceled",TOKEN_RENEW_STATUS_COMPLETED:"Completed",TOKEN_RENEW_STATUS_IN_PROGRESS:"In Progress",LOGGING_LEVEL:{ERROR:0,WARN:1,INFO:2,VERBOSE:3},LEVEL_STRING_MAP:{0:"ERROR:",1:"WARNING:",2:"INFO:",3:"VERBOSE:"},POPUP_WIDTH:483,POPUP_HEIGHT:600},ContextVssal.prototype._singletonInstance)return ContextVssal.prototype._singletonInstance;if(ContextVssal.prototype._singletonInstance=this,this.instance="https://app.vssps.visualstudio.com/",this.config={},this.callback=null,this.popUp=!1,this.isAngular=!1,this._user=null,this._activeRenewals={},this._loginInProgress=!1,this._renewStates=[],window.callBackMappedToRenewStates={},window.callBacksMappedToRenewStates={},!a.clientId)throw new Error("clientId is required");if(!a.scope)throw new Error("scope is required");if(!a.client_assertion)throw new Error("client Assertion is required");this.config=this._cloneConfig(a),this.config.baseUrlResource=this.instance,this.config.callback&&"function"==typeof this.config.callback&&(this.callback=this.config.callback),a.client_assertion_type||(this.config.client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),a.grant_type||(this.config.grant_type="urn:ietf:params:oauth:grant-type:jwt-bearer"),this.config.redirectUri||(this.config.redirectUri=this.getRedirectUri()),this.config.isAngular&&(this.isAngular=this.config.isAngular),this.config.auto&&this.isCallback()&&this.acquireToken()},window.Logging={level:0,log:function(a){}},ContextVssal.prototype.getRedirectUri=function(){return location.protocol+"//"+location.host},ContextVssal.prototype.getUrlResourceTenant=function(){return location.protocol+"//"+this.config.tenant+".visualstudio.com/"},ContextVssal.prototype.login=function(){if(this._loginInProgress)return void this.info("Login in progress");this._saveItem(this.CONSTANTS.STORAGE.ERROR,""),this._saveItem(this.CONSTANTS.STORAGE.ERROR_DESCRIPTION,"");var a=this._getNavigateUrl("Assertion",null);this._loginInProgress=!0,this.config.displayCall?this.config.displayCall(a):this.promptUser(a)},ContextVssal.prototype.loginInProgress=function(){return this._loginInProgress},ContextVssal.prototype.getCachedToken=function(){var a=this,b=a._getItem(a.CONSTANTS.STORAGE.ACCESS_TOKEN),c=a._getItem(a.CONSTANTS.STORAGE.EXPIRATION_KEY),d=a.config.expireOffsetSeconds||120;return c&&c>a._now()+d?a.promise(void 0,b):(a._saveItem(a.CONSTANTS.STORAGE.ACCESS_TOKEN,""),a._saveItem(a.CONSTANTS.STORAGE.EXPIRATION_KEY,0),a.promise(void 0,null))},ContextVssal.prototype.getCachedUser=function(){var a=this;return a._user?a.promise(void 0,a._user):a._createUser()},ContextVssal.prototype._getQueryString=function(a,b){var c=b?b:window.location.href,d=new RegExp("[?&]"+a+"=([^&#]*)","i"),e=d.exec(c);return e?e[1]:null},ContextVssal.prototype._newToken=function(a){var b=this,c=b.promise({method:"post",url:b.instance+"oauth2/token",data:{client_assertion_type:b.config.client_assertion_type,client_assertion:b.config.client_assertion,grant_type:b.config.grant_type,assertion:b._getQueryString("code"),redirect_uri:b.getRedirectUri()}}).then(function(a){return b.verbose("Renew token "),b.saveToken(a)});return c},ContextVssal.prototype._urlContainsQueryStringParameter=function(a,b){var c=new RegExp("[\\?&]"+a+"=");return c.test(b)},ContextVssal.prototype.acquireToken=function(){var a=this,b=this.getCachedToken().then(function(b){return b?(a.info("Token is already in cache"),a.promise(void 0,b)):a.isCallback()?a._newToken():void a.login()});return b},ContextVssal.prototype.promptUser=function(a){a?(this.info("Navigate to:"+a),window.location.replace(a)):this.info("Navigate url is empty")},ContextVssal.prototype.clearCache=function(){this._saveItem(this.CONSTANTS.STORAGE.SCOPE,""),this._saveItem(this.CONSTANTS.STORAGE.ACCESS_TOKEN,""),this._saveItem(this.CONSTANTS.STORAGE.EXPIRATION_KEY,0),this._saveItem(this.CONSTANTS.STORAGE.ERROR,""),this._saveItem(this.CONSTANTS.STORAGE.ERROR_DESCRIPTION,"")},ContextVssal.prototype.logOut=function(){this.clearCache(),this._user=null;var a;if(this.config.logOutUri)a=this.config.logOutUri;else{var b="";this.config.redirectUri&&(b="redirectUrl="+encodeURIComponent(this.getRedirectUri())),a=this.instance+"_signout?"+b}this.info("Logout navigate to: "+a),this.promptUser(a)},ContextVssal.prototype._isEmpty=function(a){return"undefined"==typeof a||!a||0===a.length},ContextVssal.prototype.getUser=function(a){var b=this;if("function"!=typeof a)throw new Error("callback is not a function");if(b._user)return void a(null,b._user);var c=b.getCachedUser();b._isEmpty(c)?(b.warn("User information is not available"),a("User information is not available",null)):(b.info("User exists in cache "),b._createUser().then(function(){a(null,b._user)}))},ContextVssal.prototype.promise=function(a,b){var c=this,d=new Promise(function(d,e){void 0===a?d(b):c.getCachedToken().then(function(b){a.AutoAuth&&(a.headers={"Content-Type":"application/json",Authorization:"Bearer "+b}),ajax(a).then(function(a){d(a)}).catch(function(a){e(a)}).always(function(a){d(a)})})});return d},ContextVssal.prototype._createUser=function(){var a=null,b=this,c=b.promise({AutoAuth:!0,method:"get",url:b.instance+"_apis/profile/profiles/me"}).then(function(c){return c&&c.hasOwnProperty("displayName")?(a={userName:"",profile:c},c.hasOwnProperty("emailAddress")&&(a.userName=c.emailAddress),b._user=a):b.warn("displayName has invalid aud field"),b._user});return c},ContextVssal.prototype._getHash=function(a){return a.indexOf("#/")>-1?a=a.substring(a.indexOf("#/")+2):a.indexOf("#")>-1&&(a=a.substring(1)),a},ContextVssal.prototype.isCallback=function(a){var b=this;a=b._getHash(void 0===a?window.location.hash:a);var c=b._deserialize(a);return""===a&&(c={code:b._getQueryString("code")}),c.hasOwnProperty(b.CONSTANTS.CODE)&&null!==c.code},ContextVssal.prototype.getLoginError=function(){return this._getItem(this.CONSTANTS.STORAGE.LOGIN_ERROR)},ContextVssal.prototype.saveToken=function(a){var b=this;return b._saveItem(b.CONSTANTS.STORAGE.ERROR,""),b._saveItem(b.CONSTANTS.STORAGE.ERROR_DESCRIPTION,""),a.hasOwnProperty(b.CONSTANTS.ERROR_DESCRIPTION)&&(b.info("Error :"+a[b.CONSTANTS.ERROR]+"; Error description:"+a[b.CONSTANTS.ERROR_DESCRIPTION]),b._saveItem(b.CONSTANTS.STORAGE.ERROR,a[b.CONSTANTS.ERROR]),b._saveItem(b.CONSTANTS.STORAGE.ERROR_DESCRIPTION,a[b.CONSTANTS.ERROR_DESCRIPTION]),b._saveItem(b.CONSTANTS.STORAGE.SCOPE,""),b._saveItem(b.CONSTANTS.STORAGE.ACCESS_TOKEN,""),b._saveItem(b.CONSTANTS.STORAGE.EXPIRATION_KEY,0)),a.hasOwnProperty(b.CONSTANTS.ACCESS_TOKEN)?(b.info("Fragment has access token"),b._saveItem(b.CONSTANTS.STORAGE.SCOPE,a[b.CONSTANTS.SCOPE]),b._saveItem(b.CONSTANTS.STORAGE.ACCESS_TOKEN,a[b.CONSTANTS.ACCESS_TOKEN]),b._saveItem(b.CONSTANTS.STORAGE.EXPIRATION_KEY,b._expiresIn(a[b.CONSTANTS.EXPIRES_IN])),b.promise(void 0,a[b.CONSTANTS.ACCESS_TOKEN])):b.promise(void 0,null)},ContextVssal.prototype._getHostFromUri=function(a){var b=String(a).replace(/^(https?:)\/\//,"");return b=b.split("/")[0]},ContextVssal.prototype._getNavigateUrl=function(a,b){var c="";return"Assertion"===a&&(c=this.instance+"oauth2/authorize"+this._serialize(a,this.config,b)),this.info("Navigate url:"+c),c},ContextVssal.prototype._base64DecodeStringUrlSafe=function(a){return a=a.replace(/-/g,"+").replace(/_/g,"/"),window.atob?decodeURIComponent(escape(window.atob(a))):decodeURIComponent(escape(this._decode(a)))},ContextVssal.prototype._decode=function(a){var b="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";a=String(a).replace(/=+$/,"");var c=a.length;if(c%4===1)throw new Error("The token to be decoded is not correctly encoded.");for(var d,e,f,g,h,i,j,k,l="",m=0;m<c;m+=4){if(d=b.indexOf(a.charAt(m)),e=b.indexOf(a.charAt(m+1)),f=b.indexOf(a.charAt(m+2)),g=b.indexOf(a.charAt(m+3)),m+2===c-1){h=d<<18|e<<12|f<<6,i=h>>16&255,j=h>>8&255,l+=String.fromCharCode(i,j);break}if(m+1===c-1){h=d<<18|e<<12,i=h>>16&255,l+=String.fromCharCode(i);break}h=d<<18|e<<12|f<<6|g,i=h>>16&255,j=h>>8&255,k=255&h,l+=String.fromCharCode(i,j,k)}return l},ContextVssal.prototype._convertUrlSafeToRegularBase64EncodedString=function(a){return a.replace("-","+").replace("_","/")},ContextVssal.prototype._serialize=function(a,b,c){var d=[];return null!==b&&(d.push("?response_type="+a),d.push("client_id="+encodeURIComponent(b.clientId)),c?d.push("scope="+encodeURIComponent(c)):d.push("scope="+encodeURIComponent(b.scope)),d.push("redirect_uri="+encodeURIComponent(this.getRedirectUri())),b.state&&d.push("state="+encodeURIComponent(b.state))),d.join("&")},ContextVssal.prototype._deserialize=function(a){var b,c=/\+/g,d=/([^&=]+)=([^&]*)/g,e=function(a){return decodeURIComponent(a.replace(c," "))},f={};for(b=d.exec(a);b;)f[e(b[1])]=e(b[2]),b=d.exec(a);return f},ContextVssal.prototype._decimalToHex=function(a){for(var b=a.toString(16);b.length<2;)b="0"+b;return b},ContextVssal.prototype._expiresIn=function(a){return this._now()+parseInt(a,10)},ContextVssal.prototype._now=function(){return Math.round((new Date).getTime()/1e3)},ContextVssal.prototype._saveItem=function(a,b){return this.config&&this.config.cacheLocation&&"localStorage"===this.config.cacheLocation?this._supportsLocalStorage()?(localStorage.setItem(a,b),!0):(this.info("Local storage is not supported"),!1):this._supportsSessionStorage()?(sessionStorage.setItem(a,b),!0):(this.info("Session storage is not supported"),!1)},ContextVssal.prototype._getItem=function(a){return this.config&&this.config.cacheLocation&&"localStorage"===this.config.cacheLocation?this._supportsLocalStorage()?localStorage.getItem(a):(this.info("Local storage is not supported"),null):this._supportsSessionStorage()?sessionStorage.getItem(a):(this.info("Session storage is not supported"),null)},ContextVssal.prototype._supportsLocalStorage=function(){try{var a="localStorage"in window&&window.localStorage;return a&&(window.localStorage.setItem("storageTest",""),window.localStorage.removeItem("storageTest")),a}catch(a){return!1}},ContextVssal.prototype._supportsSessionStorage=function(){try{var a="sessionStorage"in window&&window.sessionStorage;return a&&(window.sessionStorage.setItem("storageTest",""),window.sessionStorage.removeItem("storageTest")),a}catch(a){return!1}},ContextVssal.prototype._cloneConfig=function(a){if(null===a||"object"!=typeof a)return a;var b={};for(var c in a)a.hasOwnProperty(c)&&(b[c]=a[c]);return b},ContextVssal.prototype.log=function(a,b,c){if(a<=Logging.level){var d=(new Date).toUTCString(),e="";e=this.config.correlationId?d+":"+this.config.correlationId+"-"+this._libVersion()+"-"+this.CONSTANTS.LEVEL_STRING_MAP[a]+" "+b:d+":"+this._libVersion()+"-"+this.CONSTANTS.LEVEL_STRING_MAP[a]+" "+b,c&&(e+="\nstack:\n"+c.stack),Logging.log(e)}},ContextVssal.prototype.error=function(a,b){this.log(this.CONSTANTS.LOGGING_LEVEL.ERROR,a,b)},ContextVssal.prototype.warn=function(a){this.log(this.CONSTANTS.LOGGING_LEVEL.WARN,a,null)},ContextVssal.prototype.info=function(a){this.log(this.CONSTANTS.LOGGING_LEVEL.INFO,a,null)},ContextVssal.prototype.verbose=function(a){this.log(this.CONSTANTS.LOGGING_LEVEL.VERBOSE,a,null)},ContextVssal.prototype._libVersion=function(){return"0.0.1"},"undefined"!=typeof module&&module.exports&&(module.exports=ContextVssal,module.exports.inject=function(a){return new ContextVssal(a)}),ContextVssal}();!function(a,b){"use strict";"function"==typeof define&&define.amd?define("ajax",b):"object"==typeof exports?exports=module.exports=b():a.ajax=b()}(this,function(){"use strict";function a(a){var d=["get","post","put","delete"];return a=a||{},a.baseUrl=a.baseUrl||"",a.method&&a.url?c(a.method,a.baseUrl+a.url,b(a.data),a):d.reduce(function(d,e){return d[e]=function(d,f){return c(e,a.baseUrl+d,b(f),a)},d},{})}function b(a){return a||null}function c(a,b,c,e){var g=["then","catch","always"],i=g.reduce(function(a,b){return a[b]=function(c){return a[b]=c,a},a},{}),j=new XMLHttpRequest;return j.open(a,b,!0),j.withCredentials=e.hasOwnProperty("withCredentials"),d(j,e.headers),j.addEventListener("readystatechange",f(i,j),!1),j.send(h(c)),i.abort=function(){return j.abort()},i}function d(a,b){b=b||{},e(b)||(b["Content-Type"]="application/x-www-form-urlencoded"),Object.keys(b).forEach(function(c){b[c]&&a.setRequestHeader(c,b[c])})}function e(a){return Object.keys(a).some(function(a){return"content-type"===a.toLowerCase()})}function f(a,b){return function c(){b.readyState===b.DONE&&(b.removeEventListener("readystatechange",c,!1),a.always.apply(a,g(b)),b.status>=200&&b.status<300?a.then.apply(a,g(b)):a.catch.apply(a,g(b)))}}function g(a){var b;try{b=JSON.parse(a.responseText)}catch(c){b=a.responseText}return[b,a]}function h(a){return i(a)?j(a):a}function i(a){return"[object Object]"===Object.prototype.toString.call(a)}function j(a){return Object.keys(a).reduce(function(b,c){var d=b?b+"&":"";return d+k(c)+"="+k(a[c])},"")}function k(a){return encodeURIComponent(a)}return a}),function(){"use strict";if("undefined"!=typeof module&&module.exports&&(module.exports.inject=function(a){return new ContextVssal(a)}),angular){var a=angular.module("vssalAngular",[]);a.provider("vssalAuthenticationService",function(){var a=null,b={isAuthenticated:!1,userName:"",loginError:"",profile:""},c=function(){a.getCachedToken().then(function(c){b.isAuthenticated=null!==c&&c.length>0,b.isAuthenticated&&a.getCachedUser().then(function(a){var c=a||{userName:""};b.userName=c.userName,b.profile=c.profile})})};this.init=function(b,d){if(!b)throw new Error("You must set configOptions, when calling init");var e=window.location.hash,f=window.location.href;e&&(f=f.replace(e,"")),b.redirectUri=b.redirectUri||f,b.postLogoutRedirectUri=b.postLogoutRedirectUri||f,b.isAngular=!0,d&&d.interceptors&&d.interceptors.push("ProtectedResourceInterceptor"),a=new ContextVssal(b),c()},this.$get=["$rootScope","$window","$q","$location","$timeout","$injector",function(c,d,e,f,g,h){function i(a,b){return b.requireVSOLogin?a.requireVSOLogin!==!1:!!a.requireVSOLogin}function j(a){var b=null,c=[];if(a.hasOwnProperty("parent"))for(b=a;b;)c.unshift(b),b=h.get("$state").get(b.parent);else for(var d=a.name.split("."),e=0,f=d[0];e<d.length;e++)b=h.get("$state").get(f),b&&c.push(b),f+="."+d[e+1];return c}var k=function(e,f,g){a.verbose("Location change event from "+g+" to "+f);var i=d.location.hash;if(a.isCallback(i)&&(a.verbose("Processing the hash: "+i),!b.isAuthenticated)){var j=h.get("vssalAuthenticationService");j.acquireToken().then(function(d){d&&b.userName?(b.isAuthenticated=!0,c.$broadcast("vssal:loginSuccess",a._getItem(a.CONSTANTS.STORAGE.ACCESS_TOKEN))):c.$broadcast("vssal:loginFailure",a._getItem(a.CONSTANTS.STORAGE.ERROR_DESCRIPTION),a._getItem(a.CONSTANTS.STORAGE.ERROR))})}},l=function(){a.info("Login event for:"+f.$$url),a.config&&a.config.localLoginUrl?f.path(a.config.localLoginUrl):(a.info("Start login at:"+window.location.href),c.$broadcast("vssal:loginRedirect"),a.login())},m=function(c,d){if(d&&d.$$route)if(i(d.$$route,a.config))b.isAuthenticated||a.loginInProgress()||(a.info("Route change event for:"+f.$$url),l());else{var e;e="function"==typeof d.$$route.templateUrl?d.$$route.templateUrl(d.params):d.$$route.templateUrl}},n=function(c,d,e,g,h){if(d)for(var k=j(d),m=null,n=0;n<k.length;n++)if(m=k[n],i(m,a.config))b.isAuthenticated||a._renewActive||a.loginInProgress()||(a.info("State change event for:"+f.$$url),l());else if(m.templateUrl){var o;o="function"==typeof m.templateUrl?m.templateUrl(e):m.templateUrl}},o=function(b,c,d,e,f,g){a.verbose("State change error occured. Error: "+JSON.stringify(g)),g&&g.data&&(a.info("Setting defaultPrevented to true if state change error occured because vssal rejected a request. Error: "+g.data),b.preventDefault())};return c.$on("$routeChangeStart",m),c.$on("$stateChangeStart",n),c.$on("$locationChangeStart",k),c.$on("$stateChangeError",o),c.userInfo=b,{config:a.config,promise:a.promise,getUrlResourceTenant:function(){return a.getUrlResourceTenant()},login:function(){a.login()},loginInProgress:function(){return a.loginInProgress()},logOut:function(){a.logOut()},getCachedToken:function(){return a.getCachedToken()},userInfo:b,acquireToken:function(){var b=e.defer();return a.acquireToken().then(function(d){d?(c.$broadcast("vssal:acquireTokenSuccess",d),b.resolve(d)):(c.$broadcast("vssal:acquireTokenFailure"),a.error("Error when acquiring token"),b.reject("Error when acquiring token"))}),b.promise},getUser:function(){var b=e.defer();return a.getUser(function(c,d){c?(a.error("Error when getting user",c),b.reject(c)):b.resolve(d)}),b.promise},clearCache:function(){a.clearCache()},info:function(b){a.info(b)},verbose:function(b){a.verbose(b)}}}]}),a.provider("vssalVisualStudioService",function(){this.$get=["$rootScope","$window","$q","$http","$location","$timeout","$injector","vssalAuthenticationService",function(a,b,c,d,e,f,g,h){var i={};return i.GetMyProfile=function(){return h.getUser()},i.GetProjects=function(){return h.promise({AutoAuth:!0,method:"get",url:h.getUrlResourceTenant()+"DefaultCollection/_apis/projects"})},{GetMyProfile:function(){return i.GetMyProfile()},GetProjects:function(){return i.GetProjects()}}}]}),a.factory("ProtectedResourceInterceptor",["vssalAuthenticationService","$q","$rootScope",function(a,b,c){return{request:function(c){if(c){c.headers=c.headers||{};var d=a.getCachedToken();if(d)return a.info("Token is available for this url "+c.url),c.headers.Authorization="Bearer "+d,c;if(a.loginInProgress())return a.info("login is in progress."),c.data="login in progress, cancelling the request for "+c.url,b.reject(c);var e=b.defer();return a.acquireToken().then(function(b){b&&_oauthData.userName?(a.verbose("Token is available"),c.headers.Authorization="Bearer "+b,e.resolve(c)):e.reject(c)}),e.promise}},responseError:function(d){if(a.info("Getting error in the response: "+JSON.stringify(d)),d)return 401===d.status?c.$broadcast("vssal:notAuthorized",d):c.$broadcast("vssal:errorResponse",d),b.reject(d)}}}])}else console.error("Angular.JS is not included")}();