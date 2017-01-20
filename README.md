Visual Studio Sevices Auth Library (VSSAL) for JavaScript
====================================
[![Build Status](https://travis-ci.org/DiogenesPolanco/Visual-Studio-Sevices-Auth-Library-Js.svg?branch=master)](https://travis-ci.org/DiogenesPolanco/Visual-Studio-Sevices-Auth-Library-Js)

Visual Studio Sevices Auth Library for JavaScript (VSSAL JS) helps you to use Azure AD for handling authentication in your single page applications.
This library is optimized for working together with AngularJS.

## Versions
Current version - 0.0.1  
 
## Instalation
Via Bower:

    $ bower install vssal-angular

The vssal.js source is [here](https://github.com/DiogenesPolanco/Visual-Studio-Sevices-Auth-Library-Js/tree/master/lib/vssal.js).
The vssal-angular.js source is [here](https://github.com/DiogenesPolanco/Visual-Studio-Sevices-Auth-Library-Js/tree/master/lib/vssal-angular.js).
 
**Quick usage guide**

Below you can find a quick reference for the most common operations you need to perform to use vssal js.

1- Include references to angular.js libraries, vssal.js, vssal-angular.js in your main app page.

2- include a reference to vssal module
```js
var app = angular.module('demoApp', ['ngRoute', 'vssalAngular']);
```
3- ***When HTML5 mode is configured***, ensure the $locationProvider hashPrefix is set
```js
	// using '!' as the hashPrefix but can be a character of your choosing
	app.config(['$locationProvider', function($locationProvider) {
		$locationProvider.html5Mode(true).hashPrefix('!');
	}]);
```

Without the hashPrefix set, the Visual Studio Online login will loop indefinitely as the callback URL from Visual Studio Online (in the form of, {yourBaseUrl}/#{VSOTokenAndState}) will be rewritten to remove the '#' causing the token parsing to fail and login sequence to occur again.

4- Initialize vssal with the Visual Studio Online app coordinates at app config time
```js
// endpoint to resource mapping(optional)
    var endpoints = {
        "https://yourhost/api": "b6a68585-5287-45b2-ba82-383ba1f60932",
    };
vssalAuthenticationServiceProvider.init(
        {
            // Config to specify endpoints and similar for your app
            tenant: "52d4b072-9470-49fb-8721-bc3a1c9912a1", // Optional by default, it sends common
            clientId: "e9a5a8b6-8af7-4719-9821-0deef255f68e", // Required
            //localLoginUrl: "/login",  // optional
            //redirectUri : "your site", optional
            endpoints: endpoints  // If you need to send CORS api requests.
        },
        $httpProvider   // pass http provider to inject request interceptor to attach tokens
        );
```
5- Define which routes you want to secure via vssal - by adding `requireVSOLogin: true` to their definition
```js
$routeProvider.
    when("/todoList", {
        controller: "todoListController",
        templateUrl: "/App/Views/todoList.html",
        requireVSOLogin: true
    });

```
6- Any service invocation code you might have will remain unchanged. vssal's interceptor will automatically add tokens for every outgoing call.

***Optional***
7- If you so choose, in addition (or substitution) to route level protection you can add explicit login/logout UX elements. Furthermore, you can access properties of the currently signed in user directly form JavaScript (via userInfo and userInfo.profile):
```html
<!DOCTYPE html>
<html>
<head>
    <title>Angular vssal Sample</title>
</head>
<body ng-app="vssalDemo" ng-controller="homeController" ng-init="hmCtl.init()">
    <a href="#">Home</a>
    <a href="#/todoList">ToDo List</a>


    <!--These links are added to manage login/logout-->
    <div data-ng-model="userInfo">
        <span data-ng-hide="!userInfo.isAuthenticated">Welcome {{userInfo.userName}} </span>
        <button data-ng-hide="!userInfo.isAuthenticated" data-ng-click="logout()">Logout</button>
        <button data-ng-hide="userInfo.isAuthenticated" data-ng-click="login()">Login</button>

        <div>
            {{userInfo.loginError}}
        </div>
        <div>
            {{testMessage}}
        </div>
    </div>
    <div ng-view>
        Your view will appear here.
    </div>

    <script src="/Scripts/angular.min.js"></script>
    <script src="/Scripts/angular-route.min.js"></script>
    <script src="/Scripts/vssal.js"></script>
    <script src="/Scripts/vssal-angular.js"></script>
    <script src="App/Scripts/app.js"></script>
    <script src="App/Scripts/homeController.js"></script>
    <script src="App/Scripts/todoDetailController.js"></script>
    <script src="App/Scripts/todoListController.js"></script>
    <script src="App/Scripts/todoService.js"></script>
</body>
</html>
```
7- You have full control on how to trigger sign in, sign out and how to deal with errors:

```js
'use strict';
app.controller('homeController', ['$scope', '$location', 'vssalAuthenticationService', function ($scope, $location, vssalAuthenticationService) {
    // this is referencing vssal module to do login

    //userInfo is defined at the $rootscope with vssalAngular module
    $scope.testMessage = "";
    $scope.init = function () {
        $scope.testMessage = "";
    };

    $scope.logout = function () {
        vssalAuthenticationService.logOut();
    };

    $scope.login = function () {
        vssalAuthenticationService.login();
    };

    // optional
    $scope.$on("vssal:loginSuccess", function () {
        $scope.testMessage = "loginSuccess";
    });

    // optional
    $scope.$on("vssal:loginFailure", function () {
        $scope.testMessage = "loginFailure";
        $location.path("/login");
    });

    // optional
    $scope.$on("vssal:notAuthorized", function (event, rejection, forResource) {
        $scope.testMessage = "It is not Authorized for resource:" + forResource;
    });

}]);


```

### Cache Location
Default storage location is sessionStorage. You can specify localStorage in the config as well.

```js
vssalAuthenticationServiceProvider.init(
        {
            // Config to specify endpoints and similar for your app
            clientId: 'cb68f72f...',
            cacheLocation: 'localStorage' // optional cache location default is sessionStorage
        },
        $httpProvider   // pass http provider to inject request interceptor to attach tokens
        );
```

### Security
Tokens are accessible from javascript since vssal.JS is using HTML5 storage. Default storage option is sessionStorage, which keeps the tokens per session. You should ask user to login again for important operations on your app.
You should protect your site for XSS. Please check the article here: https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet
 