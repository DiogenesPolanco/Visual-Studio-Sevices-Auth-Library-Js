Visual Studio Sevices Auth Library (VSSAL) for JavaScript
====================================
[![Build Status](https://travis-ci.org/DiogenesPolanco/Visual-Studio-Sevices-Auth-Library-Js.svg?branch=master)](https://travis-ci.org/DiogenesPolanco/Visual-Studio-Sevices-Auth-Library-Js)

Visual Studio Sevices Auth Library for JavaScript (VSSAL JS) helps you to use Visual Studio Online for handling authentication in your single page applications.
This library is optimized for working together with AngularJS.

## Register your app

Go to (https://app.vssps.visualstudio.com/app/register) to register your app.

![](https://www.visualstudio.com/en-us/docs/integrate/get-started/auth/_img/grant-access.png)

When your register your app, the application settings page is displayed.
![](https://www.visualstudio.com/en-us/docs/integrate/get-started/auth/_img/app-settings.png)

You'll call the authorization URL and pass your app ID and authorized scopes when you want to have a user authorize your app to access his Visual Studio Team Services account. You'll call the access token URL when you want to get an access token to call a Visual Studio Team Services REST API.

The settings for each app that you register are available from your profile (https://app.vssps.visualstudio.com/profile/view).

## Versions
Current version - 0.3  
 
## Instalation
Via Bower, npm and yarn:

    $ bower install vssal-angular
    $ npm install vssal-angular
    $ yarn install vssal-angular
  
**Quick usage guide**

Below you can find a quick reference for the most common operations you need to perform to use vssal js.

1- Include references to angular.js libraries, vssal-angular.js in your main app page.

2- include a reference to vssal module
```js
var app = angular.module('demoApp', ['ngRoute', 'vssalAngular']);
```
3- Initialize vssal with the Visual Studio Online app coordinates at app config time
```js
app.config(['$routeProvider', '$httpProvider', 'vssalAuthenticationServiceProvider',
    function($routeProvider, $httpProvider, vssalAuthenticationServiceProvider) {	    
		vssalAuthenticationServiceProvider.init(
		{ 	   
			clientId: '00000000-0000-0000-0000-000000000000',
			tenant:'YourVisualStudioAccount', // extract from https://YourVisualStudioAccount.visualstudio.com
			client_assertion: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI...',
			scope: 'vso.connected_server vso.identity vso.work_write ...'
		},
		$httpProvider   // pass http provider to inject request interceptor to attach tokens
		);
		// configure html5 to get links working on jsfiddle
		$locationProvider.html5Mode({
		    enabled: true,
		    requireBase: false
		});
    }
]);
```
4- Define which routes you want to secure via vssal - by adding `requireVSOLogin: true` to their definition
```js
$routeProvider.
    when("/todoList", {
        controller: "todoListController",
        templateUrl: "/App/Views/todoList.html",
        requireVSOLogin: true
    });

```
5- Any service invocation code you might have will remain unchanged. vssal's interceptor will automatically add tokens for every outgoing call.

***Optional***
6- If you so choose, in addition (or substitution) to route level protection you can add explicit login/logout UX elements. Furthermore, you can access properties of the currently signed in user directly form JavaScript (via userInfo and userInfo.profile):
```html
<!DOCTYPE html>
<html>
<head>
    <title>Angular vssal Sample</title>
</head>
<body ng-app="vssalDemo" ng-controller="homeController" ng-init="init()"> 
    <!--These links are added to manage login/logout-->
    <div>
	<span ng-show="userInfo.isAuthenticated">Welcome {{CurrentProfile.profile.displayName}}</span>
	<button ng-show="userInfo.isAuthenticated" ng-click="logout()">Logout</button>
	<button ng-hide="userInfo.isAuthenticated" ng-click="login()">Login</button>
        <div>
            {{userInfo.loginError}}
	    {{testMessage}}
        </div> 
    </div>
    <div ng-view>
        Your view will appear here.
    </div>
    <script src="/bower_components/angular/angular.min.js"></script>
    <script src="/bower_components/angular-route/angular-route.min.js"></script> 
    <script src="/bower_components/vssal-angular/dist/vssal-angular.js"></script>
    <script src="App/Scripts/app.js"></script>
    <script src="App/Scripts/homeController.js"></script> 
    <script src="App/Scripts/todoListController.js"></script> 
</body>
</html>
```
7- You have full control on how to trigger sign in, sign out and how to deal with errors:

```js
app.controller('homeController', ['$scope', 'vssalAuthenticationService', 'vssalVisualStudioService'
function ($scope, $location, vssalAuthenticationService, vssalVisualStudioService) { 
    //userInfo is defined at the $rootscope with vssalAngular module
    $scope.testMessage = "";
    $scope.init = function () {
        if (vssalAuthenticationService.userInfo.isAuthenticated) {
	    vssalVisualStudioService.GetMyProfile().then(function(profile) {
		$scope.CurrentProfile = profile;
	    });
	}
    };
    $scope.createWorkItem = function() {
    	var content = 'SG9sYSBNdW5kbyE='; // btoa('Hola Mundo!')
	vssalVisualStudioService.UploadAttachment('readme.txt', content).then(function(attachment) {
		vssalVisualStudioService.CreateWorkItem({
		    project: 'MyProject',
		    type: 'Bug',//Bug, Task, Code Review, Feature, Feedback, etc...
		    title: 'Error when after login',
		    assignedTo: "Diogenes Polanco Martinez <diogenespolancomartinez@gmail.com>",
		    description: 'Repro Steps Description',
		    attachment: {
			url: attachment.url,
			comment: "file comment"
		    }
		}).then(function(response) {
		    console.log(response);
		});
	});
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
}]);
```
 
