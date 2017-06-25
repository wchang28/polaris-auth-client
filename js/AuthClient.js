"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var $node = require("rest-node");
var $J = $node.get().$J;
var AuthClient = (function () {
    function AuthClient(options, clientAppSettings) {
        this.options = options;
        this.clientAppSettings = clientAppSettings;
    }
    Object.defineProperty(AuthClient.prototype, "instance_url", {
        get: function () { return (this.options && this.options.instance_url ? this.options.instance_url : ''); },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(AuthClient.prototype, "redirect_uri", {
        get: function () { return (this.clientAppSettings && this.clientAppSettings.redirect_uri ? this.clientAppSettings.redirect_uri : null); },
        enumerable: true,
        configurable: true
    });
    AuthClient.getClientAppHeaderField = function () { return AuthClient.CLIENT_APP_HEADER_FLD; };
    Object.defineProperty(AuthClient.prototype, "connectOptions", {
        get: function () {
            var ret = {
                headers: {}
            };
            ret.headers[AuthClient.CLIENT_APP_HEADER_FLD] = JSON.stringify(this.clientAppSettings);
            if (this.options && typeof this.options.rejectUnauthorized)
                ret.rejectUnauthorized = this.options.rejectUnauthorized;
            return ret;
        },
        enumerable: true,
        configurable: true
    });
    // POST
    AuthClient.prototype.$P = function (path, data) {
        return $J('POST', this.instance_url + path, data, this.connectOptions).then(function (restReturn) { return restReturn.data; });
    };
    AuthClient.prototype.getConnectedApp = function (done) {
        return this.$P("/services/authorize/get_connected_app", {});
    };
    AuthClient.prototype.userLogin = function (response_type, username, password, signUpUserForApp) {
        var params = {
            response_type: response_type,
            username: username,
            password: password,
            signUpUserForApp: signUpUserForApp
        };
        return this.$P("/services/authorize/user_login", params);
    };
    AuthClient.prototype.automationLogin = function (username, password) {
        var params = {
            username: username,
            password: password
        };
        return this.$P("/services/authorize/automation_login", params);
    };
    AuthClient.prototype.getAccessFromAuthCode = function (code) {
        var params = { code: code };
        return this.$P("/services/authorize/get_access_from_auth_code", params);
    };
    AuthClient.prototype.refreshToken = function (refresh_token) {
        var params = { refresh_token: refresh_token };
        return this.$P("/services/authorize/refresh_token", params);
    };
    AuthClient.prototype.SSPR = function (username) {
        var params = { username: username };
        return this.$P("/services/authorize/sspr", params);
    };
    AuthClient.prototype.resetPassword = function (pin, done) {
        var params = { pin: pin };
        return this.$P("/services/authorize/reset_password", params);
    };
    AuthClient.prototype.lookupUser = function (username) {
        var params = { username: username };
        return this.$P("/services/authorize/lookup_user", params);
    };
    AuthClient.prototype.signUpNewUser = function (accountOptions) {
        var params = accountOptions;
        return this.$P("/services/authorize/sign_up_new_user", params);
    };
    ;
    return AuthClient;
}());
AuthClient.CLIENT_APP_HEADER_FLD = 'x-client-app';
exports.AuthClient = AuthClient;
var TokenVerifier = (function () {
    function TokenVerifier(options) {
        this.options = options;
    }
    TokenVerifier.prototype.getError = function (httpErr) {
        if (httpErr) {
            if (httpErr.responseJSON)
                return httpErr.responseJSON;
            else if (httpErr.responseText) {
                try {
                    return JSON.parse(httpErr.responseText);
                }
                catch (e) {
                    return httpErr.responseText;
                }
            }
            else
                return httpErr;
        }
        else
            return null;
    };
    Object.defineProperty(TokenVerifier.prototype, "instance_url", {
        get: function () { return (this.options && this.options.instance_url ? this.options.instance_url : ''); },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(TokenVerifier.prototype, "connectOptions", {
        get: function () {
            var ret = {
                headers: {}
            };
            if (this.options && typeof this.options.rejectUnauthorized)
                ret.rejectUnauthorized = this.options.rejectUnauthorized;
            return ret;
        },
        enumerable: true,
        configurable: true
    });
    // POST
    TokenVerifier.prototype.$P = function (path, data) {
        return $J('POST', this.instance_url + path, data, this.connectOptions).then(function (restReturn) { return restReturn.data; });
    };
    TokenVerifier.prototype.verifyAccessToken = function (accessToken) {
        var params = accessToken;
        return this.$P("/services/token/verify", params);
    };
    return TokenVerifier;
}());
exports.TokenVerifier = TokenVerifier;
