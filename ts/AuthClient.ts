import * as $node from 'rest-node';
import * as oauth2 from 'oauth2';
import * as restIntf from 'rest-api-interfaces';

let $J = $node.get().$J;

export {ConnectOptions as IAuthorizeEndpointOptions} from 'rest-api-interfaces';

export interface IConnectedApp {
	client_id: string;
	name: string;
	allow_reset_pswd: boolean;
	allow_create_new_user: boolean;
	allow_auto_app_sign_up: boolean;
}

export interface IAuthorizedUser {
	userId: string;
	userName: string;
	displayName: string;
	email: string;
}

export interface IAutomationLoginParams {
	username: string;
	password: string;
}

export interface IUserLoginParams extends IAutomationLoginParams {
	response_type : oauth2.AuthResponseType;
	signUpUserForApp: boolean;
}

export interface ILoginResult {
	user: IAuthorizedUser;
	access?: oauth2.Access;
	code?:string;
}

export interface IGetAccessFromCodeParams {
	code: string;
}

export interface IRefreshTokenParams {
	refresh_token: string;
}

export interface IUsernameParams {
	username: string;
}

export interface IResetPasswordParams {
	pin: string;
}

export interface IAccountOptions {
	firstName: string
	,lastName: string
	,email: string
	,username: string
	,password: string
	,companyName?: string
	,mobilePhone?: string
	,promotionalMaterial?: boolean;
}

export class AuthClient {
	private static CLIENT_APP_HEADER_FLD: string = 'x-client-app';
	constructor(public options:restIntf.ConnectOptions, public clientAppSettings:oauth2.ClientAppSettings) {}
	get instance_url():string {return (this.options && this.options.instance_url ? this.options.instance_url : '');}
	get redirect_uri():string {return (this.clientAppSettings && this.clientAppSettings.redirect_uri ? this.clientAppSettings.redirect_uri : null);}
	getError(httpErr) {
		if (httpErr) {
			if (httpErr.responseJSON)
				return httpErr.responseJSON;
			else if (httpErr.responseText) {
				try {
					return JSON.parse(httpErr.responseText);
				} catch(e) {
					return httpErr.responseText;
				}
			} else
				return httpErr;
		} else
			return null;
	}
	static getClientAppHeaderField():string {return AuthClient.CLIENT_APP_HEADER_FLD;}
	private get connectOptions(): restIntf.ApiCallOptions {
		let ret: restIntf.ApiCallOptions = {
			headers: {}
		}
		ret.headers[AuthClient.CLIENT_APP_HEADER_FLD] = JSON.stringify(this.clientAppSettings);
		if (this.options && typeof this.options.rejectUnauthorized) ret.rejectUnauthorized = this.options.rejectUnauthorized;
		return ret;
	}
	// POST
	private $P(path:string, data: any, done:(err:any, ret:any) => void) {
		let headers = {};
		headers[AuthClient.CLIENT_APP_HEADER_FLD] = JSON.stringify(this.clientAppSettings);
		$J('POST', this.instance_url + path, data, done, this.connectOptions);
	}
	getConnectedApp(done:(err:any, connectedApp:IConnectedApp) => void) {
		this.$P("/services/authorize/get_connected_app", {}, (err:any, connectedApp: IConnectedApp) => {
			if (typeof done === 'function') done(this.getError(err), connectedApp);
		});
	}
	userLogin(response_type:oauth2.AuthResponseType, username:string, password:string, signUpUserForApp:boolean, done:(err:any, ret: ILoginResult) => void) {
		let params: IUserLoginParams = {
			response_type : response_type
			,username: username
			,password: password
			,signUpUserForApp: signUpUserForApp
		};
		this.$P("/services/authorize/user_login", params, (err:any, ret: ILoginResult) => {
			if (typeof done === 'function') done(this.getError(err), ret);
		});
	}
	automationLogin(username:string, password:string, done:(err:any, ret: ILoginResult) => void) {
		let params: IAutomationLoginParams = {
			username: username
			,password: password
		};
		this.$P("/services/authorize/automation_login", params, (err:any, ret: ILoginResult) => {
			if (typeof done === 'function') done(this.getError(err), ret);
		});
	}
	getAccessFromAuthCode(code:string, done:(err:any, access:oauth2.Access) => void) {
		let params: IGetAccessFromCodeParams = {code: code};
		this.$P("/services/authorize/get_access_from_auth_code", params, (err, access:oauth2.Access) => {
			if (typeof done === 'function') done(this.getError(err), access);
		});
	}
	refreshToken(refresh_token:string, done:(err:any, access:oauth2.Access) => void) {
		let params:IRefreshTokenParams = {refresh_token : refresh_token};
		this.$P("/services/authorize/refresh_token", params, (err, access:oauth2.Access) => {
			if (typeof done === 'function') done(this.getError(err), access);
		});
	}
	verifyAccessToken(accessToken: oauth2.AccessToken, done:(err:any, user:IAuthorizedUser) => void) {
		let params = accessToken;
		this.$P("/services/authorize/verify_token", params, (err, user) => {
			if (typeof done === 'function') done(this.getError(err), user);
		});
	}

	SSPR(username:string, done:(err:any, params:IResetPasswordParams) => void) {
		let params: IUsernameParams = {username};
		this.$P("/services/authorize/sspr", params, (err, data) => {
			if (typeof done === 'function') done(this.getError(err), data);
		});
	}
	resetPassword(pin:string, done:(err:any) => void) {
		let params:IResetPasswordParams = {pin};
		this.$P("/services/authorize/reset_password", params, (err, data) => {
			if (typeof done === 'function') done(this.getError(err));
		});
	}
	lookupUser(username:string, done:(err:any, user:IAuthorizedUser) => void) {
		let params: IUsernameParams = {username};
		this.$P("/services/authorize/lookup_user", params, (err, data) => {
			if (typeof done === 'function') done(this.getError(err), data);
		});		
	}
	signUpNewUser(accountOptions:IAccountOptions, done:(err:any, user:IAuthorizedUser) => void) {
		let params = accountOptions;
		this.$P("/services/authorize/sign_up_new_user", params, (err, data) => {
			if (typeof done === 'function') done(this.getError(err), data);
		});			
	};
}