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
	private $P(path:string, data: any) : Promise<any> {
		return $J('POST', this.instance_url + path, data, this.connectOptions).then((restReturn: restIntf.RESTReturn) => restReturn.data);
	}
	getConnectedApp(done:(err:any, connectedApp:IConnectedApp) => void) : Promise<IConnectedApp> {
		return this.$P("/services/authorize/get_connected_app", {});
	}
	userLogin(response_type:oauth2.AuthResponseType, username:string, password:string, signUpUserForApp:boolean) : Promise<ILoginResult> {
		let params: IUserLoginParams = {
			response_type : response_type
			,username: username
			,password: password
			,signUpUserForApp: signUpUserForApp
		};
		return this.$P("/services/authorize/user_login", params);
	}
	automationLogin(username:string, password:string) : Promise<ILoginResult> {
		let params: IAutomationLoginParams = {
			username: username
			,password: password
		};
		return this.$P("/services/authorize/automation_login", params);
	}
	getAccessFromAuthCode(code:string) : Promise<oauth2.Access> {
		let params: IGetAccessFromCodeParams = {code: code};
		return this.$P("/services/authorize/get_access_from_auth_code", params);
	}
	refreshToken(refresh_token:string) : Promise<oauth2.Access> {
		let params:IRefreshTokenParams = {refresh_token : refresh_token};
		return this.$P("/services/authorize/refresh_token", params);
	}

	SSPR(username:string) : Promise<IResetPasswordParams> {
		let params: IUsernameParams = {username};
		return this.$P("/services/authorize/sspr", params);
	}
	resetPassword(pin:string, done:(err:any) => void) : Promise<any> {
		let params:IResetPasswordParams = {pin};
		return this.$P("/services/authorize/reset_password", params);
	}
	lookupUser(username:string) : Promise<IAuthorizedUser> {
		let params: IUsernameParams = {username};
		return this.$P("/services/authorize/lookup_user", params);		
	}
	signUpNewUser(accountOptions:IAccountOptions) : Promise<IAuthorizedUser> {
		let params = accountOptions;
		return this.$P("/services/authorize/sign_up_new_user", params);			
	};
}

export class TokenVerifier {
	constructor(public options:restIntf.ConnectOptions) {}
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
	get instance_url():string {return (this.options && this.options.instance_url ? this.options.instance_url : '');}
	private get connectOptions(): restIntf.ApiCallOptions {
		let ret: restIntf.ApiCallOptions = {
			headers: {}
		}
		if (this.options && typeof this.options.rejectUnauthorized) ret.rejectUnauthorized = this.options.rejectUnauthorized;
		return ret;
	}
	// POST
	private $P(path:string, data: any) : Promise<any> {
		return $J('POST', this.instance_url + path, data, this.connectOptions).then((restReturn: restIntf.RESTReturn) => restReturn.data);
	}
	verifyAccessToken(accessToken: oauth2.AccessToken) : Promise<IAuthorizedUser> {
		let params = accessToken;
		return this.$P("/services/token/verify", params);
	}
}