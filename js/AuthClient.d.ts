import * as oauth2 from 'oauth2';
import * as restIntf from 'rest-api-interfaces';
export { ConnectOptions as IAuthorizeEndpointOptions } from 'rest-api-interfaces';
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
    response_type: oauth2.AuthResponseType;
    signUpUserForApp: boolean;
}
export interface ILoginResult {
    user: IAuthorizedUser;
    access?: oauth2.Access;
    code?: string;
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
    firstName: string;
    lastName: string;
    email: string;
    username: string;
    password: string;
    companyName?: string;
    mobilePhone?: string;
    promotionalMaterial?: boolean;
}
export declare class AuthClient {
    options: restIntf.ConnectOptions;
    clientAppSettings: oauth2.ClientAppSettings;
    private static CLIENT_APP_HEADER_FLD;
    constructor(options: restIntf.ConnectOptions, clientAppSettings: oauth2.ClientAppSettings);
    readonly instance_url: string;
    readonly redirect_uri: string;
    static getClientAppHeaderField(): string;
    private readonly connectOptions;
    private $P(path, data);
    getConnectedApp(): Promise<IConnectedApp>;
    userLogin(response_type: oauth2.AuthResponseType, username: string, password: string, signUpUserForApp: boolean): Promise<ILoginResult>;
    automationLogin(username: string, password: string): Promise<ILoginResult>;
    getAccessFromAuthCode(code: string): Promise<oauth2.Access>;
    refreshToken(refresh_token: string): Promise<oauth2.Access>;
    SSPR(username: string): Promise<IResetPasswordParams>;
    resetPassword(pin: string): Promise<any>;
    lookupUser(username: string): Promise<IAuthorizedUser>;
    signUpNewUser(accountOptions: IAccountOptions): Promise<IAuthorizedUser>;
}
export declare class TokenVerifier {
    options: restIntf.ConnectOptions;
    constructor(options: restIntf.ConnectOptions);
    getError(httpErr: any): any;
    readonly instance_url: string;
    private readonly connectOptions;
    private $P(path, data);
    verifyAccessToken(accessToken: oauth2.AccessToken): Promise<IAuthorizedUser>;
}
