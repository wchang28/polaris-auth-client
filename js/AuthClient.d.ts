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
    getError(httpErr: any): any;
    static getClientAppHeaderField(): string;
    private readonly connectOptions;
    private $P(path, data, done);
    getConnectedApp(done: (err: any, connectedApp: IConnectedApp) => void): void;
    userLogin(response_type: oauth2.AuthResponseType, username: string, password: string, signUpUserForApp: boolean, done: (err: any, ret: ILoginResult) => void): void;
    automationLogin(username: string, password: string, done: (err: any, ret: ILoginResult) => void): void;
    getAccessFromAuthCode(code: string, done: (err: any, access: oauth2.Access) => void): void;
    refreshToken(refresh_token: string, done: (err: any, access: oauth2.Access) => void): void;
    verifyAccessToken(accessToken: oauth2.AccessToken, done: (err: any, user: IAuthorizedUser) => void): void;
    SSPR(username: string, done: (err: any, params: IResetPasswordParams) => void): void;
    resetPassword(pin: string, done: (err: any) => void): void;
    lookupUser(username: string, done: (err: any, user: IAuthorizedUser) => void): void;
    signUpNewUser(accountOptions: IAccountOptions, done: (err: any, user: IAuthorizedUser) => void): void;
}
