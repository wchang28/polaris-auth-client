import * as oauth2 from 'oauth2';
export interface IAuthorizeEndpointOptions {
    baseUrl: string;
    rejectUnauthorized?: boolean;
}
export interface IConnectedApp {
    client_id: string;
    name: string;
    allow_reset_pswd: boolean;
    allow_create_new_user: boolean;
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
export declare class AuthClient {
    options: IAuthorizeEndpointOptions;
    clientAppSettings: oauth2.ClientAppSettings;
    private $J;
    private static CLIENT_APP_HEADER_FLD;
    constructor(jQuery: any, options: IAuthorizeEndpointOptions, clientAppSettings: oauth2.ClientAppSettings);
    redirect_uri: string;
    getError(httpErr: any): any;
    static getClientAppHeaderField(): string;
    private $P(path, data, done);
    getConnectedApp(done: (err: any, connectedApp: IConnectedApp) => void): void;
    userLogin(response_type: oauth2.AuthResponseType, username: string, password: string, signUpUserForApp: boolean, done: (err: any, ret: ILoginResult) => void): void;
    automationLogin(username: string, password: string, done: (err: any, ret: ILoginResult) => void): void;
    getAccessFromAuthCode(code: string, done: (err: any, access: oauth2.Access) => void): void;
    refreshToken(refresh_token: string, done: (err: any, access: oauth2.Access) => void): void;
    verifyAccessToken(accessToken: oauth2.AccessToken, done: (err: any, user: IAuthorizedUser) => void): void;
    SSPR(username: string, done: (err: any, data: any) => void): void;
    resetPassword(pin: string, done: (err: any, data: any) => void): void;
    lookupUser(username: string, done: (err: any, data: any) => void): void;
    signUpNewUser(accountOptions: any, done: (err: any, data: any) => void): void;
}
