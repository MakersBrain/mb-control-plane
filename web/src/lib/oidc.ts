import { CLIENT_ID,ISSUER,REDIRECT_URI } from './config';
const ATTEMPT='makersbrain.members.oauth-attempt',REFRESH='makersbrain.members.refresh-token';
type Attempt={verifier:string;state:string;returnTo:string};
export type Tokens={access_token:string;refresh_token?:string;expires_in:number;id_token?:string};
const b64=(bytes:Uint8Array)=>{let binary='';for(const byte of bytes)binary+=String.fromCharCode(byte);return btoa(binary).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')};
const random=()=>{const bytes=new Uint8Array(32);crypto.getRandomValues(bytes);return b64(bytes)};
const challenge=async(verifier:string)=>b64(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(verifier))));
export async function signIn(returnTo:string){const verifier=random(),state=random();sessionStorage.setItem(ATTEMPT,JSON.stringify({verifier,state,returnTo}));const query=new URLSearchParams({response_type:'code',client_id:CLIENT_ID,redirect_uri:REDIRECT_URI,scope:'openid profile email',state,code_challenge:await challenge(verifier),code_challenge_method:'S256'});location.assign(`${ISSUER}/oidc/authorize?${query}`)}
async function token(body:Record<string,string>):Promise<Tokens>{const response=await fetch(`${ISSUER}/oidc/token`,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams(body)});if(!response.ok)throw new Error('Sign-in was refused or expired');return response.json()}
export async function callback(code:string,state:string){const raw=sessionStorage.getItem(ATTEMPT);sessionStorage.removeItem(ATTEMPT);if(!raw)throw new Error('No sign-in was pending');const attempt=JSON.parse(raw) as Attempt;if(attempt.state!==state)throw new Error('Sign-in state mismatch');return {tokens:await token({grant_type:'authorization_code',code,redirect_uri:REDIRECT_URI,client_id:CLIENT_ID,code_verifier:attempt.verifier}),returnTo:attempt.returnTo}}
export async function refresh(){const value=sessionStorage.getItem(REFRESH);if(!value)return null;return token({grant_type:'refresh_token',refresh_token:value,client_id:CLIENT_ID})}
export function remember(value:Tokens){if(value.refresh_token)sessionStorage.setItem(REFRESH,value.refresh_token)}
export function forget(){sessionStorage.removeItem(REFRESH)}
export function logoutUrl(idToken:string|null){const query=new URLSearchParams({post_logout_redirect_uri:REDIRECT_URI.replace('/oauth/callback','/signed-out')});if(idToken)query.set('id_token_hint',idToken);return `${ISSUER}/oidc/logout?${query}`}
