const trim=(value:string)=>value.replace(/\/+$/,'');
const runtime=globalThis.__MAKERSBRAIN_CONFIG__;
const required=(name:string,value:string|undefined,development:string)=>{
	const selected=value || (import.meta.env.DEV?development:'');
	if(!selected)throw new Error(`Missing browser runtime configuration: ${name}`);
	return selected;
};
export const API=trim(required('api',runtime?.api || import.meta.env.VITE_CONTROL_API_URL,'http://localhost:8080'));
export const ISSUER=trim(required('issuer',runtime?.issuer || import.meta.env.VITE_OIDC_ISSUER,'http://localhost:8081/auth/v1'));
export const CLIENT_ID=required('clientId',runtime?.clientId || import.meta.env.VITE_OIDC_CLIENT_ID,'makersbrain-members');
export const REDIRECT_URI=required('redirectUri',runtime?.redirectUri || import.meta.env.VITE_OIDC_REDIRECT_URI,'http://localhost:4175/oauth/callback');
export const ACCOUNT_URL=trim(required('accountUrl',runtime?.accountUrl || import.meta.env.VITE_ACCOUNT_URL,'http://rauthy.localhost:8092'));
