const trim=(value:string)=>value.replace(/\/+$/,'');
export const API=trim(import.meta.env.VITE_CONTROL_API_URL || (import.meta.env.DEV?'http://localhost:8080':''));
export const ISSUER=trim(import.meta.env.VITE_OIDC_ISSUER || (import.meta.env.DEV?'http://localhost:8081/auth/v1':'https://auth.makersbrain.app/auth/v1'));
export const CLIENT_ID=import.meta.env.VITE_OIDC_CLIENT_ID || 'makersbrain-members';
export const REDIRECT_URI=import.meta.env.VITE_OIDC_REDIRECT_URI || (import.meta.env.DEV?'http://localhost:4175/oauth/callback':'https://account.makersbrain.app/oauth/callback');
