type MakersBrainRuntimeConfig = {
	api: string;
	issuer: string;
	clientId: string;
	redirectUri: string;
	accountUrl: string;
};

declare global {
	var __MAKERSBRAIN_CONFIG__: MakersBrainRuntimeConfig | undefined;
	namespace App {}
}
export {};
