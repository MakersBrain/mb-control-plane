export type WorkshopRole = 'viewer' | 'artisan' | 'accountant' | 'studio_manager' | 'owner';

export interface Me {
	id: string;
	email: string;
	subject: string;
	is_operator: boolean;
}

export interface WorkshopSummary {
	id: string;
	slug: string;
	display_name: string;
	status: string;
	plan: string;
	version: number;
	role: WorkshopRole;
	authority_epoch: number;
}

export interface Operation {
	id: string;
	kind: string;
	state: string;
	workshop_id?: string;
	attempt: number;
	max_attempts: number;
	failure_class?: string;
	created_at: string;
	finished_at?: string;
	progress_percent?: number;
	progress_phase?: string;
	progress_message?: string;
	progress_updated_at?: string;
}

export interface TargetState {
	state: string;
	desired_epoch: number;
	applied_epoch: number;
	error?: string;
	observed_at?: string;
}

export interface Member {
	id: string;
	email: string;
	display_name?: string;
	role: WorkshopRole;
	status: string;
	authority_epoch: number;
	targets: Record<string, TargetState>;
	operation_id?: string;
	operation_state?: string;
}

export interface Integration {
	service: string;
	url: string;
	health: string;
	desired_epoch: number;
	applied_epoch: number;
	error?: string;
}
