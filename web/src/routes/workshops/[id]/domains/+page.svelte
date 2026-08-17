<script lang="ts">
	import { page } from '$app/state';
	import WorkshopNav from '$lib/components/WorkshopNav.svelte';
	import StatusBadge from '$lib/components/StatusBadge.svelte';
	import OperationCard from '$lib/components/OperationCard.svelte';
	import { request } from '$lib/session.svelte';
	import type { WorkshopSummary } from '$lib/types';

	type Domain = {
		id?: string; hostname: string; kind: string; state: string; desired_state: string;
		dns_state: string; certificate_state: string; verification_name?: string;
		verification_value?: string; routing_name?: string; routing_target?: string;
		ownership_verified_at?: string; last_health_checked_at?: string;
		last_error_class?: string; canonical: boolean; version: number; can_manage: boolean;
		edge_verification_records: { type: string; name: string; value: string }[];
		operation_id?: string;
	};
	type EmailDomain = {
		id: string; domain_name: string; sender_local_part: string; state: string; desired_state: string;
		provider_status?: string; dns_records: Record<string, { name?: string; value?: string }>;
		verification: Record<string, { status?: string; error?: string }>;
		test_delivered_at?: string; last_error_class?: string; operation_id?: string; version: number; can_manage: boolean;
	};
	type SmtpStatus = {
		transport: 'platform' | 'smtp'; configured: boolean; host?: string; port?: number;
		encryption?: 'starttls' | 'ssl'; username?: string; from_email?: string;
		password_configured: boolean;
	};

	const id = $derived(page.params.id ?? '');
	let workshop = $state<WorkshopSummary>();
	let domains = $state<Domain[]>([]);
	let emailDomains = $state<EmailDomain[]>([]);
	let smtp = $state<SmtpStatus>();
	let hostname = $state('');
	let emailDomain = $state('');
	let senderLocalPart = $state('bonjour');
	let smtpHost = $state('');
	let smtpPort = $state(587);
	let smtpEncryption = $state<'starttls' | 'ssl'>('starttls');
	let smtpUsername = $state('');
	let smtpPassword = $state('');
	let smtpFrom = $state('');
	let error = $state('');
	let notice = $state('');
	let busy = $state('');

	$effect(() => { id; void load(); });

	async function load() {
		try {
			[workshop, domains, emailDomains, smtp] = await Promise.all([
				request<WorkshopSummary>(`/v1/workshops/${id}`),
				request<Domain[]>(`/v1/workshops/${id}/domains`),
				request<EmailDomain[]>(`/v1/workshops/${id}/email-domains`),
				request<SmtpStatus>(`/v1/workshops/${id}/email/smtp`)
			]);
			if (smtp?.configured && !smtpHost) {
				smtpHost = smtp.host ?? ''; smtpPort = smtp.port ?? 587;
				smtpEncryption = smtp.encryption ?? 'starttls'; smtpUsername = smtp.username ?? '';
				smtpFrom = smtp.from_email ?? '';
			}
			error = '';
		} catch (cause) { error = cause instanceof Error ? cause.message : String(cause); }
	}
	async function addEmailDomain() {
		busy = 'add-email'; error = ''; notice = '';
		try { await request(`/v1/workshops/${id}/email-domains`, { method: 'POST', headers: {'idempotency-key': crypto.randomUUID()}, body: JSON.stringify({ domain_name: emailDomain, sender_local_part: senderLocalPart }) }); emailDomain = ''; notice = 'Sender domain registration queued. Publish the DNS records below when they appear.'; await load(); }
		catch (cause) { error = cause instanceof Error ? cause.message : String(cause); } finally { busy = ''; }
	}
	async function checkEmailDomain(domain: EmailDomain) { busy = domain.id; error=''; notice=''; try { await request(`/v1/workshops/${id}/email-domains/${domain.id}/check`, {method:'POST',headers:{'idempotency-key':crypto.randomUUID()}}); notice='Verification check queued. A test message is sent before activation once all required records are valid.'; await load(); } catch(cause){error=cause instanceof Error?cause.message:String(cause)} finally{busy=''} }
	async function disconnectEmailDomain(domain: EmailDomain) { if(!confirm(`Disconnect ${domain.domain_name} from the MakersBrain relay? Your selected SMTP or relay transport will not change.`))return; busy=domain.id; error=''; try{await request(`/v1/workshops/${id}/email-domains/${domain.id}`,{method:'DELETE',headers:{'idempotency-key':crypto.randomUUID()}});notice='Sender-domain disconnect queued. Your selected SMTP or relay transport is unchanged.';await load()}catch(cause){error=cause instanceof Error?cause.message:String(cause)}finally{busy=''} }
	async function saveSmtp() {
		busy='smtp'; error=''; notice='';
		try {
			await request(`/v1/workshops/${id}/email/smtp`, {method:'POST', headers:{'idempotency-key':crypto.randomUUID()}, body:JSON.stringify({host:smtpHost,port:smtpPort,encryption:smtpEncryption,username:smtpUsername,password:smtpPassword,from_email:smtpFrom})});
			smtpPassword=''; notice='SMTP credentials verified and activated. The password is stored in Odoo and is never returned by this screen.'; await load();
		} catch(cause) { error=cause instanceof Error?cause.message:String(cause); } finally { busy=''; }
	}
	async function resetSmtp() {
		if(!confirm('Remove the merchant SMTP credential and return to the MakersBrain relay?')) return;
		busy='smtp-reset'; error=''; notice='';
		try { await request(`/v1/workshops/${id}/email/smtp`, {method:'DELETE',headers:{'idempotency-key':crypto.randomUUID()}}); smtpPassword=''; smtpHost=''; smtpUsername=''; smtpFrom=''; notice='Merchant SMTP removed. Transactional mail now uses the MakersBrain relay.'; await load(); }
		catch(cause){error=cause instanceof Error?cause.message:String(cause)} finally{busy=''}
	}

	async function add() {
		busy = 'add'; error = ''; notice = '';
		try {
			await request(`/v1/workshops/${id}/domains`, {
				method: 'POST', headers: { 'idempotency-key': crypto.randomUUID() },
				body: JSON.stringify({ hostname })
			});
			hostname = '';
			notice = 'Domain reserved. Publish the ownership TXT record shown below, then verify it.';
			await load();
		} catch (cause) { error = cause instanceof Error ? cause.message : String(cause); }
		finally { busy = ''; }
	}

	async function verify(domain: Domain) {
		if (!domain.id) return;
		busy = domain.id; error = ''; notice = '';
		try {
			const observed = await request<Domain>(`/v1/workshops/${id}/domains/${domain.id}/verify`, {
				method: 'POST', headers: { 'idempotency-key': crypto.randomUUID() }
			});
			notice = observed.ownership_verified_at
				? 'Ownership verified. Publish the routing record shown below while certificate provisioning continues.'
				: 'The ownership record is not visible yet. DNS propagation can take time; retry without changing the token.';
			await load();
		} catch (cause) { error = cause instanceof Error ? cause.message : String(cause); }
		finally { busy = ''; }
	}

	async function makeCanonical(domain: Domain) {
		if (!domain.id) return;
		busy = domain.id; error = ''; notice = '';
		try {
			await request(`/v1/workshops/${id}/domains/${domain.id}/canonical`, {
				method: 'POST', headers: {
					'idempotency-key': crypto.randomUUID(),
					'if-match': `"webshop-domain-${domain.id}-v${domain.version}"`
				}
			});
			notice = 'Canonical address change queued. Secondary addresses will redirect after exact-host reconciliation succeeds.';
			await load();
		} catch (cause) { error = cause instanceof Error ? cause.message : String(cause); }
		finally { busy = ''; }
	}

	async function disconnect(domain: Domain) {
		if (!domain.id || !confirm(`Disconnect ${domain.hostname}? Its MakersBrain route and certificate will be removed. Your ownership record is not changed.`)) return;
		busy = domain.id; error = ''; notice = '';
		try {
			await request(`/v1/workshops/${id}/domains/${domain.id}`, {
				method: 'DELETE', headers: {
					'idempotency-key': crypto.randomUUID(),
					'if-match': `"webshop-domain-${domain.id}-v${domain.version}"`
				}
			});
			notice = domain.canonical
				? 'Disconnect queued. The MakersBrain address will become canonical before the provider hostname is retired.'
				: 'Disconnect queued. The exact custom-host route will be removed before the provider hostname is retired.';
			await load();
		} catch (cause) { error = cause instanceof Error ? cause.message : String(cause); }
		finally { busy = ''; }
	}

	async function copy(value?: string) {
		if (value) { await navigator.clipboard.writeText(value); notice = 'Copied to clipboard.'; }
	}
</script>

<svelte:head><title>Domains · {workshop?.display_name || 'MakersBrain'}</title></svelte:head>
<p><a href="/">← Workshops</a></p>
<header class="page-header"><div><p class="eyebrow">{workshop?.display_name ?? 'Workshop'}</p><h1>Webshop domains</h1><p class="muted">Connect an address you already own. MakersBrain verifies ownership before routing any customer traffic.</p></div><button class="secondary" onclick={load}>Refresh</button></header>
<WorkshopNav {id} />
{#if error}<p class="error" role="alert">{error}</p>{/if}
{#if notice}<p class="notice" role="status">{notice}</p>{/if}

<section class="card stack add-domain">
	<h2>Connect a domain</h2>
	<label>Domain or subdomain<input bind:value={hostname} placeholder="www.atelier-luna.fr" autocomplete="url" /></label>
	<button disabled={busy !== '' || hostname.trim().length < 4} onclick={add}>{busy === 'add' ? 'Reserving…' : 'Continue'}</button>
	<p class="muted">Enter only the hostname. International names are stored safely in their DNS form. IP addresses, public suffixes, reserved names and MakersBrain zones are rejected.</p>
</section>

<section class="section"><div class="section-header"><div><h2>Transactional email sender</h2><p class="muted">Use the MakersBrain relay, connect your existing SMTP provider, or verify a branded sender domain for the relay.</p></div></div>
	<article class="card stack add-domain">
		<div class="row"><div><h3>Use your SMTP provider</h3><p class="muted">Application passwords are accepted once and never displayed again. MakersBrain requires certificate-validated TLS.</p></div>{#if smtp}<StatusBadge state={smtp.transport === 'smtp' && smtp.configured ? 'active' : 'platform'} />{/if}</div>
		<div class="row"><label>SMTP hostname<input bind:value={smtpHost} placeholder="smtp.example.fr" autocomplete="url" /></label><label>Port<input type="number" min="1" max="65535" bind:value={smtpPort} /></label></div>
		<label>Encryption<select bind:value={smtpEncryption} onchange={() => { smtpPort = smtpEncryption === 'ssl' ? 465 : 587; }}><option value="starttls">STARTTLS (certificate validated)</option><option value="ssl">SSL/TLS (certificate validated)</option></select></label>
		<div class="row"><label>Username<input bind:value={smtpUsername} autocomplete="username" /></label><label>From address<input type="email" bind:value={smtpFrom} autocomplete="email" /></label></div>
		<label>{smtp?.password_configured ? 'New password (required to rotate)' : 'Password'}<input type="password" bind:value={smtpPassword} autocomplete="new-password" /></label>
		<div class="actions"><button disabled={busy !== '' || !smtpHost || !smtpUsername || !smtpFrom || !smtpPassword} onclick={saveSmtp}>{busy === 'smtp' ? 'Testing…' : smtp?.configured ? 'Test and rotate SMTP' : 'Test and activate SMTP'}</button>{#if smtp?.configured}<button class="secondary" disabled={busy !== ''} onclick={resetSmtp}>Use MakersBrain relay</button>{/if}</div>
		<p class="muted">The connection, login, sender, and relay permission are tested before activation. Private-network and reserved SMTP hosts are rejected.</p>
	</article>
	<article class="card stack add-domain">
		<div class="row"><label>Domain<input bind:value={emailDomain} placeholder="atelier-luna.fr" autocomplete="url" /></label><label>Address<input bind:value={senderLocalPart} placeholder="bonjour" autocomplete="off" /></label></div>
		<button disabled={busy !== '' || emailDomain.trim().length < 4} onclick={addEmailDomain}>{busy === 'add-email' ? 'Registering…' : 'Connect sender domain'}</button>
	</article>
	{#if emailDomains.length === 0}<p class="muted">Current transport: {smtp?.transport === 'smtp' ? `merchant SMTP at ${smtp.host}` : 'Atelier via MakersBrain (platform verified domain)'}.</p>{/if}
	{#each emailDomains as domain (domain.id)}
		<article class="card stack domain">
			<div class="row"><div><strong>{domain.sender_local_part}@{domain.domain_name}</strong><div class="muted">Provider: {domain.provider_status ?? 'registration pending'}</div></div><StatusBadge state={domain.state} /></div>
			{#each Object.entries(domain.dns_records ?? {}) as [kind, record]}
				{#if record?.name && record?.value}<div class="record"><div><span class="muted">{kind.toUpperCase()} · {record.name}</span><code>{record.value}</code></div><button class="secondary" onclick={() => copy(record.value)}>Copy value</button></div>{/if}
			{/each}
			<div class="states">{#each Object.entries(domain.verification ?? {}) as [kind, observed]}{#if kind.endsWith('_record')}<span>{kind.replace('_record','').toUpperCase()} <StatusBadge state={observed?.status ?? 'unknown'} /></span>{/if}{/each}</div>
			{#if domain.test_delivered_at}<p class="muted">Test delivery confirmed {new Date(domain.test_delivered_at).toLocaleString()}.</p>{/if}
			{#if domain.state !== 'active'}<button disabled={!domain.can_manage || busy !== ''} onclick={() => checkEmailDomain(domain)}>{busy === domain.id ? 'Checking…' : 'Check DNS and test'}</button>{/if}
			<button class="secondary" disabled={!domain.can_manage || busy !== ''} onclick={() => disconnectEmailDomain(domain)}>Disconnect sender domain</button>
			{#if domain.last_error_class}<p class="error">{domain.last_error_class.replaceAll('_',' ')}</p>{/if}
			{#if domain.operation_id}<OperationCard id={domain.operation_id} compact onsettled={load} />{/if}
		</article>
	{/each}
</section>

<section class="section"><div class="section-header"><div><h2>Addresses</h2><p class="muted">Desired and observed state are kept separately so interrupted DNS or certificate work can recover.</p></div></div>
	{#each domains as domain (domain.id ?? domain.hostname)}
		<article class="card stack domain">
			<div class="row"><div><strong>{domain.hostname}</strong><div class="muted">{domain.kind === 'platform_subdomain' ? 'MakersBrain address' : domain.canonical ? 'Canonical custom address' : 'Custom address'}</div></div><StatusBadge state={domain.state} /></div>
			<div class="states"><span>DNS <StatusBadge state={domain.dns_state} /></span><span>Certificate <StatusBadge state={domain.certificate_state} /></span></div>
			{#if domain.state === 'ownership_pending'}
				<p>Add this TXT record at your DNS provider. Keep it in place until ownership is verified.</p>
				<div class="record"><div><span class="muted">Name</span><code>{domain.verification_name}</code></div><button class="secondary" onclick={() => copy(domain.verification_name)}>Copy</button></div>
				<div class="record"><div><span class="muted">Value</span><code>{domain.verification_value}</code></div><button class="secondary" onclick={() => copy(domain.verification_value)}>Copy</button></div>
				<button disabled={!domain.can_manage || busy !== ''} onclick={() => verify(domain)}>{busy === domain.id ? 'Checking…' : 'Verify ownership'}</button>
			{:else if domain.kind === 'custom_domain' && domain.state !== 'active'}
				<p>Publish the routing record while MakersBrain prepares and tests the certificate.</p>
				<div class="record"><div><span class="muted">CNAME name</span><code>{domain.routing_name}</code></div><button class="secondary" onclick={() => copy(domain.routing_name)}>Copy</button></div>
				<div class="record"><div><span class="muted">CNAME target</span><code>{domain.routing_target}</code></div><button class="secondary" onclick={() => copy(domain.routing_target)}>Copy</button></div>
				{#if domain.state === 'action_required'}
					<button disabled={!domain.can_manage || busy !== ''} onclick={() => verify(domain)}>{busy === domain.id ? 'Checking…' : 'Retry verification and provisioning'}</button>
				{/if}
			{/if}
			{#if domain.edge_verification_records?.length}
				<p>Cloudflare also requires these records to activate the hostname and issue its certificate.</p>
				{#each domain.edge_verification_records as record}
					<div class="record"><div><span class="muted">{record.type} · {record.name}</span><code>{record.value}</code></div><button class="secondary" onclick={() => copy(record.value)}>Copy value</button></div>
				{/each}
			{/if}
			{#if domain.kind === 'custom_domain' && domain.state === 'active' && !domain.canonical}
				<button disabled={!domain.can_manage || busy !== ''} onclick={() => makeCanonical(domain)}>{busy === domain.id ? 'Updating…' : 'Make canonical'}</button>
			{/if}
			{#if domain.kind === 'custom_domain' && domain.desired_state === 'active'}
				<button class="secondary" disabled={!domain.can_manage || busy !== ''} onclick={() => disconnect(domain)}>{busy === domain.id ? 'Updating…' : 'Disconnect domain'}</button>
			{/if}
			{#if domain.last_error_class}<p class="error">{domain.last_error_class.replaceAll('_', ' ')}</p>{/if}
			{#if domain.operation_id}<OperationCard id={domain.operation_id} compact onsettled={load} />{/if}
		</article>
	{/each}
</section>

<style>
	.add-domain{max-width:44rem}.domain{margin-bottom:1rem}.states{display:flex;gap:1.5rem;flex-wrap:wrap}.states span{display:flex;align-items:center;gap:.5rem}.record{display:flex;align-items:center;justify-content:space-between;gap:1rem;padding:.75rem;border:1px solid var(--border);border-radius:.5rem}.record div{display:grid;gap:.25rem;min-width:0}.record code{overflow-wrap:anywhere}
</style>
