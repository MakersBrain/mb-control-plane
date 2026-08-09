<script lang="ts">
	import { page } from '$app/state';
	const links = [
		{ href: '/platform', label: 'Overview' },
		{ href: '/platform/workshops', label: 'Workshops' },
		{ href: '/platform/users', label: 'Accounts' },
		{ href: '/platform/operations', label: 'Operations' },
		{ href: '/platform/status', label: 'Health' },
		{ href: '/platform/email', label: 'Email' },
		{ href: '/platform/audit', label: 'Audit journal' }
	];
	const active = (href: string) => href === '/platform' ? page.url.pathname === href : page.url.pathname.startsWith(href);
</script>

<nav class="tabs" aria-label="Platform operator navigation">{#each links as link}<a href={link.href} class:active={active(link.href)} aria-current={active(link.href) ? 'page' : undefined}>{link.label}</a>{/each}</nav>
