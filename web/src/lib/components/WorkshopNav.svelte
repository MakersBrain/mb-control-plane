<script lang="ts">
	import { page } from '$app/state';
	let { id }: { id: string } = $props();
	const links = $derived([
		{ href: `/workshops/${id}/members`, label: 'People & access' },
		{ href: `/workshops/${id}/modules`, label: 'Modules' },
		{ href: `/workshops/${id}/database`, label: 'Recovery' }
	]);
</script>

<nav class="tabs" aria-label="Workshop navigation">
	{#each links as link}
		<a href={link.href} class:active={page.url.pathname === link.href} aria-current={page.url.pathname === link.href ? 'page' : undefined}>{link.label}</a>
	{/each}
</nav>
