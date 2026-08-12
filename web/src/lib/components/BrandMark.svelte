<script lang="ts">
	// The weave: two strands crossing over and under. Kept inline rather than
	// loaded as an image so it inherits the current text colour, which is what
	// lets the same file sit on the topbar, on a dark ground, and in a
	// single-colour context without three separate assets.
	//
	// Source of truth: brand/logo/weave.svg. Regenerate with brand/build-logo.py.
	let { size = '1.35em' }: { size?: string } = $props();
</script>

<svg
	class="brand-mark"
	style:width={size}
	style:height={size}
	viewBox="0 0 32 32"
	aria-hidden="true"
	focusable="false"
>
	<path d="M3 3h26v6H9v20H3Z" fill="currentColor" />
	<path d="M29 29H3v-6h20V3h6Z" fill="var(--mb-brand)" />
	<path d="M23 3h6v6h-6Z" fill="currentColor" />
</svg>
