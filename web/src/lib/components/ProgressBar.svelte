<script lang="ts">
	let { value = 0, label = 'Operation progress' }: { value?: number; label?: string } = $props();
	const bounded = $derived(Math.min(100, Math.max(0, value)));
</script>

<div class="progress-track" role="progressbar" aria-label={label} aria-valuemin="0" aria-valuemax="100" aria-valuenow={bounded}>
	<span style={`width:${bounded}%`}></span>
</div>
