import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: 'https://pete-builds.github.io',
  base: '/mcp-unifi',
  integrations: [
    starlight({
      title: 'mcp-unifi',
      description: 'Self-hosted UniFi MCP server. Multi-site config, dry-run previews, JSONL audit log. Network + Protect.',
      social: [
        { icon: 'github', label: 'GitHub', href: 'https://github.com/pete-builds/mcp-unifi' }
      ],
      sidebar: [
        { label: 'Getting Started', link: '/getting-started/' },
        {
          label: 'Install',
          items: [
            { label: 'Docker', link: '/install/docker/' },
            { label: 'Claude Desktop (.dxt)', link: '/install/dxt/' },
            { label: 'Helm', link: '/install/helm/' },
            { label: 'uvx / pipx', link: '/install/uvx/' },
          ],
        },
        {
          label: 'Guides',
          items: [
            { label: 'Multi-Site Setup', link: '/guides/multi-site/' },
            { label: 'Dry-Run & Audit Log', link: '/guides/dry-run-audit/' },
            { label: 'Security Model', link: '/guides/security/' },
            { label: 'Migrate from v0.x', link: '/guides/migration/' },
          ],
        },
        {
          label: 'Recipes',
          items: [
            { label: 'Claude Desktop', link: '/recipes/claude-desktop/' },
            { label: 'Claude Code', link: '/recipes/claude-code/' },
            { label: 'Cursor', link: '/recipes/cursor/' },
            { label: 'Cline', link: '/recipes/cline/' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { label: 'Network Tools', link: '/reference/network/' },
            { label: 'Protect Tools', link: '/reference/protect/' },
            { label: 'Configuration', link: '/reference/configuration/' },
            { label: 'Tool Manifest (auto)', link: '/tools/' },
          ],
        },
        { label: 'Changelog', link: '/changelog/' },
      ],
      editLink: {
        baseUrl: 'https://github.com/pete-builds/mcp-unifi/edit/main/docs/site/',
      },
    }),
  ],
});
