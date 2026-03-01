import { defineConfig } from 'vitepress'
import { withMermaid } from 'vitepress-plugin-mermaid'

export default withMermaid(
  defineConfig({
    vite: {
      optimizeDeps: {
        include: ['mermaid'],
      },
    },

    title: 'tiltshift',
    description: 'Iterative structure extraction from opaque binary data',

    base: '/tiltshift/',

    head: [
      ['link', { rel: 'icon', type: 'image/svg+xml', href: '/tiltshift/logo.svg' }],
    ],

    themeConfig: {
      nav: [
        { text: 'Guide', link: '/introduction' },
        { text: 'Signals', link: '/signals' },
        { text: 'CLI', link: '/cli/' },
        { text: 'rhi', link: 'https://docs.rhi.zone/' },
      ],

      sidebar: {
        '/': [
          {
            text: 'Guide',
            items: [
              { text: 'Introduction', link: '/introduction' },
            ],
          },
          {
            text: 'Signal Reference',
            items: [
              { text: 'Overview', link: '/signals' },
            ],
          },
          {
            text: 'CLI Reference',
            items: [
              { text: 'analyze', link: '/cli/analyze' },
              { text: 'probe', link: '/cli/probe' },
              { text: 'scan', link: '/cli/scan' },
              { text: 'magic', link: '/cli/magic' },
              { text: 'obfuscate', link: '/cli/obfuscate' },
              { text: 'region', link: '/cli/region' },
              { text: 'descend', link: '/cli/descend' },
              { text: 'diff', link: '/cli/diff' },
            ],
          },
        ],
      },

      socialLinks: [
        { icon: 'github', link: 'https://github.com/rhi-zone/tiltshift' },
      ],

      search: {
        provider: 'local',
      },

      editLink: {
        pattern: 'https://github.com/rhi-zone/tiltshift/edit/master/docs/:path',
        text: 'Edit this page on GitHub',
      },
    },
  }),
)
