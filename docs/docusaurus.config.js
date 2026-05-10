// @ts-check
// =============================================================================
// docusaurus.config.js — EASM Platform Dokumentation
// Inspired by: https://ionicframework.com/docs
// =============================================================================

const lightCodeTheme  = require('prism-react-renderer').themes.github;
const darkCodeTheme   = require('prism-react-renderer').themes.dracula;

/** @type {import('@docusaurus/types').Config} */
const config = {
  title:           'EASM MSSP Platform',
  tagline:         'External Attack Surface Management — Dokumentation',
  favicon:         'img/favicon.ico',
  url:             'https://docs.easm.example.de',
  baseUrl:         '/',
  onBrokenLinks:   'throw',
  onBrokenMarkdownLinks: 'warn',
  i18n: {
    defaultLocale: 'de',
    locales: ['de', 'en'],
  },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          sidebarPath:       require.resolve('./sidebars.js'),
          routeBasePath:     '/',            // Docs auf Root-Pfad
          showLastUpdateTime: true,
          showLastUpdateAuthor: false,
        },
        blog: false,                         // Kein Blog
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      colorMode: {
        defaultMode:             'dark',
        disableSwitch:           false,
        respectPrefersColorScheme: true,
      },
      navbar: {
        title: '',
        logo: {
          alt: 'EASM Platform',
          src: 'img/logo.svg',
          srcDark: 'img/logo.svg',
        },
        items: [
          {
            type:      'docSidebar',
            sidebarId: 'mainSidebar',
            position:  'left',
            label:     'Dokumentation',
          },
          {
            href:     'https://your-domain.de',
            label:    'Platform öffnen',
            position: 'right',
          },
          {
            href:     'https://github.com/your-org/easm-platform',
            label:    'GitHub',
            position: 'right',
          },
        ],
      },
      footer: {
        style: 'dark',
        links: [
          {
            title: 'Dokumentation',
            items: [
              { label: 'Installation',     to: '/getting-started/installation' },
              { label: 'Konfiguration',    to: '/getting-started/configuration' },
              { label: 'Architektur',      to: '/architecture/overview' },
              { label: 'API-Referenz',     to: '/api/authentication' },
            ],
          },
          {
            title: 'Operations',
            items: [
              { label: 'Monitoring',       to: '/operations/monitoring' },
              { label: 'Backup',           to: '/operations/backups' },
              { label: 'Troubleshooting',  to: '/operations/troubleshooting' },
            ],
          },
        ],
        copyright: `Copyright © ${new Date().getFullYear()} EASM MSSP Platform`,
      },
      prism: {
        theme:         lightCodeTheme,
        darkTheme:     darkCodeTheme,
        additionalLanguages: ['bash', 'yaml', 'python', 'sql', 'nginx', 'docker'],
      },
      algolia: {
        // Algolia DocSearch — kostenfrei für Open-Source / Docs-Seiten
        // Beantragen unter: https://docsearch.algolia.com/apply/
        appId:     'YOUR_APP_ID',
        apiKey:    'YOUR_SEARCH_API_KEY',
        indexName: 'easm-platform',
        contextualSearch: true,
      },
    }),
};

module.exports = config;
