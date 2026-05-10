// =============================================================================
// sidebars.js — Navigationsstruktur der Dokumentation
// =============================================================================

/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  mainSidebar: [
    {
      type:  'doc',
      id:    'intro',
      label: 'Einführung',
    },
    {
      type:      'category',
      label:     'Getting Started',
      collapsed: false,
      items: [
        'getting-started/installation',
        'getting-started/configuration',
        'getting-started/first-scan',
      ],
    },
    {
      type:  'category',
      label: 'Architektur',
      items: [
        'architecture/overview',
        'architecture/backend',
        'architecture/database',
        'architecture/tools',
        'architecture/mcp-detection',
      ],
    },
    {
      type:  'category',
      label: 'UI Guide',
      items: [
        'ui/overview',
        'ui/findings',
        'ui/assets',
        'ui/intelligence',
        'ui/scans',
        'ui/settings',
      ],
    },
    {
      type:  'category',
      label: 'API-Referenz',
      items: [
        'api/authentication',
        'api/tenants',
        'api/findings',
        'api/assets',
        'api/scans',
        'api/reports',
      ],
    },
    {
      type:  'category',
      label: 'Operations',
      items: [
        'operations/monitoring',
        'operations/backups',
        'operations/scaling',
        'operations/updates',
        'operations/troubleshooting',
      ],
    },
  ],
};

module.exports = sidebars;
