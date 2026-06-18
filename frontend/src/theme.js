import { createTheme } from '@mantine/core';

export const theme = createTheme({
  primaryColor: 'apeiron',
  fontFamily: 'Inter, system-ui, -apple-system, Segoe UI, Roboto, sans-serif',
  fontFamilyMonospace: 'JetBrains Mono, Menlo, Monaco, Consolas, monospace',
  defaultRadius: 'md',
  colors: {
    apeiron: [
      '#e6fcf5', '#c3fae8', '#96f2d7', '#63e6be', '#38d9a9',
      '#20c997', '#12b886', '#0ca678', '#099268', '#087f5b',
    ],
  },
});

export const SEVERITY_COLORS = {
  info: 'gray',
  low: 'blue',
  medium: 'yellow',
  high: 'red',
};

export const VERDICT_COLORS = {
  benign: 'teal',
  'low-risk': 'lime',
  suspicious: 'orange',
  malicious: 'red',
  unknown: 'gray',
};

export const CATEGORY_COLORS = {
  api: 'grape',
  syscall: 'violet',
  file: 'cyan',
  registry: 'indigo',
  network: 'pink',
  process: 'orange',
  memory: 'red',
};
