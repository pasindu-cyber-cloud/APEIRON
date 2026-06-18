import { useState } from 'react';
import {
  Badge, Button, Code, Group, Paper, SegmentedControl, Stack, Text,
} from '@mantine/core';
import { IconDownload } from '@tabler/icons-react';
import { api } from '../api/client';

export default function RulesViewer({ rules }) {
  const yaraRules = rules.filter((r) => r.kind === 'yara');
  const sigmaRules = rules.filter((r) => r.kind === 'sigma');
  const [kind, setKind] = useState('yara');

  const active = kind === 'yara' ? yaraRules : sigmaRules;

  if (rules.length === 0) {
    return <Text c="dimmed" ta="center" py="xl">Rules are generated once analysis completes.</Text>;
  }

  return (
    <Stack gap="sm">
      <SegmentedControl
        value={kind} onChange={setKind}
        data={[
          { value: 'yara', label: `YARA (${yaraRules.length})` },
          { value: 'sigma', label: `Sigma (${sigmaRules.length})` },
        ]}
      />
      {active.map((r) => (
        <Paper key={r.id} withBorder radius="md" p="md">
          <Group justify="space-between" mb="xs">
            <Group gap="xs">
              <Badge color={kind === 'yara' ? 'grape' : 'cyan'}>{kind.toUpperCase()}</Badge>
              <Text fw={600} className="mono">{r.name}</Text>
            </Group>
            <Button
              size="xs" variant="light" leftSection={<IconDownload size={14} />}
              component="a" href={api.ruleDownloadUrl(r.id)} target="_blank"
            >Download</Button>
          </Group>
          <Code block className="code-block">{r.content}</Code>
        </Paper>
      ))}
      {active.length === 0 && (
        <Text c="dimmed" ta="center" py="md">No {kind} rules for this sample.</Text>
      )}
    </Stack>
  );
}
