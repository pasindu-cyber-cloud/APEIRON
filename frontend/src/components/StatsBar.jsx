import { Group, Paper, SimpleGrid, Text } from '@mantine/core';
import {
  IconFileAnalytics,
  IconBug,
  IconReportSearch,
  IconDeviceSdCard,
} from '@tabler/icons-react';

function Stat({ icon: Icon, label, value, color }) {
  return (
    <Paper withBorder p="md" radius="md">
      <Group gap="sm" wrap="nowrap">
        <Icon size={28} color={`var(--mantine-color-${color}-5)`} />
        <div>
          <Text size="xs" c="dimmed" tt="uppercase" fw={700}>
            {label}
          </Text>
          <Text fw={700} size="xl">
            {value ?? 0}
          </Text>
        </div>
      </Group>
    </Paper>
  );
}

export default function StatsBar({ stats }) {
  const malicious = stats?.samples_by_verdict?.malicious || 0;
  return (
    <SimpleGrid cols={{ base: 2, sm: 4 }} spacing="md">
      <Stat icon={IconFileAnalytics} color="apeiron" label="Samples" value={stats?.samples_total} />
      <Stat icon={IconBug} color="red" label="Malicious" value={malicious} />
      <Stat icon={IconReportSearch} color="grape" label="IOCs" value={stats?.iocs_total} />
      <Stat icon={IconDeviceSdCard} color="orange" label="Dumps" value={stats?.dumps_total} />
    </SimpleGrid>
  );
}
