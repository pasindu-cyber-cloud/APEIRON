import {
  ActionIcon,
  Badge,
  Group,
  Loader,
  Paper,
  ScrollArea,
  Select,
  Stack,
  Text,
  TextInput,
  Tooltip,
  UnstyledButton,
} from '@mantine/core';
import { IconRefresh, IconSearch } from '@tabler/icons-react';
import { VERDICT_COLORS } from '../theme';
import { fmtTime, shorten } from '../utils';

const STATUS_COLORS = {
  queued: 'gray',
  running: 'blue',
  completed: 'teal',
  failed: 'red',
};

function StatusDot({ status }) {
  return (
    <Badge size="xs" variant="dot" color={STATUS_COLORS[status] || 'gray'}>
      {status}
    </Badge>
  );
}

export default function SampleList({
  samples,
  selectedId,
  onSelect,
  filters,
  onFilters,
  onRefresh,
}) {
  return (
    <Stack gap="xs" style={{ flex: 1, minHeight: 0 }}>
      <Group justify="space-between">
        <Text fw={700} size="sm" tt="uppercase" c="dimmed">
          Samples
        </Text>
        <Tooltip label="Refresh">
          <ActionIcon variant="subtle" onClick={onRefresh}>
            <IconRefresh size={16} />
          </ActionIcon>
        </Tooltip>
      </Group>
      <TextInput
        size="xs"
        placeholder="Search filename or hash…"
        leftSection={<IconSearch size={14} />}
        value={filters.q}
        onChange={(e) => onFilters({ ...filters, q: e.currentTarget.value })}
      />
      <Select
        size="xs"
        placeholder="All statuses"
        clearable
        data={['queued', 'running', 'completed', 'failed']}
        value={filters.status || null}
        onChange={(v) => onFilters({ ...filters, status: v || '' })}
      />
      <ScrollArea style={{ flex: 1 }} type="auto">
        <Stack gap={6}>
          {samples.length === 0 && (
            <Text size="xs" c="dimmed" ta="center" mt="md">
              No samples yet.
            </Text>
          )}
          {samples.map((s) => (
            <Paper
              key={s.id}
              withBorder
              p="xs"
              radius="md"
              style={{
                cursor: 'pointer',
                borderColor: s.id === selectedId ? 'var(--mantine-color-apeiron-6)' : undefined,
                background: s.id === selectedId ? 'var(--mantine-color-dark-6)' : undefined,
              }}
            >
              <UnstyledButton w="100%" onClick={() => onSelect(s.id)}>
                <Group justify="space-between" wrap="nowrap">
                  <div style={{ minWidth: 0 }}>
                    <Text size="sm" fw={600} truncate>
                      {s.filename}
                    </Text>
                    <Text size="xs" c="dimmed" className="mono">
                      {shorten(s.sha256, 24)}
                    </Text>
                  </div>
                  {s.status === 'running' ? (
                    <Loader size="xs" />
                  ) : (
                    <Badge size="xs" color={VERDICT_COLORS[s.verdict] || 'gray'}>
                      {s.verdict}
                    </Badge>
                  )}
                </Group>
                <Group justify="space-between" mt={4}>
                  <StatusDot status={s.status} />
                  <Group gap={6}>
                    <Badge size="xs" variant="outline">
                      {s.file_format}
                    </Badge>
                    <Text size="xs" c="dimmed">
                      {fmtTime(s.created_at)}
                    </Text>
                  </Group>
                </Group>
              </UnstyledButton>
            </Paper>
          ))}
        </Stack>
      </ScrollArea>
    </Stack>
  );
}
