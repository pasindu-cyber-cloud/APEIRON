import { useCallback, useEffect, useRef, useState } from 'react';
import {
  Badge, Group, Paper, ScrollArea, Select, Stack, Switch, Table, Text, TextInput, Tooltip,
} from '@mantine/core';
import { IconSearch } from '@tabler/icons-react';
import { api, traceSocketUrl } from '../api/client';
import { useWebSocket } from '../hooks/useWebSocket';
import { CATEGORY_COLORS, SEVERITY_COLORS } from '../theme';
import { fmtRel } from '../utils';

const CATEGORIES = ['api', 'syscall', 'file', 'registry', 'network', 'process', 'memory'];
const MAX_ROWS = 4000;

export default function TraceStream({ sampleId, live }) {
  const [events, setEvents] = useState([]);
  const [category, setCategory] = useState(null);
  const [onlySuspicious, setOnlySuspicious] = useState(false);
  const [search, setSearch] = useState('');
  const [autoscroll, setAutoscroll] = useState(true);
  const viewportRef = useRef(null);

  // Load historical events for the sample.
  const loadHistory = useCallback(async () => {
    try {
      const data = await api.getTrace(sampleId, { limit: MAX_ROWS });
      setEvents(data.items);
    } catch (_e) { /* ignore */ }
  }, [sampleId]);

  useEffect(() => { loadHistory(); }, [loadHistory]);
  // When live ends, refresh once to pick up persisted ordering.
  useEffect(() => { if (!live) loadHistory(); }, [live, loadHistory]);

  const onWsMessage = useCallback((msg) => {
    if (msg.type !== 'trace') return;
    setEvents((prev) => {
      const next = [...prev, msg];
      return next.length > MAX_ROWS ? next.slice(-MAX_ROWS) : next;
    });
  }, []);
  const { connected } = useWebSocket(live ? traceSocketUrl(sampleId) : null, onWsMessage);

  useEffect(() => {
    if (autoscroll && viewportRef.current) {
      viewportRef.current.scrollTo({ top: viewportRef.current.scrollHeight });
    }
  }, [events, autoscroll]);

  const filtered = events.filter((e) => {
    if (category && e.category !== category) return false;
    if (onlySuspicious && !e.suspicious) return false;
    if (search) {
      const hay = `${e.name} ${e.detail} ${JSON.stringify(e.args || {})}`.toLowerCase();
      if (!hay.includes(search.toLowerCase())) return false;
    }
    return true;
  });

  return (
    <Stack gap="sm">
      <Group justify="space-between">
        <Group gap="sm">
          <Select
            size="xs" placeholder="All categories" clearable w={150}
            data={CATEGORIES} value={category} onChange={setCategory}
          />
          <TextInput
            size="xs" placeholder="Filter…" leftSection={<IconSearch size={14} />}
            value={search} onChange={(e) => setSearch(e.currentTarget.value)}
          />
          <Switch
            size="xs" label="Suspicious only"
            checked={onlySuspicious} onChange={(e) => setOnlySuspicious(e.currentTarget.checked)}
          />
        </Group>
        <Group gap="sm">
          <Switch size="xs" label="Auto-scroll" checked={autoscroll}
            onChange={(e) => setAutoscroll(e.currentTarget.checked)} />
          {live && (
            <Badge color={connected ? 'teal' : 'gray'} variant={connected ? 'filled' : 'light'}>
              {connected ? 'streaming' : 'connecting…'}
            </Badge>
          )}
          <Text size="xs" c="dimmed">{filtered.length} events</Text>
        </Group>
      </Group>

      <Paper withBorder radius="md">
        <ScrollArea h="58vh" viewportRef={viewportRef} type="auto">
          <Table stickyHeader fz="xs" highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                <Table.Th w={70}>Time</Table.Th>
                <Table.Th w={90}>Category</Table.Th>
                <Table.Th>API / Event</Table.Th>
                <Table.Th>Arguments</Table.Th>
                <Table.Th w={90}>Return</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {filtered.map((e, i) => (
                <Table.Tr key={`${e.seq}-${i}`}
                  className={e.suspicious ? 'trace-row-suspicious' : undefined}>
                  <Table.Td c="dimmed">{fmtRel(e.rel_ts)}</Table.Td>
                  <Table.Td>
                    <Badge size="xs" color={CATEGORY_COLORS[e.category] || 'gray'} variant="light">
                      {e.category}
                    </Badge>
                  </Table.Td>
                  <Table.Td>
                    <Group gap={6} wrap="nowrap">
                      <Text className="mono" fw={e.suspicious ? 700 : 400}>{e.name}</Text>
                      {e.severity && e.severity !== 'info' && (
                        <Badge size="xs" color={SEVERITY_COLORS[e.severity]}>{e.severity}</Badge>
                      )}
                    </Group>
                    {e.detail && <Text size="xs" c="dimmed">{e.detail}</Text>}
                  </Table.Td>
                  <Table.Td>
                    <Text className="mono" c="dimmed" lineClamp={2}>
                      {Object.entries(e.args || {})
                        .map(([k, v]) => `${k}=${v}`).join(', ')}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Tooltip label={e.ret || ''} disabled={!e.ret}>
                      <Text className="mono" lineClamp={1}>{e.ret}</Text>
                    </Tooltip>
                  </Table.Td>
                </Table.Tr>
              ))}
              {filtered.length === 0 && (
                <Table.Tr>
                  <Table.Td colSpan={5}>
                    <Text ta="center" c="dimmed" py="lg">
                      {live ? 'Waiting for trace events…' : 'No trace events match the filters.'}
                    </Text>
                  </Table.Td>
                </Table.Tr>
              )}
            </Table.Tbody>
          </Table>
        </ScrollArea>
      </Paper>
    </Stack>
  );
}
