import { useCallback, useEffect, useState } from 'react';
import {
  ActionIcon, Badge, Button, Group, Loader, Paper, Stack, Tabs, Text, Title, Tooltip,
} from '@mantine/core';
import { notifications } from '@mantine/notifications';
import {
  IconActivity, IconBinaryTree, IconDownload, IconFileText, IconList,
  IconNetwork, IconShieldCode, IconTimeline, IconTrash,
} from '@tabler/icons-react';
import { api } from '../api/client';
import { VERDICT_COLORS } from '../theme';
import Overview from './Overview';
import TraceStream from './TraceStream';
import IOCExplorer from './IOCExplorer';
import RulesViewer from './RulesViewer';
import MemoryDumps from './MemoryDumps';
import Timeline from './Timeline';

export default function SampleDetail({ sampleId, onDeleted }) {
  const [sample, setSample] = useState(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    try {
      const data = await api.getSample(sampleId);
      setSample(data);
      return data.status;
    } catch (e) {
      notifications.show({ color: 'red', title: 'Load failed', message: e.message });
      return null;
    } finally {
      setLoading(false);
    }
  }, [sampleId]);

  useEffect(() => {
    setLoading(true);
    load();
  }, [load]);

  // Poll while the sample is still being processed.
  useEffect(() => {
    if (!sample || ['completed', 'failed'].includes(sample.status)) return undefined;
    const t = setInterval(load, 2500);
    return () => clearInterval(t);
  }, [sample, load]);

  const remove = async () => {
    if (!window.confirm('Delete this sample and all its artifacts?')) return;
    try {
      await api.deleteSample(sampleId);
      onDeleted?.();
    } catch (e) {
      notifications.show({ color: 'red', title: 'Delete failed', message: e.message });
    }
  };

  if (loading && !sample) {
    return <Group justify="center" p="xl"><Loader /></Group>;
  }
  if (!sample) return null;

  const running = ['queued', 'running'].includes(sample.status);

  return (
    <Paper withBorder radius="md" p="md">
      <Group justify="space-between" align="flex-start" mb="sm">
        <div style={{ minWidth: 0 }}>
          <Group gap="sm">
            <Title order={4} style={{ wordBreak: 'break-all' }}>{sample.filename}</Title>
            {running
              ? <Badge color="blue" leftSection={<Loader size={10} color="white" />}>{sample.status}</Badge>
              : <Badge color={VERDICT_COLORS[sample.verdict] || 'gray'}>{sample.verdict}</Badge>}
          </Group>
          <Text size="xs" c="dimmed" className="mono">{sample.sha256}</Text>
          <Group gap={6} mt={6}>
            {(sample.tags || []).map((t) => (
              <Badge key={t} size="sm" variant="light" color="apeiron">{t}</Badge>
            ))}
          </Group>
        </div>
        <Group gap="xs">
          <Tooltip label="Download JSON report">
            <Button
              size="xs" variant="light" leftSection={<IconFileText size={14} />}
              component="a" href={api.reportUrl(sampleId, 'json')} target="_blank"
              disabled={!sample.report}
            >JSON</Button>
          </Tooltip>
          <Tooltip label="Download PDF report">
            <Button
              size="xs" variant="light" leftSection={<IconDownload size={14} />}
              component="a" href={api.reportUrl(sampleId, 'pdf')} target="_blank"
              disabled={!sample.report?.pdf_path}
            >PDF</Button>
          </Tooltip>
          <Tooltip label="Delete sample">
            <ActionIcon color="red" variant="light" onClick={remove}><IconTrash size={16} /></ActionIcon>
          </Tooltip>
        </Group>
      </Group>

      {sample.status === 'failed' && (
        <Paper withBorder p="sm" mb="sm" bg="rgba(224,49,49,0.1)">
          <Text size="sm" c="red">Analysis failed: {sample.error}</Text>
        </Paper>
      )}

      <Tabs defaultValue="overview" keepMounted={false}>
        <Tabs.List>
          <Tabs.Tab value="overview" leftSection={<IconList size={14} />}>Overview</Tabs.Tab>
          <Tabs.Tab value="trace" leftSection={<IconActivity size={14} />}>
            API Trace
          </Tabs.Tab>
          <Tabs.Tab value="iocs" leftSection={<IconNetwork size={14} />}>
            IOCs <Badge size="xs" ml={6} variant="filled">{sample.iocs?.length || 0}</Badge>
          </Tabs.Tab>
          <Tabs.Tab value="rules" leftSection={<IconShieldCode size={14} />}>
            Rules <Badge size="xs" ml={6} variant="filled">{sample.rules?.length || 0}</Badge>
          </Tabs.Tab>
          <Tabs.Tab value="dumps" leftSection={<IconBinaryTree size={14} />}>
            Dumps <Badge size="xs" ml={6} variant="filled">{sample.dumps?.length || 0}</Badge>
          </Tabs.Tab>
          <Tabs.Tab value="timeline" leftSection={<IconTimeline size={14} />}>Timeline</Tabs.Tab>
        </Tabs.List>

        <Tabs.Panel value="overview" pt="md">
          <Overview sample={sample} />
        </Tabs.Panel>
        <Tabs.Panel value="trace" pt="md">
          <TraceStream sampleId={sampleId} live={running} />
        </Tabs.Panel>
        <Tabs.Panel value="iocs" pt="md">
          <IOCExplorer iocs={sample.iocs || []} />
        </Tabs.Panel>
        <Tabs.Panel value="rules" pt="md">
          <RulesViewer rules={sample.rules || []} />
        </Tabs.Panel>
        <Tabs.Panel value="dumps" pt="md">
          <MemoryDumps sampleId={sampleId} dumps={sample.dumps || []} />
        </Tabs.Panel>
        <Tabs.Panel value="timeline" pt="md">
          <Timeline sampleId={sampleId} />
        </Tabs.Panel>
      </Tabs>
    </Paper>
  );
}
