import { useEffect, useState } from 'react';
import { Badge, Loader, Group, Text, Timeline as MTimeline } from '@mantine/core';
import {
  IconActivity, IconAlertTriangle, IconFileText, IconNetwork, IconCpu,
} from '@tabler/icons-react';
import { api } from '../api/client';
import { CATEGORY_COLORS, SEVERITY_COLORS } from '../theme';
import { fmtRel } from '../utils';

const ICONS = {
  network: IconNetwork, file: IconFileText, memory: IconCpu, process: IconCpu,
};

export default function Timeline({ sampleId }) {
  const [events, setEvents] = useState(null);

  useEffect(() => {
    api.getTrace(sampleId, { limit: 2000 })
      .then((d) => {
        // Highlight suspicious + lifecycle events for a concise narrative.
        const key = d.items.filter(
          (e) => e.suspicious
            || e.name.startsWith('emulation.')
            || e.name.startsWith('detection:')
            || e.category === 'memory',
        );
        setEvents(key.slice(0, 200));
      })
      .catch(() => setEvents([]));
  }, [sampleId]);

  if (events === null) return <Group justify="center" py="xl"><Loader /></Group>;
  if (events.length === 0) {
    return <Text c="dimmed" ta="center" py="xl">No timeline events to display yet.</Text>;
  }

  return (
    <MTimeline active={events.length} bulletSize={22} lineWidth={2}>
      {events.map((e, i) => {
        const Icon = e.suspicious ? IconAlertTriangle : (ICONS[e.category] || IconActivity);
        return (
          <MTimeline.Item
            key={`${e.seq}-${i}`}
            bullet={<Icon size={12} />}
            color={e.suspicious ? (SEVERITY_COLORS[e.severity] || 'red') : (CATEGORY_COLORS[e.category] || 'gray')}
            title={(
              <Group gap="xs">
                <Text fw={600} className="mono" size="sm">{e.name}</Text>
                <Badge size="xs" variant="light" color={CATEGORY_COLORS[e.category] || 'gray'}>
                  {e.category}
                </Badge>
                {e.suspicious && <Badge size="xs" color={SEVERITY_COLORS[e.severity] || 'red'}>{e.severity}</Badge>}
              </Group>
            )}
          >
            {e.detail && <Text size="xs" c="dimmed">{e.detail}</Text>}
            <Text size="xs" c="dimmed">{fmtRel(e.rel_ts)}</Text>
          </MTimeline.Item>
        );
      })}
    </MTimeline>
  );
}
