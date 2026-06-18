import { useCallback, useEffect, useState } from 'react';
import {
  ActionIcon,
  AppShell,
  Badge,
  Burger,
  Group,
  Stack,
  Text,
  Title,
  Tooltip,
} from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import { notifications } from '@mantine/notifications';
import {
  IconShieldHalfFilled,
  IconRadar2,
  IconSettings,
  IconBrandGithub,
} from '@tabler/icons-react';
import { api, eventsSocketUrl } from './api/client';
import { useWebSocket } from './hooks/useWebSocket';
import UploadPanel from './components/UploadPanel';
import SampleList from './components/SampleList';
import SampleDetail from './components/SampleDetail';
import StatsBar from './components/StatsBar';
import ApiKeyModal from './components/ApiKeyModal';

export default function App() {
  const [opened, { toggle }] = useDisclosure();
  const [samples, setSamples] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [stats, setStats] = useState(null);
  const [filters, setFilters] = useState({ q: '', status: '' });
  const [keyModal, setKeyModal] = useState(false);

  const refreshSamples = useCallback(async () => {
    try {
      const data = await api.listSamples({ ...filters, limit: 200 });
      setSamples(data.items);
    } catch (e) {
      notifications.show({ color: 'red', title: 'Failed to load samples', message: e.message });
    }
  }, [filters]);

  const refreshStats = useCallback(async () => {
    try {
      setStats(await api.stats());
    } catch (_e) {
      /* non-fatal */
    }
  }, []);

  useEffect(() => {
    refreshSamples();
  }, [refreshSamples]);
  useEffect(() => {
    refreshStats();
    const t = setInterval(refreshStats, 5000);
    return () => clearInterval(t);
  }, [refreshStats]);

  // Global event feed: refresh lists whenever a sample changes status.
  const onGlobalEvent = useCallback(
    (evt) => {
      if (evt.type === 'status') {
        refreshSamples();
        refreshStats();
      }
    },
    [refreshSamples, refreshStats]
  );
  const { connected } = useWebSocket(eventsSocketUrl(), onGlobalEvent);

  const handleUploaded = (resp) => {
    notifications.show({
      color: 'apeiron',
      title: 'Sample queued',
      message: `${resp.sha256.slice(0, 16)}… is now being analyzed.`,
    });
    refreshSamples();
    setSelectedId(resp.id);
  };

  return (
    <AppShell
      header={{ height: 60 }}
      navbar={{ width: 380, breakpoint: 'md', collapsed: { mobile: !opened } }}
      padding="md"
    >
      <AppShell.Header>
        <Group h="100%" px="md" justify="space-between">
          <Group gap="xs">
            <Burger opened={opened} onClick={toggle} hiddenFrom="md" size="sm" />
            <IconShieldHalfFilled size={28} color="var(--mantine-color-apeiron-5)" />
            <Title order={3} style={{ letterSpacing: 1 }}>
              APEIRON
            </Title>
            <Badge variant="light" color="apeiron" size="sm">
              PE / ELF Sandbox
            </Badge>
          </Group>
          <Group gap="sm">
            <Tooltip label={connected ? 'Live feed connected' : 'Live feed offline'}>
              <Badge
                leftSection={<IconRadar2 size={14} />}
                color={connected ? 'teal' : 'gray'}
                variant={connected ? 'filled' : 'light'}
              >
                {connected ? 'LIVE' : 'OFFLINE'}
              </Badge>
            </Tooltip>
            <Tooltip label="API key settings">
              <ActionIcon variant="subtle" onClick={() => setKeyModal(true)}>
                <IconSettings size={18} />
              </ActionIcon>
            </Tooltip>
            <ActionIcon
              variant="subtle"
              component="a"
              target="_blank"
              rel="noreferrer"
              href="https://github.com/pasindu-cyber-cloud/APEIRON"
            >
              <IconBrandGithub size={18} />
            </ActionIcon>
          </Group>
        </Group>
      </AppShell.Header>

      <AppShell.Navbar p="md">
        <Stack gap="md" h="100%">
          <UploadPanel onUploaded={handleUploaded} />
          <SampleList
            samples={samples}
            selectedId={selectedId}
            onSelect={setSelectedId}
            filters={filters}
            onFilters={setFilters}
            onRefresh={refreshSamples}
          />
        </Stack>
      </AppShell.Navbar>

      <AppShell.Main>
        <Stack gap="md">
          <StatsBar stats={stats} />
          {selectedId ? (
            <SampleDetail
              sampleId={selectedId}
              onDeleted={() => {
                setSelectedId(null);
                refreshSamples();
              }}
            />
          ) : (
            <Stack align="center" justify="center" mih={300} gap={6}>
              <IconShieldHalfFilled size={64} color="var(--mantine-color-dark-3)" />
              <Text c="dimmed">Select a sample, or upload a PE/ELF binary to begin analysis.</Text>
            </Stack>
          )}
        </Stack>
      </AppShell.Main>

      <ApiKeyModal
        opened={keyModal}
        onClose={() => {
          setKeyModal(false);
          refreshSamples();
        }}
      />
    </AppShell>
  );
}
