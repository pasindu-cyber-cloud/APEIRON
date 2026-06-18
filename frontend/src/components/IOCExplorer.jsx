import { useMemo, useState } from 'react';
import {
  ActionIcon,
  Badge,
  Group,
  Paper,
  ScrollArea,
  SegmentedControl,
  Stack,
  Table,
  Text,
  TextInput,
  Tooltip,
} from '@mantine/core';
import { IconCopy, IconSearch } from '@tabler/icons-react';
import { notifications } from '@mantine/notifications';
import { copyText } from '../utils';

const TYPE_COLORS = {
  ip: 'pink',
  domain: 'grape',
  url: 'violet',
  mutex: 'orange',
  registry_key: 'indigo',
  filepath: 'cyan',
  email: 'teal',
  hash: 'gray',
  bitcoin: 'yellow',
};

export default function IOCExplorer({ iocs }) {
  const [type, setType] = useState('all');
  const [search, setSearch] = useState('');

  const types = useMemo(() => {
    const counts = {};
    iocs.forEach((i) => {
      counts[i.ioc_type] = (counts[i.ioc_type] || 0) + 1;
    });
    return ['all', ...Object.keys(counts).sort()];
  }, [iocs]);

  const filtered = iocs.filter((i) => {
    if (type !== 'all' && i.ioc_type !== type) return false;
    if (search && !i.value.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const copy = async (value) => {
    if (await copyText(value)) {
      notifications.show({ message: 'Copied', color: 'apeiron', autoClose: 1000 });
    }
  };

  if (iocs.length === 0) {
    return (
      <Text c="dimmed" ta="center" py="xl">
        No IOCs were extracted from this sample.
      </Text>
    );
  }

  return (
    <Stack gap="sm">
      <Group justify="space-between">
        <SegmentedControl
          size="xs"
          value={type}
          onChange={setType}
          data={types.map((t) => ({ value: t, label: t }))}
        />
        <TextInput
          size="xs"
          placeholder="Search value…"
          leftSection={<IconSearch size={14} />}
          value={search}
          onChange={(e) => setSearch(e.currentTarget.value)}
        />
      </Group>
      <Paper withBorder radius="md">
        <ScrollArea h="56vh" type="auto">
          <Table stickyHeader fz="xs" highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                <Table.Th w={120}>Type</Table.Th>
                <Table.Th>Value</Table.Th>
                <Table.Th w={70}>Count</Table.Th>
                <Table.Th>Context</Table.Th>
                <Table.Th w={40} />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {filtered.map((i) => (
                <Table.Tr key={i.id}>
                  <Table.Td>
                    <Badge size="xs" color={TYPE_COLORS[i.ioc_type] || 'gray'}>
                      {i.ioc_type}
                    </Badge>
                  </Table.Td>
                  <Table.Td className="mono" style={{ wordBreak: 'break-all' }}>
                    {i.value}
                  </Table.Td>
                  <Table.Td>{i.count}</Table.Td>
                  <Table.Td c="dimmed">{i.context}</Table.Td>
                  <Table.Td>
                    <Tooltip label="Copy">
                      <ActionIcon size="sm" variant="subtle" onClick={() => copy(i.value)}>
                        <IconCopy size={14} />
                      </ActionIcon>
                    </Tooltip>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </ScrollArea>
      </Paper>
    </Stack>
  );
}
