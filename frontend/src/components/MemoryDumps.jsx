import { Badge, Button, Paper, Table, Text } from '@mantine/core';
import { IconDownload } from '@tabler/icons-react';
import { api } from '../api/client';
import { fmtBytes, fmtTime } from '../utils';

export default function MemoryDumps({ sampleId, dumps }) {
  if (dumps.length === 0) {
    return (
      <Text c="dimmed" ta="center" py="xl">
        No memory dumps were triggered. Dumps are captured automatically on suspicious events such
        as process injection or privilege escalation.
      </Text>
    );
  }
  return (
    <Paper withBorder radius="md">
      <Table fz="xs" highlightOnHover>
        <Table.Thead>
          <Table.Tr>
            <Table.Th>Reason</Table.Th>
            <Table.Th>Address</Table.Th>
            <Table.Th>Size</Table.Th>
            <Table.Th>SHA256</Table.Th>
            <Table.Th>Captured</Table.Th>
            <Table.Th />
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {dumps.map((d) => (
            <Table.Tr key={d.id}>
              <Table.Td>
                <Badge color="red" variant="light">
                  {d.reason}
                </Badge>
              </Table.Td>
              <Table.Td className="mono">{d.address}</Table.Td>
              <Table.Td>{fmtBytes(d.size)}</Table.Td>
              <Table.Td className="mono" style={{ wordBreak: 'break-all' }}>
                {d.sha256}
              </Table.Td>
              <Table.Td>{fmtTime(d.created_at)}</Table.Td>
              <Table.Td>
                <Button
                  size="xs"
                  variant="light"
                  leftSection={<IconDownload size={14} />}
                  component="a"
                  target="_blank"
                  rel="noreferrer"
                  href={api.dumpDownloadUrl(sampleId, d.id)}
                >
                  Download
                </Button>
              </Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
    </Paper>
  );
}
