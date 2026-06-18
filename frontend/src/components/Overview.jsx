import { useEffect, useState } from 'react';
import {
  Alert,
  Badge,
  Card,
  Grid,
  Group,
  List,
  Progress,
  SimpleGrid,
  Stack,
  Table,
  Text,
  Title,
} from '@mantine/core';
import { IconAlertTriangle, IconCircleCheck } from '@tabler/icons-react';
import { api } from '../api/client';
import { SEVERITY_COLORS, VERDICT_COLORS } from '../theme';
import { fmtBytes, fmtTime } from '../utils';

function ScoreRing({ score, verdict }) {
  const color = VERDICT_COLORS[verdict] || 'gray';
  return (
    <Card withBorder radius="md" p="md">
      <Text size="xs" c="dimmed" tt="uppercase" fw={700}>
        Threat score
      </Text>
      <Group align="flex-end" gap="xs" mt={4}>
        <Text fw={800} size={42} lh={1} c={`${color}.5`}>
          {score}
        </Text>
        <Text c="dimmed" mb={6}>
          / 100
        </Text>
      </Group>
      <Progress value={score} color={color} mt="sm" radius="xl" />
      <Badge mt="sm" color={color} variant="light">
        {verdict}
      </Badge>
    </Card>
  );
}

export default function Overview({ sample }) {
  const [report, setReport] = useState(null);

  useEffect(() => {
    let active = true;
    if (sample.report) {
      fetch(api.reportUrl(sample.id, 'json'), {
        headers: localStorage.getItem('apeiron_api_key')
          ? { 'X-API-Key': localStorage.getItem('apeiron_api_key') }
          : {},
      })
        .then((r) => (r.ok ? r.json() : null))
        .then((d) => {
          if (active) setReport(d);
        })
        .catch(() => {});
    }
    return () => {
      active = false;
    };
  }, [sample.id, sample.report]);

  const detections = report?.detections || [];
  const stat = report?.static;

  return (
    <Grid>
      <Grid.Col span={{ base: 12, md: 4 }}>
        <Stack>
          <ScoreRing score={sample.threat_score} verdict={sample.verdict} />
          <Card withBorder radius="md" p="md">
            <Text size="xs" c="dimmed" tt="uppercase" fw={700} mb={6}>
              File
            </Text>
            <Table withRowBorders={false} verticalSpacing={2} fz="xs">
              <Table.Tbody>
                <Table.Tr>
                  <Table.Td c="dimmed">Format</Table.Td>
                  <Table.Td>
                    {sample.file_format} / {sample.arch} ({sample.bits}-bit)
                  </Table.Td>
                </Table.Tr>
                <Table.Tr>
                  <Table.Td c="dimmed">Platform</Table.Td>
                  <Table.Td>{sample.platform}</Table.Td>
                </Table.Tr>
                <Table.Tr>
                  <Table.Td c="dimmed">Size</Table.Td>
                  <Table.Td>{fmtBytes(sample.size)}</Table.Td>
                </Table.Tr>
                <Table.Tr>
                  <Table.Td c="dimmed">MD5</Table.Td>
                  <Table.Td className="mono">{sample.md5}</Table.Td>
                </Table.Tr>
                <Table.Tr>
                  <Table.Td c="dimmed">SHA1</Table.Td>
                  <Table.Td className="mono">{sample.sha1}</Table.Td>
                </Table.Tr>
                <Table.Tr>
                  <Table.Td c="dimmed">ssdeep</Table.Td>
                  <Table.Td className="mono">{sample.ssdeep || '-'}</Table.Td>
                </Table.Tr>
                <Table.Tr>
                  <Table.Td c="dimmed">Submitted</Table.Td>
                  <Table.Td>{fmtTime(sample.created_at)}</Table.Td>
                </Table.Tr>
              </Table.Tbody>
            </Table>
          </Card>
        </Stack>
      </Grid.Col>

      <Grid.Col span={{ base: 12, md: 8 }}>
        <Stack>
          <Card withBorder radius="md" p="md">
            <Title order={5} mb="xs">
              Detections
            </Title>
            {detections.length === 0 ? (
              <Alert color="teal" icon={<IconCircleCheck size={16} />} variant="light">
                No notable behavioral detections.
              </Alert>
            ) : (
              <Stack gap="xs">
                {detections.map((d) => (
                  <Alert
                    key={d.name}
                    color={SEVERITY_COLORS[d.severity] || 'gray'}
                    icon={<IconAlertTriangle size={16} />}
                    variant="light"
                    title={
                      <Group gap="xs">
                        <Text fw={700}>{d.name}</Text>
                        <Badge size="xs" color={SEVERITY_COLORS[d.severity]}>
                          {d.severity}
                        </Badge>
                        {(d.mitre || []).map((m) => (
                          <Badge key={m} size="xs" variant="outline">
                            {m}
                          </Badge>
                        ))}
                      </Group>
                    }
                  >
                    <Text size="sm">{d.description}</Text>
                    {d.evidence?.length > 0 && (
                      <Text size="xs" c="dimmed" mt={4} className="mono">
                        {d.evidence.join('  ·  ')}
                      </Text>
                    )}
                  </Alert>
                ))}
              </Stack>
            )}
          </Card>

          {stat && (
            <SimpleGrid cols={{ base: 1, sm: 2 }}>
              <Card withBorder radius="md" p="md">
                <Title order={6} mb="xs">
                  Sections
                </Title>
                <Table fz="xs" striped>
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>Name</Table.Th>
                      <Table.Th>Size</Table.Th>
                      <Table.Th>Entropy</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {(stat.sections || []).map((s, i) => (
                      <Table.Tr key={`${s.name}-${i}`}>
                        <Table.Td className="mono">{s.name}</Table.Td>
                        <Table.Td>{fmtBytes(s.rawsize)}</Table.Td>
                        <Table.Td>
                          <Badge size="xs" color={s.entropy >= 7.2 ? 'red' : 'gray'}>
                            {s.entropy}
                          </Badge>
                        </Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </Card>
              <Card withBorder radius="md" p="md">
                <Title order={6} mb="xs">
                  Imported libraries
                </Title>
                <List size="xs" spacing={2}>
                  {Object.keys(stat.imports || {})
                    .slice(0, 20)
                    .map((dll) => (
                      <List.Item key={dll}>
                        <Text className="mono" size="xs">
                          {dll}
                          {stat.imports[dll]?.length > 0 && (
                            <Text span c="dimmed">
                              {' '}
                              ({stat.imports[dll].length})
                            </Text>
                          )}
                        </Text>
                      </List.Item>
                    ))}
                </List>
              </Card>
            </SimpleGrid>
          )}
        </Stack>
      </Grid.Col>
    </Grid>
  );
}
