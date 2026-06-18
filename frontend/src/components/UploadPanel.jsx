import { useState } from 'react';
import { Group, Paper, Text, rem } from '@mantine/core';
import { Dropzone } from '@mantine/dropzone';
import { notifications } from '@mantine/notifications';
import { IconUpload, IconX, IconFileUnknown } from '@tabler/icons-react';
import { api } from '../api/client';

export default function UploadPanel({ onUploaded }) {
  const [loading, setLoading] = useState(false);

  const handleDrop = async (files) => {
    const file = files[0];
    if (!file) return;
    setLoading(true);
    try {
      const resp = await api.uploadSample(file);
      onUploaded?.(resp);
    } catch (e) {
      notifications.show({ color: 'red', title: 'Upload failed', message: e.message });
    } finally {
      setLoading(false);
    }
  };

  return (
    <Paper withBorder p="xs" radius="md">
      <Dropzone
        onDrop={handleDrop}
        loading={loading}
        maxSize={64 * 1024 ** 2}
        multiple={false}
      >
        <Group justify="center" gap="md" mih={90} style={{ pointerEvents: 'none' }}>
          <Dropzone.Accept>
            <IconUpload style={{ width: rem(40), height: rem(40) }}
              color="var(--mantine-color-apeiron-5)" stroke={1.4} />
          </Dropzone.Accept>
          <Dropzone.Reject>
            <IconX style={{ width: rem(40), height: rem(40) }}
              color="var(--mantine-color-red-6)" stroke={1.4} />
          </Dropzone.Reject>
          <Dropzone.Idle>
            <IconFileUnknown style={{ width: rem(40), height: rem(40) }}
              color="var(--mantine-color-dimmed)" stroke={1.4} />
          </Dropzone.Idle>
          <div>
            <Text size="sm" fw={600}>Drop a PE / ELF sample</Text>
            <Text size="xs" c="dimmed">.exe .dll .bin ELF · up to 64 MB</Text>
          </div>
        </Group>
      </Dropzone>
    </Paper>
  );
}
