import { useState } from 'react';
import { Button, Group, Modal, PasswordInput, Stack, Text } from '@mantine/core';
import { getApiKey, setApiKey } from '../api/client';

export default function ApiKeyModal({ opened, onClose }) {
  const [value, setValue] = useState(getApiKey());

  const save = () => {
    setApiKey(value.trim());
    onClose?.();
  };

  return (
    <Modal opened={opened} onClose={onClose} title="API key" centered>
      <Stack>
        <Text size="sm" c="dimmed">
          If the backend has <b>APEIRON_API_KEY</b> set, enter it here. It is stored locally in your
          browser and sent as the <b>X-API-Key</b> header.
        </Text>
        <PasswordInput
          label="X-API-Key"
          placeholder="leave blank if auth is disabled"
          value={value}
          onChange={(e) => setValue(e.currentTarget.value)}
        />
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={save}>Save</Button>
        </Group>
      </Stack>
    </Modal>
  );
}
