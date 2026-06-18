import { useEffect, useRef, useState } from 'react';

// Resilient WebSocket hook with auto-reconnect. Calls onMessage for each
// parsed JSON message. `url` may be null to disable the connection.
export function useWebSocket(url, onMessage) {
  const [connected, setConnected] = useState(false);
  const wsRef = useRef(null);
  const handlerRef = useRef(onMessage);
  handlerRef.current = onMessage;

  useEffect(() => {
    if (!url) return undefined;
    let closedByUs = false;
    let reconnectTimer = null;

    const connect = () => {
      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        if (!closedByUs) {
          reconnectTimer = setTimeout(connect, 2000);
        }
      };
      ws.onerror = () => ws.close();
      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          handlerRef.current?.(data);
        } catch (_e) {
          /* ignore non-JSON frames */
        }
      };
    };

    connect();
    return () => {
      closedByUs = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      wsRef.current?.close();
    };
  }, [url]);

  return { connected };
}
