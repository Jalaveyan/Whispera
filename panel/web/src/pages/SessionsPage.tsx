import { useEffect, useState } from "react";
import { Table, Title, Stack, Group, Button, Skeleton, Badge, ActionIcon, } from "@mantine/core";
import { IconRefresh, IconX } from "@tabler/icons-react";
import { notifications } from "@mantine/notifications";
import { api } from "@/api/client";
function fmtBytes(n) {
    if (n == null)
        return "—";
    if (n < 1024)
        return `${n} B`;
    if (n < 1024 * 1024)
        return `${(n / 1024).toFixed(1)} KB`;
    if (n < 1024 * 1024 * 1024)
        return `${(n / (1024 * 1024)).toFixed(1)} MB`;
    return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}
export function SessionsPage() {
    const [sessions, setSessions] = useState<Record<string, any>[]>([]);
    const [loading, setLoading] = useState(true);
    async function reload() {
        setLoading(true);
        try {
            const res = await api.get("/sessions");
            setSessions(Array.isArray(res.data) ? res.data : []);
        }
        catch {
            notifications.show({ color: "red", title: "Load failed", message: "/sessions" });
        }
        finally {
            setLoading(false);
        }
    }
    useEffect(() => {
        void reload();
        const iv = setInterval(() => void reload(), 5000);
        return () => clearInterval(iv);
    }, []);
    async function onKill(id) {
        if (!confirm("Kill session?"))
            return;
        try {
            await api.post(`/sessions/${id}/kill`);
            setSessions((xs) => xs.filter((s) => s.id !== id));
        }
        catch {
            notifications.show({ color: "red", title: "Kill failed", message: String(id) });
        }
    }
    return (<Stack>
      <Group justify="space-between">
        <Title order={2}>Active sessions</Title>
        <Button variant="light" leftSection={<IconRefresh size={16}/>} onClick={() => void reload()}>
          Refresh
        </Button>
      </Group>

      {loading && sessions.length === 0 ? (<Stack>
          {Array.from({ length: 4 }).map((_, i) => (<Skeleton key={i} h={36}/>))}
        </Stack>) : sessions.length === 0 ? (<Stack align="center" py="xl">
          <Title order={5} c="dimmed">No active sessions</Title>
        </Stack>) : (<Table striped highlightOnHover withTableBorder>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>User</Table.Th>
              <Table.Th>IP</Table.Th>
              <Table.Th>Transport</Table.Th>
              <Table.Th>Started</Table.Th>
              <Table.Th>RX / TX</Table.Th>
              <Table.Th w={60}></Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {sessions.map((s) => (<Table.Tr key={s.id}>
                <Table.Td>{s.user ?? "—"}</Table.Td>
                <Table.Td style={{ fontFamily: "monospace" }}>{s.ip ?? "—"}</Table.Td>
                <Table.Td>
                  {s.transport ? <Badge variant="light">{s.transport}</Badge> : "—"}
                </Table.Td>
                <Table.Td>{s.started_at ?? "—"}</Table.Td>
                <Table.Td style={{ fontFamily: "monospace", fontSize: 12 }}>
                  {fmtBytes(s.rx_bytes)} / {fmtBytes(s.tx_bytes)}
                </Table.Td>
                <Table.Td>
                  <ActionIcon color="red" variant="subtle" onClick={() => void onKill(s.id)}>
                    <IconX size={16}/>
                  </ActionIcon>
                </Table.Td>
              </Table.Tr>))}
          </Table.Tbody>
        </Table>)}
    </Stack>);
}
