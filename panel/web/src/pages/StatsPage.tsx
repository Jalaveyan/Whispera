import { useEffect, useState } from "react";
import { Title, Stack, Group, Card, Text, SimpleGrid, Skeleton, Tabs, Table, } from "@mantine/core";
import { IconChartBar } from "@tabler/icons-react";
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
function MiniChart({ data }) {
    if (data.length === 0)
        return <Text c="dimmed">no data</Text>;
    const max = Math.max(...data.map((p) => Math.max(p.rx, p.tx)), 1);
    return (<div style={{
            display: "flex",
            alignItems: "flex-end",
            gap: 2,
            height: 160,
            padding: "8px 0",
        }}>
      {data.map((p, i) => (<div key={i} style={{
                flex: 1,
                display: "flex",
                flexDirection: "column",
                gap: 1,
                minWidth: 4,
            }} title={`${p.ts}\nRX: ${fmtBytes(p.rx)}\nTX: ${fmtBytes(p.tx)}`}>
          <div style={{
                background: "var(--mantine-color-violet-5)",
                height: `${(p.rx / max) * 50}%`,
                minHeight: p.rx > 0 ? 2 : 0,
            }}/>
          <div style={{
                background: "var(--mantine-color-cyan-5)",
                height: `${(p.tx / max) * 50}%`,
                minHeight: p.tx > 0 ? 2 : 0,
            }}/>
        </div>))}
    </div>);
}
export function StatsPage() {
    const [traffic, setTraffic] = useState<Record<string, any>>({});
    const [chart, setChart] = useState<Record<string, any>[]>([]);
    const [users, setUsers] = useState<Record<string, any>[]>([]);
    const [loading, setLoading] = useState(true);
    useEffect(() => {
        let cancel = false;
        setLoading(true);
        Promise.allSettled([
            api.get("/stats/traffic"),
            api.get("/stats/chart"),
            api.get("/stats/users"),
        ]).then((results) => {
            if (cancel)
                return;
            if (results[0].status === "fulfilled")
                setTraffic(results[0].value.data);
            if (results[1].status === "fulfilled") {
                const d = results[1].value.data;
                setChart(Array.isArray(d) ? d : []);
            }
            if (results[2].status === "fulfilled") {
                const d = results[2].value.data;
                setUsers(Array.isArray(d) ? d : []);
            }
            setLoading(false);
        });
        return () => {
            cancel = true;
        };
    }, []);
    return (<Stack>
      <Title order={2}>Statistics</Title>

      <SimpleGrid cols={{ base: 1, sm: 2, md: 4 }}>
        <StatCard label="Total RX" value={fmtBytes(traffic.total_rx)} loading={loading}/>
        <StatCard label="Total TX" value={fmtBytes(traffic.total_tx)} loading={loading}/>
        <StatCard label="Sessions" value={traffic.sessions ?? "—"} loading={loading}/>
        <StatCard label="Avg rate" value={traffic.avg_rate ?? "—"} loading={loading}/>
      </SimpleGrid>

      <Tabs defaultValue="chart">
        <Tabs.List>
          <Tabs.Tab value="chart" leftSection={<IconChartBar size={16}/>}>
            Traffic
          </Tabs.Tab>
          <Tabs.Tab value="users">Top users</Tabs.Tab>
        </Tabs.List>

        <Tabs.Panel value="chart" pt="md">
          <Card withBorder>
            <MiniChart data={chart}/>
            <Group justify="center" mt="xs" gap="lg">
              <Group gap={6}>
                <div style={{ width: 10, height: 10, background: "var(--mantine-color-violet-5)" }}/>
                <Text size="xs">RX</Text>
              </Group>
              <Group gap={6}>
                <div style={{ width: 10, height: 10, background: "var(--mantine-color-cyan-5)" }}/>
                <Text size="xs">TX</Text>
              </Group>
            </Group>
          </Card>
        </Tabs.Panel>

        <Tabs.Panel value="users" pt="md">
          {users.length === 0 ? (<Text c="dimmed">no data</Text>) : (<Table striped withTableBorder>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>User</Table.Th>
                  <Table.Th>Traffic</Table.Th>
                  <Table.Th>Sessions</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {users.map((u) => (<Table.Tr key={u.username}>
                    <Table.Td>{u.username}</Table.Td>
                    <Table.Td>{fmtBytes(u.traffic)}</Table.Td>
                    <Table.Td>{u.sessions ?? 0}</Table.Td>
                  </Table.Tr>))}
              </Table.Tbody>
            </Table>)}
        </Tabs.Panel>
      </Tabs>
    </Stack>);
}
function StatCard({ label, value, loading, }) {
    return (<Card withBorder padding="lg" radius="md">
      <Stack gap={4}>
        <Text size="xs" c="dimmed" tt="uppercase" fw={700}>{label}</Text>
        {loading ? <Skeleton h={28} w={80}/> : <Text size="xl" fw={700}>{value}</Text>}
      </Stack>
    </Card>);
}
