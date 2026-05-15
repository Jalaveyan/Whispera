import { useEffect, useState } from "react";
import { SimpleGrid, Card, Text, Group, Stack, Skeleton, Title, } from "@mantine/core";
import { api } from "@/api/client";
function StatCard({ label, value, loading, }) {
    return (<Card withBorder padding="lg" radius="md">
      <Stack gap={4}>
        <Text size="xs" c="dimmed" tt="uppercase" fw={700}>
          {label}
        </Text>
        {loading ? (<Skeleton h={28} w={80}/>) : (<Text size="xl" fw={700}>
            {value ?? "—"}
          </Text>)}
      </Stack>
    </Card>);
}
export function DashboardPage() {
    const [stats, setStats] = useState<Record<string, any>>({});
    const [loading, setLoading] = useState(true);
    useEffect(() => {
        let cancel = false;
        api
            .get("/dashboard/stats")
            .then((r) => {
            if (!cancel)
                setStats(r.data);
        })
            .catch(() => {
        })
            .finally(() => {
            if (!cancel)
                setLoading(false);
        });
        return () => {
            cancel = true;
        };
    }, []);
    return (<Stack>
      <Group justify="space-between">
        <Title order={2}>Dashboard</Title>
      </Group>
      <SimpleGrid cols={{ base: 1, sm: 2, md: 4 }} spacing="md">
        <StatCard label="Users" value={stats.users} loading={loading}/>
        <StatCard label="Active sessions" value={stats.active_sessions} loading={loading}/>
        <StatCard label="Bridges" value={stats.bridges} loading={loading}/>
        <StatCard label="Total traffic" value={stats.total_traffic} loading={loading}/>
      </SimpleGrid>
    </Stack>);
}
