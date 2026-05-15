import { useEffect, useState } from "react";
import { Title, Stack, Group, Button, Card, Text, Badge, Code, Table, Tabs, Skeleton, SimpleGrid, ActionIcon, } from "@mantine/core";
import { IconRefresh, IconRestore, IconDownload, IconCertificate, IconActivity, IconServer, IconShieldCheck, IconBan, } from "@tabler/icons-react";
import { notifications } from "@mantine/notifications";
import { api } from "@/api/client";
export function SystemPage() {
    const [info, setInfo] = useState<Record<string, any>>({});
    const [health, setHealth] = useState(null);
    const [probeStats, setProbeStats] = useState<Record<string, any>[]>([]);
    const [loading, setLoading] = useState(true);
    const [reloading, setReloading] = useState(false);
    const [renewing, setRenewing] = useState(false);
    async function reload() {
        setLoading(true);
        const [i, h, p] = await Promise.allSettled([
            api.get("/system/info"),
            api.get("/health"),
            api.get("/probe/stats"),
        ]);
        if (i.status === "fulfilled")
            setInfo(i.value.data ?? {});
        if (h.status === "fulfilled")
            setHealth(h.value.data);
        if (p.status === "fulfilled")
            setProbeStats(Array.isArray(p.value.data) ? p.value.data : []);
        setLoading(false);
    }
    useEffect(() => { void reload(); }, []);
    async function onReloadConfig() {
        setReloading(true);
        try {
            await api.post("/system/reload");
            notifications.show({ color: "green", title: "Config reloaded", message: "" });
        }
        catch {
            notifications.show({ color: "red", title: "Reload failed", message: "" });
        }
        finally {
            setReloading(false);
        }
    }
    async function onBackup() {
        try {
            const res = await api.get("/backup", { responseType: "blob" });
            const blob = new Blob([res.data]);
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `whispera-backup-${Date.now()}.zip`;
            a.click();
            URL.revokeObjectURL(url);
        }
        catch {
            notifications.show({ color: "red", title: "Backup failed", message: "" });
        }
    }
    async function onRenewCert() {
        setRenewing(true);
        try {
            await api.post("/v1/config/renew-cert");
            notifications.show({ color: "green", title: "Cert renewed", message: "" });
        }
        catch {
            notifications.show({ color: "red", title: "Renew failed", message: "" });
        }
        finally {
            setRenewing(false);
        }
    }
    async function onToggleProbe(ip, block) {
        try {
            await api.post(block ? "/probe/block" : "/probe/unblock", { ip });
            await reload();
        }
        catch {
            notifications.show({ color: "red", title: "Probe action failed", message: ip });
        }
    }
    return (<Stack>
      <Group justify="space-between">
        <Title order={2}>System</Title>
        <Group>
          <Button variant="light" leftSection={<IconRestore size={16}/>} loading={reloading} onClick={() => void onReloadConfig()}>Reload config</Button>
          <Button variant="light" leftSection={<IconDownload size={16}/>} onClick={() => void onBackup()}>Backup</Button>
          <Button variant="light" leftSection={<IconCertificate size={16}/>} loading={renewing} onClick={() => void onRenewCert()}>Renew cert</Button>
          <Button variant="light" leftSection={<IconRefresh size={16}/>} onClick={() => void reload()}>Refresh</Button>
        </Group>
      </Group>

      <Tabs defaultValue="info">
        <Tabs.List>
          <Tabs.Tab value="info" leftSection={<IconServer size={16}/>}>Info</Tabs.Tab>
          <Tabs.Tab value="health" leftSection={<IconActivity size={16}/>}>Health</Tabs.Tab>
          <Tabs.Tab value="probes" leftSection={<IconShieldCheck size={16}/>}>Probes</Tabs.Tab>
        </Tabs.List>

        <Tabs.Panel value="info" pt="md">
          {loading ? (<SimpleGrid cols={{ base: 1, sm: 2, md: 3 }}>
              {Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} h={70}/>)}
            </SimpleGrid>) : (<SimpleGrid cols={{ base: 1, sm: 2, md: 3 }}>
              <InfoCard label="Hostname" value={info.hostname}/>
              <InfoCard label="OS / Arch" value={`${info.os ?? "—"} / ${info.arch ?? "—"}`}/>
              <InfoCard label="Version" value={info.version}/>
              <InfoCard label="Uptime" value={info.uptime}/>
              <InfoCard label="CPU cores" value={info.cpu_cores}/>
              <InfoCard label="Memory" value={`${info.memory_used ?? "—"} / ${info.memory_total ?? "—"}`}/>
              <InfoCard label="Disk" value={`${info.disk_used ?? "—"} / ${info.disk_total ?? "—"}`}/>
            </SimpleGrid>)}
        </Tabs.Panel>

        <Tabs.Panel value="health" pt="md">
          <Card withBorder>
            <Group justify="space-between" mb="md">
              <Text fw={600}>Overall health</Text>
              <Badge color={health?.ok ? "green" : "red"} size="lg">
                {health?.ok ? "OK" : "FAIL"}
              </Badge>
            </Group>
            <Code block>{JSON.stringify(health?.details ?? health, null, 2)}</Code>
          </Card>
        </Tabs.Panel>

        <Tabs.Panel value="probes" pt="md">
          {probeStats.length === 0 ? (<Text c="dimmed" ta="center" py="xl">No probe data</Text>) : (<Table striped withTableBorder>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>IP</Table.Th>
                  <Table.Th>Probes</Table.Th>
                  <Table.Th>Last seen</Table.Th>
                  <Table.Th>Status</Table.Th>
                  <Table.Th w={80}></Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {probeStats.map((p) => (<Table.Tr key={p.ip}>
                    <Table.Td style={{ fontFamily: "monospace" }}>{p.ip}</Table.Td>
                    <Table.Td>{p.count ?? 0}</Table.Td>
                    <Table.Td style={{ fontSize: 12 }}>{p.last_seen ?? "—"}</Table.Td>
                    <Table.Td>
                      {p.blocked ? <Badge color="red">Blocked</Badge> : <Badge variant="light">Active</Badge>}
                    </Table.Td>
                    <Table.Td>
                      <ActionIcon variant="subtle" color={p.blocked ? "green" : "red"} onClick={() => void onToggleProbe(p.ip, !p.blocked)}>
                        <IconBan size={16}/>
                      </ActionIcon>
                    </Table.Td>
                  </Table.Tr>))}
              </Table.Tbody>
            </Table>)}
        </Tabs.Panel>
      </Tabs>
    </Stack>);
}
function InfoCard({ label, value }) {
    return (<Card withBorder padding="md" radius="md">
      <Stack gap={4}>
        <Text size="xs" c="dimmed" tt="uppercase" fw={700}>{label}</Text>
        <Text fw={600}>{value ?? "—"}</Text>
      </Stack>
    </Card>);
}
