import { useEffect, useState } from "react";
import { Table, Title, Stack, Group, Button, Skeleton, Badge, ActionIcon, } from "@mantine/core";
import { IconRefresh, IconTrash } from "@tabler/icons-react";
import { notifications } from "@mantine/notifications";
import { api } from "@/api/client";
export function UsersPage() {
    const [users, setUsers] = useState<Record<string, any>[]>([]);
    const [loading, setLoading] = useState(true);
    async function reload() {
        setLoading(true);
        try {
            const res = await api.get("/users");
            setUsers(Array.isArray(res.data) ? res.data : []);
        }
        catch {
            notifications.show({ color: "red", title: "Load failed", message: "/users" });
        }
        finally {
            setLoading(false);
        }
    }
    useEffect(() => {
        void reload();
    }, []);
    async function onDelete(id) {
        if (!confirm("Delete user?"))
            return;
        try {
            await api.delete(`/users/${id}`);
            setUsers((xs) => xs.filter((u) => u.id !== id));
        }
        catch {
            notifications.show({ color: "red", title: "Delete failed", message: String(id) });
        }
    }
    return (<Stack>
      <Group justify="space-between">
        <Title order={2}>Users</Title>
        <Button variant="light" leftSection={<IconRefresh size={16}/>} onClick={() => void reload()}>
          Refresh
        </Button>
      </Group>
      {loading ? (<Stack>
          {Array.from({ length: 4 }).map((_, i) => (<Skeleton key={i} h={36}/>))}
        </Stack>) : users.length === 0 ? (<Stack align="center" py="xl">
          <Title order={5} c="dimmed">
            No users yet
          </Title>
        </Stack>) : (<Table striped highlightOnHover withTableBorder>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Username</Table.Th>
              <Table.Th>Status</Table.Th>
              <Table.Th>Created</Table.Th>
              <Table.Th>Traffic</Table.Th>
              <Table.Th w={60}></Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {users.map((u) => (<Table.Tr key={u.id}>
                <Table.Td>{u.username}</Table.Td>
                <Table.Td>
                  <Badge color={u.enabled === false ? "red" : "green"} variant="light">
                    {u.enabled === false ? "disabled" : "active"}
                  </Badge>
                </Table.Td>
                <Table.Td>{u.created_at ?? "—"}</Table.Td>
                <Table.Td>{u.traffic_used ?? "—"}</Table.Td>
                <Table.Td>
                  <ActionIcon color="red" variant="subtle" onClick={() => void onDelete(u.id)}>
                    <IconTrash size={16}/>
                  </ActionIcon>
                </Table.Td>
              </Table.Tr>))}
          </Table.Tbody>
        </Table>)}
    </Stack>);
}
