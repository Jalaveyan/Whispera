import { useState } from "react";
import { AppShell, Burger, Group, NavLink, Title, ActionIcon, Menu } from "@mantine/core";
import { Outlet, useLocation, useNavigate } from "react-router-dom";
import { IconDashboard, IconUsers, IconLogout, IconUser, IconRoute, IconNetwork, IconActivityHeartbeat, IconFileText, IconChartLine, IconShield, IconBlocks, IconArrowsDownUp, IconLink, IconServer, IconUpload, } from "@tabler/icons-react";
import { useAuthStore } from "@/store/auth";
const NAV = [
    { label: "Dashboard", path: "/dashboard", icon: IconDashboard },
    { label: "Users", path: "/users", icon: IconUsers },
    { label: "Bridges", path: "/bridges", icon: IconNetwork },
    { label: "Inbounds", path: "/inbounds", icon: IconArrowsDownUp },
    { label: "Outbounds", path: "/outbounds", icon: IconArrowsDownUp },
    { label: "Subscriptions", path: "/subscriptions", icon: IconLink },
    { label: "Routing", path: "/routing", icon: IconRoute },
    { label: "Sessions", path: "/sessions", icon: IconActivityHeartbeat },
    { label: "Stats", path: "/stats", icon: IconChartLine },
    { label: "Firewall", path: "/firewall", icon: IconShield },
    { label: "Adblock", path: "/adblock", icon: IconBlocks },
    { label: "System", path: "/system", icon: IconServer },
    { label: "Upload", path: "/upload", icon: IconUpload },
    { label: "Logs", path: "/logs", icon: IconFileText },
];
export function AppShellLayout() {
    const [opened, setOpened] = useState(false);
    const location = useLocation();
    const navigate = useNavigate();
    const username = useAuthStore((s) => s.username);
    const logout = useAuthStore((s) => s.logout);
    return (<AppShell header={{ height: 56 }} navbar={{
            width: 240,
            breakpoint: "sm",
            collapsed: { mobile: !opened },
        }} padding="md">
      <AppShell.Header>
        <Group h="100%" px="md" justify="space-between">
          <Group>
            <Burger opened={opened} onClick={() => setOpened((o) => !o)} hiddenFrom="sm" size="sm"/>
            <Title order={4}>Whispera</Title>
          </Group>
          <Menu>
            <Menu.Target>
              <ActionIcon variant="subtle" size="lg">
                <IconUser size={20}/>
              </ActionIcon>
            </Menu.Target>
            <Menu.Dropdown>
              <Menu.Label>{username ?? "user"}</Menu.Label>
              <Menu.Divider />
              <Menu.Item color="red" leftSection={<IconLogout size={16}/>} onClick={() => {
            logout();
            navigate("/login");
        }}>
                Logout
              </Menu.Item>
            </Menu.Dropdown>
          </Menu>
        </Group>
      </AppShell.Header>
      <AppShell.Navbar p="xs">
        {NAV.map((item) => (<NavLink key={item.path} label={item.label} leftSection={<item.icon size={18}/>} active={location.pathname === item.path} onClick={() => {
                navigate(item.path);
                setOpened(false);
            }}/>))}
      </AppShell.Navbar>
      <AppShell.Main>
        <Outlet />
      </AppShell.Main>
    </AppShell>);
}
