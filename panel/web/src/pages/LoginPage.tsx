import { useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { Paper, TextInput, PasswordInput, Button, Title, Center, Stack, Container, } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { api } from "@/api/client";
import { useAuthStore } from "@/store/auth";
export function LoginPage() {
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [loading, setLoading] = useState(false);
    const setAuth = useAuthStore((s) => s.setAuth);
    const navigate = useNavigate();
    const location = useLocation();
    const from = location.state?.from?.pathname ??
        "/dashboard";
    async function onSubmit(e) {
        e.preventDefault();
        setLoading(true);
        try {
            const res = await api.post("/auth/login", {
                username,
                password,
            });
            setAuth(res.data.token, username);
            navigate(from, { replace: true });
        }
        catch (err) {
            const msg = err && typeof err === "object" && "message" in err
                ? String(err.message)
                : "login failed";
            notifications.show({ color: "red", title: "Login failed", message: msg });
        }
        finally {
            setLoading(false);
        }
    }
    return (<Center h="100vh">
      <Container size={400} w="100%">
        <Paper p="xl" radius="md" withBorder>
          <Stack>
            <Title order={2} ta="center">
              Whispera Panel
            </Title>
            <form onSubmit={onSubmit}>
              <Stack>
                <TextInput label="Username" value={username} onChange={(e) => setUsername(e.currentTarget.value)} required autoFocus/>
                <PasswordInput label="Password" value={password} onChange={(e) => setPassword(e.currentTarget.value)} required/>
                <Button type="submit" loading={loading} fullWidth mt="sm">
                  Sign in
                </Button>
              </Stack>
            </form>
          </Stack>
        </Paper>
      </Container>
    </Center>);
}
