import { Routes, Route, Navigate } from "react-router-dom";
import { LoginPage } from "./pages/LoginPage";
import { DashboardPage } from "./pages/DashboardPage";
import { UsersPage } from "./pages/UsersPage";
import { BridgesPage } from "./pages/BridgesPage";
import { RoutingPage } from "./pages/RoutingPage";
import { SessionsPage } from "./pages/SessionsPage";
import { LogsPage } from "./pages/LogsPage";
import { StatsPage } from "./pages/StatsPage";
import { FirewallPage } from "./pages/FirewallPage";
import { AdblockPage } from "./pages/AdblockPage";
import { InboundsPage } from "./pages/InboundsPage";
import { OutboundsPage } from "./pages/OutboundsPage";
import { SubscriptionsPage } from "./pages/SubscriptionsPage";
import { SystemPage } from "./pages/SystemPage";
import { UploadPage } from "./pages/UploadPage";
import { AppShellLayout } from "./components/AppShellLayout";
import { ProtectedRoute } from "./components/ProtectedRoute";
export function App() {
    return (<Routes>
      <Route path="/login" element={<LoginPage />}/>
      <Route element={<ProtectedRoute>
            <AppShellLayout />
          </ProtectedRoute>}>
        <Route path="/" element={<Navigate to="/dashboard" replace/>}/>
        <Route path="/dashboard" element={<DashboardPage />}/>
        <Route path="/users" element={<UsersPage />}/>
        <Route path="/bridges" element={<BridgesPage />}/>
        <Route path="/routing" element={<RoutingPage />}/>
        <Route path="/sessions" element={<SessionsPage />}/>
        <Route path="/stats" element={<StatsPage />}/>
        <Route path="/firewall" element={<FirewallPage />}/>
        <Route path="/adblock" element={<AdblockPage />}/>
        <Route path="/inbounds" element={<InboundsPage />}/>
        <Route path="/outbounds" element={<OutboundsPage />}/>
        <Route path="/subscriptions" element={<SubscriptionsPage />}/>
        <Route path="/system" element={<SystemPage />}/>
        <Route path="/upload" element={<UploadPage />}/>
        <Route path="/logs" element={<LogsPage />}/>
      </Route>
      <Route path="*" element={<Navigate to="/dashboard" replace/>}/>
    </Routes>);
}
