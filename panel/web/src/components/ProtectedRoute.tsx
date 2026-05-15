import { Navigate, useLocation } from "react-router-dom";
import { useAuthStore } from "@/store/auth";
export function ProtectedRoute({ children }) {
    const isAuthenticated = useAuthStore((s) => !!s.token);
    const location = useLocation();
    if (!isAuthenticated) {
        return <Navigate to="/login" state={{ from: location }} replace/>;
    }
    return <>{children}</>;
}
