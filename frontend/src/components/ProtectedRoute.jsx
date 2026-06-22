import { Navigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

// Empêche l'accès aux pages si l'utilisateur n'est pas connecté.
export default function ProtectedRoute({ children }) {
  const { user } = useAuth();
  if (!user) {
    return <Navigate to="/login" replace />;
  }
  return children;
}
