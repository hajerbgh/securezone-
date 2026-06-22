import axios from "axios";

// Client axios centralisé pour toute l'application.
// baseURL pointe vers /api/v1 — proxifié vers le backend FastAPI par Vite.
const api = axios.create({
  baseURL: "/api/v1",
  headers: { "Content-Type": "application/json" },
});

// Intercepteur de requête : injecte le JWT dans chaque appel
api.interceptors.request.use((config) => {
  const token = localStorage.getItem("sz_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Intercepteur de réponse : déconnecte sur 401 (token expiré/invalide)
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem("sz_token");
      localStorage.removeItem("sz_user");
      // Évite une boucle si on est déjà sur /login
      if (!window.location.pathname.includes("/login")) {
        window.location.href = "/login";
      }
    }
    return Promise.reject(error);
  }
);

export default api;
