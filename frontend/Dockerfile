# ── Build de développement ──────────────────────────────────────
FROM node:20-alpine AS development

WORKDIR /app

# Copier les fichiers de dépendances en premier (cache Docker)
COPY package*.json ./
RUN npm ci

COPY . .

EXPOSE 3000
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "3000"]


# ── Build de production ──────────────────────────────────────────
FROM node:20-alpine AS build

WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build


# ── Image de production (Nginx sert les fichiers statiques) ─────
FROM nginx:1.25-alpine AS production

COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.prod.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
