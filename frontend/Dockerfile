FROM node:20-alpine AS build
WORKDIR /app

COPY package.json ./
RUN npm install --legacy-peer-deps

# Copy everything (node_modules and dist excluded via .dockerignore)
COPY . .

# Debug: show what's in the build context
RUN ls -la /app/

RUN npm run build

# ── Production ───────────────────────────────────
FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
