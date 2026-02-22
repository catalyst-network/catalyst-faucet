FROM node:20-bookworm-slim AS base
WORKDIR /app

FROM base AS deps
COPY package.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi

FROM deps AS build
COPY tsconfig.json eslint.config.js prettier.config.cjs vitest.config.ts ./
COPY prisma ./prisma
COPY src ./src
RUN npm run prisma:generate && npm run build

FROM base AS runtime
ENV NODE_ENV=production
COPY package.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci --omit=dev; else npm install --omit=dev; fi
COPY --from=build /app/dist ./dist
COPY --from=build /app/prisma ./prisma
COPY docker/entrypoint.sh ./docker/entrypoint.sh
RUN chmod +x ./docker/entrypoint.sh

EXPOSE 3000
CMD ["./docker/entrypoint.sh"]

