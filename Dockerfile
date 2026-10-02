# lob-mcp container image. Build stage compiles TypeScript and bundles the
# spec PDFs into build/specs/pdfs (read at runtime by src/specs/pdf-loader.ts).
FROM node:20-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY tsconfig.json ./
COPY src ./src
COPY scripts ./scripts
COPY specs ./specs
RUN npm run build

FROM node:20-slim
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
COPY --from=build /app/build ./build
EXPOSE 3018
CMD ["node", "build/http.js"]
