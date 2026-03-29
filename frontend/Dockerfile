FROM node:20-alpine

WORKDIR /app

COPY package.json .
RUN npm install --legacy-peer-deps

COPY . .

# Build-time args for NEXT_PUBLIC_ vars (Railway injects these at build time)
ARG NEXT_PUBLIC_API_URL
ARG NEXT_PUBLIC_WS_URL
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL
ENV NEXT_PUBLIC_WS_URL=$NEXT_PUBLIC_WS_URL

RUN npm run build

# Create non-root user and hand off ownership
RUN addgroup -S vexis && adduser -S vexis -G vexis \
    && chown -R vexis:vexis /app

USER vexis

ENV PORT=3000
EXPOSE 3000
CMD ["npm", "start"]
