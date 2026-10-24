FROM node:22-alpine

ENV NODE_ENV=production
WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund \
    && npm cache clean --force

COPY --chown=node:node server.js ./
COPY --chown=node:node public ./public

USER node
EXPOSE 3000
CMD ["node", "server.js"]
