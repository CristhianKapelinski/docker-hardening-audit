FROM node:20.18.1-alpine3.20@sha256:2f46fd49c767554c089a5eb219115313b72748d8f62f5eccb58b9f9a5b5e0234
WORKDIR /usr/src/app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY src/ ./src/
USER node
EXPOSE 3000
HEALTHCHECK CMD node -e "process.exit(0)"
CMD ["node", "src/index.js"]
