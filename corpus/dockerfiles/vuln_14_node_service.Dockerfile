FROM node:20
WORKDIR /usr/src/app
COPY package.json ./
RUN npm install express
COPY . .
ENV API_TOKEN=ghp_exampletokenvalue123456
EXPOSE 3000
CMD ["node", "index.js"]
