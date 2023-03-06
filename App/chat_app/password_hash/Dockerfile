FROM node:alpine
WORKDIR /pass
COPY . /pass
RUN npm install
COPY . .
CMD [ "node", "server.js" ]