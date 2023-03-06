FROM node:alpine
WORKDIR /mailer_service
COPY package*.json ./
RUN npm install
COPY . .
CMD [ "node", "mailer.js" ]