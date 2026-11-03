FROM node
WORKDIR /app
ENV STRIPE_SECRET_KEY=sk_test_fixture_value
ARG NPM_TOKEN=npm_LadPockFixtureBuildToken
COPY .env .env
RUN curl -fsSL https://get.example.dev/install.sh | bash
COPY . .
RUN npm install
CMD ["node", "server.js"]
