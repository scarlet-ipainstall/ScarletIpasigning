FROM node:22-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends git g++ make pkg-config libssl-dev ca-certificates unzip && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/zhlynn/zsign.git /tmp/zsign-src \
    && make -C /tmp/zsign-src/build/linux clean \
    && make -C /tmp/zsign-src/build/linux \
    && mkdir -p /opt/zsign \
    && find /tmp/zsign-src -type f -name zsign -perm -111 -exec cp {} /opt/zsign/zsign \; \
    && test -x /opt/zsign/zsign \
    && rm -rf /tmp/zsign-src

WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY . .

ENV NODE_ENV=production
ENV PORT=10000
EXPOSE 10000
CMD ["node","server.js"]
