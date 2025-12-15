# Build stage
FROM node:latest AS builder

WORKDIR /app

# Copia apenas os arquivos de dependência primeiro (cache layer)
COPY package*.json ./

# Instala todas as dependências (incluindo devDependencies para build)
RUN npm install

# Production stage
FROM node:latest AS production

WORKDIR /app

# Cria usuário não-root para segurança
RUN groupadd -r nodejs && useradd -r -g nodejs nodejs

# Copia os arquivos de dependência (package.json + package-lock.json)
COPY package*.json ./

# Instala apenas dependências de produção
RUN npm install --omit=dev && npm cache clean --force

# Copia o código fonte
COPY --chown=nodejs:nodejs . .

# Define o usuário não-root
USER nodejs

# Expõe a porta padrão
EXPOSE 3000

# Variáveis de ambiente
ENV NODE_ENV=production
ENV PORT=3000

# Comando de inicialização
CMD ["npm", "start"]

