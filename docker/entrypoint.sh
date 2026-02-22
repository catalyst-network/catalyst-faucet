#!/usr/bin/env sh
set -eu

echo "Running Prisma migrations..."
npm run prisma:migrate:deploy

echo "Starting faucet..."
exec npm run start

