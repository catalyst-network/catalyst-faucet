-- CreateTable
CREATE TABLE "Claim" (
    "id" TEXT NOT NULL,
    "address" TEXT NOT NULL,
    "ip_hash" TEXT NOT NULL,
    "amount_wei" BIGINT NOT NULL,
    "tx_hash" TEXT NOT NULL,
    "country" VARCHAR(2),
    "asn" INTEGER,
    "user_agent" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Claim_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Claim_tx_hash_key" ON "Claim"("tx_hash");

-- CreateIndex
CREATE INDEX "Claim_address_created_at_idx" ON "Claim"("address", "created_at");

-- CreateIndex
CREATE INDEX "Claim_ip_hash_created_at_idx" ON "Claim"("ip_hash", "created_at");

-- CreateIndex
CREATE INDEX "Claim_created_at_idx" ON "Claim"("created_at");

