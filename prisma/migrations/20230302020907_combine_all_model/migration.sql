-- CreateTable
CREATE TABLE "customers" (
    "id" SERIAL NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "email" TEXT NOT NULL,
    "nickName" TEXT,
    "firstName" TEXT,
    "lastName" TEXT,
    "fullname" TEXT,
    "phone" TEXT,
    "address" TEXT,
    "city" TEXT,
    "gender" TEXT,
    "dateOfBirth" TIMESTAMP(3),
    "height" INTEGER,
    "weight" INTEGER,

    CONSTRAINT "customers_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "products" (
    "id" SERIAL NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "SKU" TEXT,
    "originPrice" DOUBLE PRECISION,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "imageUrl" TEXT,
    "rating" DOUBLE PRECISION,

    CONSTRAINT "products_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "customers_email_key" ON "customers"("email");
