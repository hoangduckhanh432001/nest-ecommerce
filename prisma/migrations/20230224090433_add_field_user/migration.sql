-- AlterTable
ALTER TABLE "users" ADD COLUMN     "address" TEXT,
ADD COLUMN     "city" TEXT,
ADD COLUMN     "dateOfBirth" TIMESTAMP(3),
ADD COLUMN     "fullname" TEXT,
ADD COLUMN     "gender" TEXT,
ADD COLUMN     "height" INTEGER,
ADD COLUMN     "phone" TEXT,
ADD COLUMN     "weight" INTEGER;
