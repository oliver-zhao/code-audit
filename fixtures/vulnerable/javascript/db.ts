// Query-builder and ORM raw SQL seeds (knex, TypeORM, Sequelize, Prisma).
import knex from "knex";
import { DataSource } from "typeorm";
import { PrismaClient } from "@prisma/client";
import { Sequelize } from "sequelize";

const db = knex({ client: "pg" });
const dataSource = new DataSource({ type: "postgres" });
const prisma = new PrismaClient();
const sequelize = new Sequelize("postgres://localhost/app");

export async function search(term: string, userId: string, sort: string) {
  await db("users").whereRaw(`name LIKE '%${term}%'`);
  await db.raw("SELECT * FROM users WHERE id = " + userId);
  await dataSource.getRepository("User").createQueryBuilder("u").where(`u.id = ${userId}`).getMany();
  await sequelize.query(`UPDATE users SET name = '${term}' WHERE id = 1`);
  await prisma.$queryRawUnsafe(`SELECT * FROM users ORDER BY ${sort}`);
  await prisma.$executeRawUnsafe("DELETE FROM users WHERE id = " + userId);
  return dataSource.query(sort);
}
