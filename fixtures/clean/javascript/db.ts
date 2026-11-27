// Parameterized counterparts of the query-builder seeds.
import knex from "knex";
import { DataSource } from "typeorm";
import { PrismaClient, Prisma } from "@prisma/client";
import { Sequelize } from "sequelize";
import sql from "sql-template-strings";

const db = knex({ client: "pg" });
const dataSource = new DataSource({ type: "postgres" });
const prisma = new PrismaClient();
const sequelize = new Sequelize("postgres://localhost/app");

export async function search(term: string, userId: string, table: string) {
  await db("users").whereRaw("name LIKE ?", [`%${term}%`]);
  await db.raw("SELECT * FROM users WHERE id = ?", [userId]);
  await dataSource.getRepository("User").createQueryBuilder("u").where("u.id = :id", { id: userId }).getMany();
  await sequelize.query("UPDATE users SET name = :name WHERE id = 1", { replacements: { name: term } });
  await prisma.$queryRaw`SELECT * FROM users WHERE id = ${userId}`;
  await prisma.$queryRaw(Prisma.sql`SELECT * FROM users WHERE name = ${term}`);
  await db.query(sql`SELECT * FROM users WHERE id = ${userId}`);
  await db.raw(`ALTER TABLE ${table} ADD COLUMN note TEXT`);
  return dataSource.query("SELECT 1");
}
