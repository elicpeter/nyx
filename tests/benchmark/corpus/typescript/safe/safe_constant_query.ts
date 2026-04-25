import { Pool } from 'pg';

const pool = new Pool();

export async function totalUsers(): Promise<number> {
    const r = await pool.query('SELECT COUNT(*) AS n FROM users');
    return Number(r.rows[0].n);
}
