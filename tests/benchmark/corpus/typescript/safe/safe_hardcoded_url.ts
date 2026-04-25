import axios from 'axios';

interface Metrics { total: number }

export async function pullMetrics(): Promise<Metrics> {
    const resp = await axios.get<Metrics>('https://metrics.internal/totals');
    return resp.data;
}
