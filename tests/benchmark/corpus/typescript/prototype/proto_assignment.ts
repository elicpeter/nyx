interface Bag { [k: string]: unknown }

export function absorb(target: Bag, attacker: Bag): Bag {
    (target as any).__proto__ = attacker;
    return target;
}
