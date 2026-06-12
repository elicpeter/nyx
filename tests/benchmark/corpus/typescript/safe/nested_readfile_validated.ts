// The nested-sink-under-sanitizer surfacing must NOT defeat validator
// narrowing: a recognised path validator (`isValidPath`, BooleanTrueIsValid)
// guarding the sink on the surviving branch keeps the flow safe.
import fs from 'node:fs'
import path from 'node:path'

const base = '/srv/data'
const isValidPath = (p: string): boolean => path.resolve(base, p).startsWith(base + '/')

export function readMap(req: any) {
  const p = path.resolve(base, req.query.f as string)
  if (!isValidPath(p)) {
    return
  }
  const map = JSON.parse(fs.readFileSync(p, 'utf-8'))
  return map
}
