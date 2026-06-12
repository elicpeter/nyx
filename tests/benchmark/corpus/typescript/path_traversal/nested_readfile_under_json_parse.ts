// A FILE_IO sink nested as an argument to an outer non-sink call (the
// JSON.parse sanitizer) must still fire: the sanitizer neutralises the
// parsed result, never the inner sink's path argument.
import fs from 'node:fs'
import path from 'node:path'

export function readMap(req: any, root: string) {
  const p = path.resolve(root, req.query.f as string)
  const map = JSON.parse(fs.readFileSync(p, 'utf-8'))
  return map
}
