// Same nested-sink-under-sanitizer shape, but the FILE_IO sink is the
// `node:fs/promises` import-alias form (`fsp.readFile`) whose label is only
// resolvable once the per-file import view is built.  Must still fire.
import fsp from 'node:fs/promises'
import path from 'node:path'

export async function readMap(req: any, root: string) {
  const p = path.resolve(root, req.query.f as string)
  const map = JSON.parse(await fsp.readFile(p, 'utf-8'))
  return map
}
