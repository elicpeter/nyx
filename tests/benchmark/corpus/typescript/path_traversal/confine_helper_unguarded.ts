// Precision guard for behaviour-based path-confinement: the helper
// `isWithinBaseDir` is DEFINED in the file but never used to gate the read,
// so the FILE_IO flow must still fire.  Recognising a confinement helper
// must not suppress flows it does not actually guard.
import fs from 'node:fs'
import path from 'node:path'

const baseDir = '/srv/assets'
const normalizePath = (id: string): string => id.replace(/\\/g, '/')
const isWithinBaseDir = (id: string): boolean =>
  normalizePath(id).startsWith(`${baseDir}/`)

export function readAsset(req: any) {
  const p = path.resolve(baseDir, req.query.f as string)
  const map = JSON.parse(fs.readFileSync(p, 'utf-8'))
  return map
}
