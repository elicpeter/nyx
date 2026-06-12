// Behaviour-based path-confinement: `isWithinBaseDir` is NOT a
// name-recognised validator (no is_valid / is_safe / validate / verify
// prefix); it is recognised by its body returning a constant-prefix
// containment check (`normalizePath(id).startsWith(`${baseDir}/`)`), so
// `if (!isWithinBaseDir(p)) return` narrows the FILE_IO taint on the
// surviving (confined) branch and the read is safe.
import fs from 'node:fs'
import path from 'node:path'

const baseDir = '/srv/assets'
const normalizePath = (id: string): string => id.replace(/\\/g, '/')
const isWithinBaseDir = (id: string): boolean =>
  normalizePath(id).startsWith(`${baseDir}/`)

export function readAsset(req: any) {
  const p = path.resolve(baseDir, req.query.f as string)
  if (!isWithinBaseDir(p)) {
    return
  }
  const map = JSON.parse(fs.readFileSync(p, 'utf-8'))
  return map
}
