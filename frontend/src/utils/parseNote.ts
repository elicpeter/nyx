export function parseNoteText(note: string): string {
  if (note.startsWith('source_kind:')) {
    const kind = note.split(':')[1];
    const readable: Record<string, string> = {
      UserInput: 'User Input',
      EnvironmentConfig: 'Environment/Config',
      Database: 'Database',
      FileSystem: 'File System',
      CaughtException: 'Caught Exception',
      Unknown: 'Unclassified',
    };
    return `Source type: ${readable[kind] || kind}`;
  }
  if (note.startsWith('hop_count:'))
    return `Path length: ${note.split(':')[1]} blocks`;
  if (note === 'uses_summary') return 'Uses cross-file summary';
  if (note === 'path_validated') return 'Path has validation guard';
  if (note.startsWith('cap_specificity:'))
    return `Cap specificity: ${note.split(':')[1]}`;
  if (note.startsWith('degraded:'))
    return `Degraded analysis: ${note.split(':')[1]}`;
  return note;
}
