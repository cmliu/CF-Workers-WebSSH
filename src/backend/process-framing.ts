export function retainTrailingMarkerPrefix(buffer: string, marker: string): string {
  const maxLength = Math.min(buffer.length, Math.max(0, marker.length - 1));
  for (let length = maxLength; length > 0; length--) {
    if (buffer.endsWith(marker.slice(0, length))) return buffer.slice(-length);
  }
  return '';
}
