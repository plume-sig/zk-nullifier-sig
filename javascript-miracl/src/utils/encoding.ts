export function asciitobytes(s: string): number[] {
  var b = [],
    i: number;
  for (i = 0; i < s.length; i++) {
    b.push(s.charCodeAt(i));
  }
  return b;
}
