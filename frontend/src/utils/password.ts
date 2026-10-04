export function isPasswordTooLong(password: string): boolean {
  return new TextEncoder().encode(password).length > 72
}
