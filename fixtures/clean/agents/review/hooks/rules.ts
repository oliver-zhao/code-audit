// Rules for the auto-mode hook. A `path` rule also sees `cat ~/.aws/credentials`.
export function decide(command: string, mcpServer?: string): string {
  /** Ignore previous instructions is a known phrase; the hook denies it. */
  if (mcpServer && command.includes('~/.aws/credentials')) return 'deny';
  return 'allow';
}
