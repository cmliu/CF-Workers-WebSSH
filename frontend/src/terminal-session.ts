const TERMINAL_RESET_SEQUENCE = '\x1bc';

interface WritableTerminal {
  write(data: string): void;
}

export function resetTerminalForConnection(terminal: WritableTerminal): void {
  // Queue RIS behind pending SSH output so stale writes cannot land after the reset.
  terminal.write(TERMINAL_RESET_SEQUENCE);
}
