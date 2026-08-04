/**
 * WebSocket Reconnect Manager
 *
 * A framework-agnostic utility that monitors a WebSocket connection and
 * automatically attempts to re-establish it after an unexpected drop.
 * Each instance manages one connection independently; multiple instances
 * can coexist without interfering with each other.
 */

export interface ReconnectConfig {
  /** Human-readable identifier used in log output, e.g. "SSH" / "SFTP" / "Process". */
  id: string;
  /** Maximum number of consecutive reconnection attempts. Default: 3. */
  maxAttempts?: number;
  /** Per-attempt delay in milliseconds. Index 0 = first retry delay, etc.
   *  If the attempt count exceeds the array length the last value is reused.
   *  Default: [1000, 2000, 4000]. */
  delays?: number[];
  /**
   * Factory that creates a fresh WebSocket for each reconnection attempt.
   * Called with the current attempt number (1-based).
   * The manager calls `attach()` on the returned socket to monitor its
   * close events for future reconnects.
   */
  onConnect: (attempt: number) => WebSocket | Promise<WebSocket>;
  /** Optional callback invoked for every lifecycle event. */
  onLog?: (entry: ReconnectLogEntry) => void;
}

export interface ReconnectLogEntry {
  /** ISO-8601 timestamp of the event. */
  timestamp: string;
  /** Connection identifier from the config. */
  id: string;
  /** Lifecycle event type. */
  event: 'disconnect' | 'reconnect_attempt' | 'reconnect_success' | 'reconnect_failed' | 'give_up';
  /** WebSocket close code (disconnect event only). */
  code?: number;
  /** WebSocket close reason (disconnect event only). */
  reason?: string;
  /** Current attempt number (1-based). */
  attempt?: number;
  /** Configured maximum attempts. */
  maxAttempts?: number;
}

const DEFAULT_MAX_ATTEMPTS = 3;
const DEFAULT_DELAYS: readonly number[] = [1000, 2000, 4000];

export class WebSocketReconnectManager {
  private id: string;
  private maxAttempts: number;
  private delays: number[];
  private onConnect: (attempt: number) => WebSocket | Promise<WebSocket>;
  private onLog?: (entry: ReconnectLogEntry) => void;
  private socket: WebSocket | null = null;
  private destroyed = false;
  private reconnecting = false;
  private attempt = 0;
  private timer: ReturnType<typeof setTimeout> | null = null;

  constructor(config: ReconnectConfig) {
    this.id = config.id;
    this.maxAttempts = config.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
    this.delays = config.delays?.length ? config.delays : [...DEFAULT_DELAYS];
    this.onConnect = config.onConnect;
    this.onLog = config.onLog;
  }

  /**
   * Bind an existing WebSocket to this manager.
   * The manager will listen for the `close` event and automatically
   * begin the reconnection sequence when the socket drops unexpectedly.
   *
   * Safe to call multiple times; each call replaces the tracked socket
   * and re-registers the close listener.
   */
  attach(socket: WebSocket): void {
    if (this.destroyed) return;
    // Avoid stacking duplicate close listeners when the same socket is
    // re-attached (the existing listener already calls handleClose).
    if (this.socket === socket) return;
    this.socket = socket;
    this.socket.addEventListener('close', (event: CloseEvent) => this.handleClose(event));
  }

  /**
   * Stop all reconnection activity and forget the current socket.
   * Call this when the user intentionally disconnects (code 1000).
   * After reset the manager is permanently deactivated — create a new
   * instance when the user initiates a fresh connection.
   */
  reset(): void {
    this.clearTimer();
    this.destroyed = true;
    this.socket = null;
    this.reconnecting = false;
    this.attempt = 0;
  }

  /**
   * Alias for `reset()` to match common teardown naming conventions.
   */
  destroy(): void {
    this.reset();
  }

  // ------------------------------------------------------------------ private

  private handleClose(event: CloseEvent): void {
    if (this.destroyed) return;
    // Guard: ignore close events from superseded sockets that have been
    // replaced by a newer attach() or a successful reconnect.  Without
    // this check a stale socket closing later could trigger a spurious
    // reconnection cycle.
    if (event.target !== this.socket) return;

    this.log({
      timestamp: new Date().toISOString(),
      id: this.id,
      event: 'disconnect',
      code: event.code,
      reason: event.reason,
    });

    // Normal closures (user-initiated or "no status") should never reconnect.
    if (event.code === 1000 || event.code === 1005) {
      return;
    }

    if (this.reconnecting) {
      // The current reconnect attempt's socket closed before the `open`
      // event confirmed success (e.g. CONNECTING → error).  Continue
      // retrying from the current attempt counter so we don't loop
      // infinitely on the same attempt number.
      this.tryReconnect();
    } else {
      this.startReconnect();
    }
  }

  private startReconnect(): void {
    if (this.destroyed || this.reconnecting) return;
    this.reconnecting = true;
    this.attempt = 0;
    this.tryReconnect();
  }

  private tryReconnect(): void {
    if (this.destroyed) {
      this.reconnecting = false;
      return;
    }

    this.attempt++;

    if (this.attempt > this.maxAttempts) {
      this.reconnecting = false;
      this.log({
        timestamp: new Date().toISOString(),
        id: this.id,
        event: 'give_up',
        attempt: this.attempt - 1,
        maxAttempts: this.maxAttempts,
      });
      return;
    }

    const delayIndex = this.attempt - 1;
    const delay = delayIndex < this.delays.length
      ? this.delays[delayIndex]
      : this.delays[this.delays.length - 1];

    this.log({
      timestamp: new Date().toISOString(),
      id: this.id,
      event: 'reconnect_attempt',
      attempt: this.attempt,
      maxAttempts: this.maxAttempts,
    });

    this.timer = setTimeout(() => {
      this.timer = null;
      if (this.destroyed) {
        this.reconnecting = false;
        return;
      }

      void this.executeReconnect();
    }, delay);
  }

  private async executeReconnect(): Promise<void> {
    const attemptSnapshot = this.attempt;

    try {
      const newSocket = await this.onConnect(attemptSnapshot);

      if (this.destroyed) {
        this.reconnecting = false;
        if (newSocket.readyState < WebSocket.CLOSING) {
          newSocket.close(1000, 'Reconnect superseded');
        }
        return;
      }

      const onConnectSuccess = (): void => {
        if (this.destroyed || this.socket !== newSocket) return;
        this.reconnecting = false;
        this.log({
          timestamp: new Date().toISOString(),
          id: this.id,
          event: 'reconnect_success',
          attempt: attemptSnapshot,
          maxAttempts: this.maxAttempts,
        });
      };

      // Re-attach the close listener so future drops are also handled.
      this.socket = newSocket;
      this.socket.addEventListener('close', (event: CloseEvent) => this.handleClose(event));

      // Only declare success after the WebSocket actually opens —
      // onConnect() may return while the socket is still CONNECTING.
      if (newSocket.readyState === WebSocket.OPEN) {
        onConnectSuccess();
      } else {
        newSocket.addEventListener('open', onConnectSuccess, { once: true });
      }
    } catch {
      if (this.destroyed) {
        this.reconnecting = false;
        return;
      }

      this.log({
        timestamp: new Date().toISOString(),
        id: this.id,
        event: 'reconnect_failed',
        attempt: attemptSnapshot,
        maxAttempts: this.maxAttempts,
      });

      this.tryReconnect();
    }
  }

  private log(entry: ReconnectLogEntry): void {
    const details = this.formatDetails(entry);
    console.log(`[WS-Reconnect] ${entry.timestamp} | ${entry.id} | ${entry.event} | ${details}`);
    this.onLog?.(entry);
  }

  private formatDetails(entry: ReconnectLogEntry): string {
    const parts: string[] = [];
    if (entry.code !== undefined) parts.push(`code=${entry.code}`);
    if (entry.reason !== undefined && entry.reason !== '') parts.push(`reason="${entry.reason}"`);
    if (entry.attempt !== undefined && entry.maxAttempts !== undefined) {
      parts.push(`attempt=${entry.attempt}/${entry.maxAttempts}`);
    }
    return parts.length > 0 ? parts.join(' | ') : '-';
  }

  private clearTimer(): void {
    if (this.timer !== null) {
      clearTimeout(this.timer);
      this.timer = null;
    }
  }
}
