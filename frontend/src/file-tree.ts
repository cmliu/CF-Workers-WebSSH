import type { SFTPEntry } from './file-manager';

/**
 * Whether an entry should be shown in the left directory tree.
 *
 * The tree only displays folders ('directory') and links ('symlink');
 * regular files ('file') and other types ('other') are hidden because
 * listing files in the tree has no practical value. The right-hand file
 * detail panel still renders every entry.
 *
 * Kept as a pure, DOM-free function for testability and clarity.
 */
export function isTreeVisibleEntry(entry: { type: string }): boolean {
  return entry.type === 'directory' || entry.type === 'symlink';
}

/** Result returned by FileManager.fetchDirectoryEntries. */
export interface TreeListResult {
  path: string;
  entries: SFTPEntry[];
  isTruncated: boolean;
}

/** Options for constructing a FileTree instance. */
export interface FileTreeOptions {
  /** The <aside id="file-tree"> container element. */
  container: HTMLElement;
  /** Callback to fetch directory entries (provided by FileManager.fetchDirectoryEntries). */
  fetchEntries: (path: string) => Promise<TreeListResult>;
  /** Returns the current UI language code. */
  getLanguage: () => string;
  /** Called when the user activates a folder node (navigates the right panel). */
  onNavigate: (path: string) => void;
  /** Optional error reporting callback. */
  onError?: (message: string) => void;
  /** Initial root path; defaults to "/". */
  initialRoot?: string;
}

/** A node in the directory tree. */
interface TreeNode {
  /** Absolute path, e.g. "/etc/nginx"; root is "/". */
  path: string;
  /** Display name; root is "/". */
  name: string;
  /** Entry type (symlink treated as non-expandable, same as file). */
  type: 'directory' | 'file' | 'symlink' | 'other';
  /** Parent node, null for root. */
  parent: TreeNode | null;
  /**
   * Children:
   * - null: not yet loaded (collapsed)
   * - []: loaded and empty
   * - [...]: loaded child nodes
   */
  children: TreeNode[] | null;
  /** State machine driving UI rendering. */
  state: 'collapsed' | 'loading' | 'expanded' | 'error';
  /** Backend truncation flag. */
  isTruncated: boolean;
  /** Load token: incremented on each fetch to cancel stale results. */
  loadToken: number;
  /** Cached DOM row element (.file-tree-row), null if not yet rendered. */
  element: HTMLElement | null;
  /** Depth in the tree (root = 0). */
  depth: number;
  /**
   * True if the node is on the path to cwd but its SFTP list failed
   * (e.g. Permission denied). The node is rendered as a "locked" leaf —
   * still visible to preserve the full path, but not expandable.
   */
  unavailable: boolean;
}

interface LocalizedText {
  zh: string;
  en: string;
}

const EMPTY_TEXT: LocalizedText = { zh: '— 空 —', en: '— Empty —' };
const TRUNCATED_TEXT: LocalizedText = { zh: '(已截断)', en: '(truncated)' };
const RETRY_TEXT: LocalizedText = { zh: '重试', en: 'Retry' };

const WIDTH_STORAGE_KEY = 'cf-webssh.file-tree.width';
const COLLAPSED_STORAGE_KEY = 'cf-webssh.file-tree.collapsed';
const DEFAULT_WIDTH = 240;
const MIN_WIDTH = 160;
const MAX_WIDTH = 480;

/**
 * Split an absolute path into ancestor segments, root-first.
 * e.g. "/var/log/nginx" -> ["/", "/var", "/var/log", "/var/log/nginx"]
 */
function splitPathSegments(path: string): string[] {
  if (path === '/') return ['/'];
  const segments: string[] = ['/'];
  const parts = path.split('/').filter(Boolean);
  let accumulated = '';
  for (const part of parts) {
    accumulated += `/${part}`;
    segments.push(accumulated);
  }
  return segments;
}

/** Check whether `child` is the same as or a descendant of `parent`. */
function isDescendantPath(parent: string, child: string): boolean {
  if (parent === child) return true;
  if (parent === '/') return child.startsWith('/');
  return child.startsWith(parent + '/');
}

/**
 * FileTree implements a lazy-loading directory tree view using pure DOM.
 *
 * Features:
 * - Lazy expand/collapse with loadToken race-condition cancellation
 * - setCwd path expansion with setCwdToken cancellation
 * - ARIA tree / roving tabindex keyboard navigation
 * - Width drag-to-resize with localStorage persistence
 * - Collapsible sidebar with localStorage persistence
 * - Full i18n support (zh/en)
 */
export class FileTree {
  private readonly container: HTMLElement;
  private readonly fetchEntries: FileTreeOptions['fetchEntries'];
  private readonly getLanguage: () => string;
  private readonly onNavigate: (path: string) => void;
  private readonly onError?: (message: string) => void;
  private readonly bindings = new AbortController();

  private readonly scroller: HTMLElement;
  private readonly collapseButton: HTMLButtonElement;
  private readonly resizeHandle: HTMLElement;

  private root: TreeNode | null = null;
  private selectedPath: string | null = null;
  private focusedNode: TreeNode | null = null;
  private rootPath = '/';
  private ready = false;
  private collapsed = false;
  private width = DEFAULT_WIDTH;
  /** Token to cancel a previous in-progress setCwd expansion (Risk 2). */
  private setCwdToken = 0;
  /**
   * Map tracking in-flight expandNode promises keyed by node.
   *
   * When a second expandToPath call overlaps with an on-going expandNode
   * fetch on the same node (e.g. sftp_ready and sftp_list_result both
   * emitCwdChange), the second call retrieves the in-flight promise and
   * awaits it instead of bailing out. This prevents the race condition
   * where the second expandToPath breaks prematurely because the node
   * was still 'loading'.
   */
  private inflightExpands = new Map<TreeNode, Promise<void>>();
  /**
   * Tree-level lifecycle epoch.
   *
   * `node.loadToken` only guards per-node races; it cannot observe that the
   * entire tree was torn down (setReady(false) / destroy())
   * while a fetch was in flight. Every whole-tree teardown bumps this counter,
   * so an awaiting `expandNode` continuation can tell that the node it owns
   * has been orphaned and must not touch the DOM, node state, or `onError`.
   * <b>Invariant: any code path that replaces or clears this.root must increment treeEpoch.</b>
   */
  private treeEpoch = 0;

  constructor(options: FileTreeOptions) {
    this.container = options.container;
    this.fetchEntries = options.fetchEntries;
    this.getLanguage = options.getLanguage;
    this.onNavigate = options.onNavigate;
    this.onError = options.onError;
    this.rootPath = options.initialRoot ?? '/';

    // Query sub-elements from the container (provided by index.html)
    const scroller = this.container.querySelector<HTMLElement>('.file-tree-scroller');
    const collapseBtn = this.container.querySelector<HTMLButtonElement>('.file-tree-collapse');
    const resize = this.container.querySelector<HTMLElement>('.file-tree-resize');
    if (!scroller || !collapseBtn || !resize) {
      throw new Error('FileTree: container must contain .file-tree-scroller, .file-tree-collapse, .file-tree-resize');
    }
    this.scroller = scroller;
    this.collapseButton = collapseBtn;
    this.resizeHandle = resize;

    this.container.setAttribute('role', 'tree');

    // Load persisted state
    this.loadWidth();
    this.loadCollapsed();

    // Bind events
    const signal = this.bindings.signal;
    this.scroller.addEventListener('keydown', (event) => this.handleKeydown(event), { signal });
    this.scroller.addEventListener('click', (event) => this.handleClick(event), { signal });
    this.collapseButton.addEventListener('click', () => this.toggleCollapsed(), { signal });
    this.initResize(signal);
  }

  // ── Public API ──────────────────────────────────────────────────────

  /** Mark the tree as ready (SFTP channel open) or not (disconnected). */
  setReady(ready: boolean): void {
    this.ready = ready;
    if (!ready) {
      this.treeEpoch++;
      this.root = null;
      this.selectedPath = null;
      this.focusedNode = null;
      this.scroller.replaceChildren();
      return;
    }
    // Initialize with just the root node (collapsed)
    this.root = this.createRootNode(this.rootPath);
    this.focusedNode = this.root;
    this.selectedPath = null;
    this.renderRoot();
  }

  /**
   * Expand ancestor nodes along the path to `cwd` and highlight the target.
   * Uses setCwdToken to cancel a previous in-progress expansion (Risk 2).
   */
  setCwd(cwd: string): void {
    this.selectedPath = cwd;
    this.setCwdToken++;
    // Kick off root expansion immediately for visual feedback so aria-expanded
    // changes to "true" (or shows a spinner) without waiting for the async
    // SFTP fetch. silent=true  keeps the unavailable-path compatible with
    // expandToPath.
    if (this.root && this.root.state === 'collapsed') {
      void this.expandNode(this.root, true);
    }
    const token = this.setCwdToken;
    void this.expandToPath(cwd, token);
  }

  /** Re-render i18n text after a language switch. */
  setLanguage(): void {
    if (this.root) {
      this.rerenderVisible(this.root);
    }
  }

  /** Tear down: abort listeners, clear DOM. */
  destroy(): void {
    this.bindings.abort();
    this.treeEpoch++;
    this.root = null;
    this.selectedPath = null;
    this.focusedNode = null;
    this.ready = false;
    this.scroller.replaceChildren();
  }

  // ── Node creation ───────────────────────────────────────────────────

  private createRootNode(path: string): TreeNode {
    return {
      path,
      name: path === '/' ? '/' : path.slice(path.lastIndexOf('/') + 1),
      type: 'directory',
      parent: null,
      children: null,
      state: 'collapsed',
      isTruncated: false,
      loadToken: 0,
      element: null,
      depth: 0,
      unavailable: false,
    };
  }

  private createTreeNode(entry: SFTPEntry, parent: TreeNode): TreeNode {
    const childPath = parent.path === '/'
      ? `/${entry.name}`
      : `${parent.path}/${entry.name}`;
    return {
      path: childPath,
      name: entry.name,
      type: entry.type,
      parent,
      children: null,
      state: 'collapsed',
      isTruncated: false,
      loadToken: 0,
      element: null,
      depth: parent.depth + 1,
      unavailable: false,
    };
  }

  /**
   * Create a synthetic "potentially available" child for the next path
   * segment when the parent's list failed. The synthetic node starts
   * without the unavailable flag — it will be marked unavailable on the
   * next fetch attempt if that one also fails.
   */
  private createUnavailableChild(path: string, parent: TreeNode): TreeNode {
    const name = path.slice(parent.path === '/' ? 1 : parent.path.length + 1);
    return {
      path,
      name,
      type: 'directory',
      parent,
      children: null,
      state: 'collapsed',
      isTruncated: false,
      loadToken: 0,
      element: null,
      depth: parent.depth + 1,
      unavailable: false,
    };
  }

  /** Whether a node can be expanded (only directories, excludes unavailable). */
  private isExpandable(node: TreeNode): boolean {
    return node.type === 'directory' && !node.unavailable;
  }

  // ── Rendering ───────────────────────────────────────────────────────

  /** Render the root node into the scroller. */
  private renderRoot(): void {
    if (!this.root) return;
    this.scroller.replaceChildren();
    const el = this.renderNode(this.root);
    this.scroller.append(el);
    this.updateTabindex();
  }

  /**
   * Create (or refresh) the DOM row for a node.
   * If the node already has an element, its inner content is updated in-place.
   */
  private renderNode(node: TreeNode): HTMLElement {
    if (node.element) {
      this.refreshRowContent(node);
      return node.element;
    }
    const row = document.createElement('div');
    row.className = 'file-tree-row';
    row.setAttribute('role', 'treeitem');
    row.style.setProperty('--file-tree-depth', String(node.depth));
    row.dataset.path = node.path;
    row.tabIndex = -1;
    node.element = row;
    this.refreshRowContent(node);
    return row;
  }

  /** Update the inner content and state classes of a node's existing row. */
  private refreshRowContent(node: TreeNode): void {
    const row = node.element;
    if (!row) return;

    // Reset classes, keeping is-selected if applicable
    const isSelected = this.selectedPath === node.path;
    row.className = 'file-tree-row';
    if (isSelected) row.classList.add('is-selected');
    if (node.state === 'loading') row.classList.add('is-loading');
    if (node.state === 'error') row.classList.add('is-error');
    if (node.unavailable) row.classList.add('is-unavailable');

    row.style.setProperty('--file-tree-depth', String(node.depth));
    row.dataset.path = node.path;
    row.replaceChildren();

    const expandable = this.isExpandable(node);

    // Toggle / spinner / lock / spacer
    if (node.state === 'loading') {
      const spinner = document.createElement('span');
      spinner.className = 'file-tree-spinner';
      spinner.setAttribute('aria-hidden', 'true');
      row.append(spinner);
    } else if (node.unavailable) {
      // Lock icon for nodes whose SFTP list failed (e.g. Permission denied
      // on an ancestor). Not expandable; preserves full path in the tree.
      const lock = document.createElement('span');
      lock.className = 'file-tree-lock';
      lock.setAttribute('aria-hidden', 'true');
      lock.textContent = '\u{1F512}'; // 🔒
      row.append(lock);
    } else if (expandable) {
      const toggle = document.createElement('span');
      toggle.className = 'file-tree-toggle';
      toggle.setAttribute('aria-hidden', 'true');
      toggle.textContent = node.state === 'expanded' ? '\u25BE' : '\u25B8';
      row.append(toggle);
    } else {
      const spacer = document.createElement('span');
      spacer.className = 'file-tree-toggle';
      spacer.setAttribute('aria-hidden', 'true');
      row.append(spacer);
    }

    // Icon
    const icon = document.createElement('span');
    icon.className = `file-tree-icon ${node.type}`;
    icon.setAttribute('aria-hidden', 'true');
    icon.textContent = node.type === 'directory' ? '\u25A0' : node.type === 'symlink' ? '\u2197' : '\u25A1';
    row.append(icon);

    // Name
    const name = document.createElement('span');
    name.className = 'file-tree-name';
    name.textContent = node.name;
    row.append(name);

    // Retry button for error state
    if (node.state === 'error') {
      const retry = document.createElement('button');
      retry.type = 'button';
      retry.className = 'file-tree-retry';
      retry.textContent = this.localize(RETRY_TEXT);
      // Keep retry out of the Tab sequence. The tree uses a roving-tabindex
      // model (only the focused row has tabIndex=0); a natively tabbable
      // control inside role="treeitem" would break ARIA tree navigation.
      retry.tabIndex = -1;
      // Give assistive tech a node-scoped label instead of context-free "Retry".
      retry.setAttribute('aria-label', this.localize({
        zh: `重试加载 ${node.name}`,
        en: `Retry loading ${node.name}`,
      }));
      row.append(retry);
    }

    // ARIA expanded: treat "loading" as expanded since the expand is in progress.
    if (expandable) {
      row.setAttribute('aria-expanded', String(node.state === 'expanded' || node.state === 'loading'));
    } else {
      row.removeAttribute('aria-expanded');
    }
  }

  /** Create a non-interactive status row (empty / truncated indicator). */
  private createStatusRow(copy: LocalizedText, depth: number): HTMLElement {
    const row = document.createElement('div');
    row.className = 'file-tree-status';
    row.setAttribute('aria-hidden', 'true');
    row.style.setProperty('--file-tree-depth', String(depth));
    row.dataset.i18nZh = copy.zh;
    row.dataset.i18nEn = copy.en;
    row.textContent = this.localize(copy);
    return row;
  }

  /** Render child rows (and status indicators) after an expanded node's row. */
  private renderChildren(node: TreeNode): void {
    const row = node.element;
    if (!row || !node.children) return;

    // Remove any existing descendant rows first
    this.removeDescendantRows(node);

    const fragment = document.createDocumentFragment();
    for (const child of node.children) {
      const childRow = this.renderNode(child);
      fragment.append(childRow);
    }
    // Empty directory indicator
    if (node.children.length === 0) {
      fragment.append(this.createStatusRow(EMPTY_TEXT, node.depth + 1));
    }
    // Truncated sentinel
    if (node.isTruncated) {
      fragment.append(this.createStatusRow(TRUNCATED_TEXT, node.depth + 1));
    }
    row.after(fragment);
    this.updateTabindex();
  }

  /** Remove all descendant rows (and status rows) of `node` from the DOM. */
  private removeDescendantRows(node: TreeNode): void {
    const row = node.element;
    if (!row) return;
    let next = row.nextElementSibling as HTMLElement | null;
    while (next) {
      const depthStr = next.style.getPropertyValue('--file-tree-depth');
      const depth = depthStr ? Number(depthStr) : -1;
      // Stop when we reach a sibling at the same or shallower depth
      if (depth >= 0 && depth <= node.depth) break;
      const toRemove = next;
      next = next.nextElementSibling as HTMLElement | null;
      toRemove.remove();
    }
  }

  // ── Expand / Collapse ───────────────────────────────────────────────

  /**
   * Lazily load and expand a node's children.
   *
   * Two independent cancellation layers:
   * - `loadToken`  — per-node: a newer expand/collapse superseded this fetch.
   * - `treeEpoch`  — per-tree: the whole tree was torn down while awaiting.
   */
  private async expandNode(node: TreeNode, silent = false): Promise<void> {
    // Not expandable or already expanded → no-op.
    if (!this.isExpandable(node) || node.state === 'expanded') return;

    // Node is currently loading — return the in-flight promise so callers
    // (e.g. a second expandToPath) can await the result rather than
    // bailing out prematurely. This fixes the race condition triggered
    // when FileManager double-emits setCwd (sftp_ready + sftp_list_result).
    if (node.state === 'loading') {
      const inflight = this.inflightExpands.get(node);
      if (inflight) return inflight;
      // Defensive fallback: shouldn't happen if inflightExpands is always
      // set before transitioning to 'loading'.
      return;
    }

    // Capture the tree generation this call belongs to.
    const epoch = this.treeEpoch;

    node.loadToken++;
    const token = node.loadToken;
    node.state = 'loading';
    this.refreshRowContent(node);

    // Create the in-flight promise and register it so concurrent callers
    // can await it instead of creating a duplicate fetch.
    let resolve: () => void = () => {};
    const promise = new Promise<void>((res) => { resolve = res; });
    this.inflightExpands.set(node, promise);

    try {
      const result = await this.fetchEntries(node.path);
      // Tree-level guard: the tree was destroyed or rebuilt while awaiting,
      // so `node` is orphaned. Return without rolling back node.state —
      // the node died together with its tree and is unreachable.
      if (epoch !== this.treeEpoch || !this.ready || !this.root) { resolve(); return; }
      // Per-node race-condition guard: if loadToken changed, this was superseded.
      if (token !== node.loadToken) { resolve(); return; }

      node.children = result.entries
        .filter(isTreeVisibleEntry)
        .map((entry) => this.createTreeNode(entry, node));
      node.isTruncated = result.isTruncated;
      node.state = 'expanded';
      this.refreshRowContent(node);
      this.renderChildren(node);
      resolve();
    } catch (error) {
      // Tree-level guard MUST run before onError: a fetch rejected by the
      // teardown itself (rejectTreeLists on close/destroy) would otherwise
      // surface a bogus error toast for a session the user already left.
      if (epoch !== this.treeEpoch || !this.ready || !this.root) { resolve(); return; }
      if (token !== node.loadToken) { resolve(); return; }

      // ── Silent failure handling for setCwd auto-expansion ────────────
      // When the tree is auto-walking to cwd and an ancestor fetch fails
      // (e.g. restricted shell where / is unreadable), mark the node as
      // unavailable instead of re-rooting. The walk will continue via a
      // synthetic child in expandToPath, preserving the full path display.
      // Manual expand (user click/keyboard) does NOT pass silent=true, so
      // those errors still surface via the error path below.
      if (silent) {
        const cwd = this.selectedPath;
        if (cwd && isDescendantPath(node.path, cwd)) {
          node.unavailable = true;
          node.state = 'collapsed';
          node.children = null;
          this.removeDescendantRows(node);
          this.refreshRowContent(node);
          resolve();
          return;
        }
      }
      // ── End silent handling ──────────────────────────────────────────

      node.state = 'error';
      node.children = null;
      this.removeDescendantRows(node);
      this.refreshRowContent(node);
      const message = error instanceof Error ? error.message : String(error);
      this.onError?.(message);
      resolve();
    } finally {
      // Clean up the inflight map entry, but only if our promise is still
      // the one registered (prevents clobbering a new expand on the same
      // node that started after this one completed/cleaned up).
      if (this.inflightExpands.get(node) === promise) {
        this.inflightExpands.delete(node);
      }
    }
  }

  /** Collapse a node: cancel pending fetch, discard children, remove DOM. */
  private collapseNode(node: TreeNode): void {
    if (!this.isExpandable(node) || node.state === 'collapsed') return;
    node.loadToken++; // cancel any pending expand
    node.state = 'collapsed';
    node.children = null;
    node.isTruncated = false;
    this.removeDescendantRows(node);
    this.refreshRowContent(node);
    this.updateTabindex();
  }

  // ── setCwd path expansion (Risk 2: setCwdToken cancellation) ────────

  /**
   * Walk from root down to `cwd`, expanding ancestors along the way.
   * The `token` parameter cancels the operation if setCwd is called again.
   */
  private async expandToPath(cwd: string, token: number): Promise<void> {
    if (!this.ready || !this.root) return;

    const segments = splitPathSegments(cwd);
    let current = this.root;

    for (const segment of segments) {
      if (token !== this.setCwdToken) return;
      if (segment === current.path) {
        // Even when the segment matches the current node (e.g. root "/" on
        // initial load or setCwd("/")), we must still expand it so its
        // children are rendered in the tree. Without this, clicking the root
        // loads the right panel but the left tree stays collapsed.
        if (current.state !== 'expanded') {
          await this.expandNode(current, true);
          if (token !== this.setCwdToken) return;
        }
        continue;
      }

      // If current is unavailable, we can't see its real children.
      // Create a synthetic child for the next segment so the walk can
      // continue. The synthetic child starts as "potentially available"
      // and will be tried on the next iteration.
      if (current.unavailable) {
        // Check if a synthetic child for this segment already exists
        let synth = current.children?.find((c) => c.path === segment) ?? null;
        if (!synth) {
          synth = this.createUnavailableChild(segment, current);
          if (!current.children) current.children = [];
          current.children.push(synth);
          this.renderChildren(current);
        }
        current = synth;
        continue;
      }

      // Try to expand current (silent, no error UI on failure).
      if (current.state !== 'expanded') {
        await this.expandNode(current, true);
        if (token !== this.setCwdToken) return;

        // Expansion failed and marked current as unavailable: create
        // a synthetic child for the next segment.
        if (current.unavailable) {
          let synth = current.children?.find((c) => c.path === segment) ?? null;
          if (!synth) {
            synth = this.createUnavailableChild(segment, current);
            if (!current.children) current.children = [];
            current.children.push(synth);
            this.renderChildren(current);
          }
          current = synth;
          continue;
        }
      }

      // Find the real child matching the next segment.
      const child = current.children?.find((c) => c.path === segment);
      if (!child) break; // path segment not found in directory
      current = child;
    }

    if (token !== this.setCwdToken) return;

    // If the final node is a synthetic child of an unavailable parent,
    // try expanding it (the loop's post-expansion check above may have
    // created it and skipped to the next iteration, which then
    // short-circuited because segment === current.path).
    if (current.state === 'collapsed' && !current.unavailable && current.parent?.unavailable) {
      await this.expandNode(current, true);
      if (token !== this.setCwdToken) return;
    }

    // Expand the target directory itself (not just its ancestors) so its
    // children are immediately rendered and aria-expanded is "true".
    // This covers initial-connection setCwd where activateNode is never
    // called — ancestors were expanded during the loop above; the target
    // needs this extra step.
    if (current.state === 'collapsed' && current.type === 'directory' && !current.unavailable) {
      await this.expandNode(current, true);
      if (token !== this.setCwdToken) return;
    }

    this.highlightNode(current);
    this.focusedNode = current;
    this.updateTabindex();
    current.element?.scrollIntoView({ block: 'nearest' });
  }

  /** Set is-selected on the target node, removing it from all others. */
  private highlightNode(node: TreeNode): void {
    this.selectedPath = node.path;
    const rows = this.scroller.querySelectorAll('.file-tree-row.is-selected');
    rows.forEach((row) => row.classList.remove('is-selected'));
    if (node.element) {
      node.element.classList.add('is-selected');
    }
  }

  // ── Keyboard navigation (ARIA tree + roving tabindex) ───────────────

  /** Depth-first list of all visible (rendered) nodes. */
  private getVisibleNodes(): TreeNode[] {
    const result: TreeNode[] = [];
    const walk = (node: TreeNode): void => {
      result.push(node);
      if (node.state === 'expanded' && node.children) {
        for (const child of node.children) {
          walk(child);
        }
      }
    };
    if (this.root) walk(this.root);
    return result;
  }

  /** Find a TreeNode by path (searches the entire loaded tree). */
  private findNodeByPath(path: string): TreeNode | null {
    if (!this.root) return null;
    const walk = (node: TreeNode): TreeNode | null => {
      if (node.path === path) return node;
      if (node.children) {
        for (const child of node.children) {
          const found = walk(child);
          if (found) return found;
        }
      }
      return null;
    };
    return walk(this.root);
  }

  /** Update roving tabindex: only the focused node gets tabIndex=0. */
  private updateTabindex(): void {
    const rows = this.scroller.querySelectorAll<HTMLElement>('.file-tree-row');
    rows.forEach((row) => { row.tabIndex = -1; });
    const focusTarget = this.focusedNode ?? this.root;
    if (focusTarget?.element) {
      focusTarget.element.tabIndex = 0;
    }
  }

  /** Move focus to a node and update roving tabindex. */
  private focusNode(node: TreeNode): void {
    this.focusedNode = node;
    this.updateTabindex();
    node.element?.focus();
  }

  /** Activate a node (Enter key or click on folder): select + navigate. */
  private activateNode(node: TreeNode): void {
    this.highlightNode(node);
    this.focusedNode = node;
    this.updateTabindex();
    if ((node.type === 'directory' || node.type === 'symlink') && !node.unavailable) {
      this.onNavigate(node.path);
      // Expand the node in the tree immediately so aria-expanded flips to
      // "true" (or shows a loading spinner) without waiting for the async
      // setCwd → expandToPath round-trip that follows onNavigate.
      // Only real directories are expandable; symlinks navigate the right
      // panel but are not expanded in the tree (isExpandable returns false).
      if (node.type === 'directory') {
        void this.expandNode(node);
      }
    }
    // Symlinks: navigate the right panel but are not expandable in the
    // tree (isExpandable returns false). Files: select only, no navigation.
    // Unavailable directories: highlight but don't navigate (SFTP would
    // refuse and surface an error to the user).
  }

  private handleKeydown(event: KeyboardEvent): void {
    if (!this.focusedNode) return;
    const node = this.focusedNode;
    const visible = this.getVisibleNodes();
    const index = visible.indexOf(node);
    if (index < 0) return;

    switch (event.key) {
      case 'ArrowDown': {
        event.preventDefault();
        const next = visible[index + 1];
        if (next) this.focusNode(next);
        break;
      }
      case 'ArrowUp': {
        event.preventDefault();
        const prev = visible[index - 1];
        if (prev) this.focusNode(prev);
        break;
      }
      case 'ArrowRight': {
        event.preventDefault();
        if (this.isExpandable(node)) {
          if (node.state === 'collapsed' || node.state === 'error') {
            void this.expandNode(node);
          } else if (node.state === 'expanded' && node.children && node.children.length > 0) {
            this.focusNode(node.children[0]);
          }
        }
        break;
      }
      case 'ArrowLeft': {
        event.preventDefault();
        if (this.isExpandable(node) && node.state === 'expanded') {
          this.collapseNode(node);
        } else if (node.parent) {
          this.focusNode(node.parent);
        }
        break;
      }
      case 'Enter': {
        event.preventDefault();
        this.activateNode(node);
        break;
      }
      case ' ': {
        event.preventDefault();
        if (this.isExpandable(node)) {
          if (node.state === 'expanded') {
            this.collapseNode(node);
          } else {
            void this.expandNode(node);
          }
        }
        break;
      }
      case 'Home': {
        event.preventDefault();
        if (visible[0]) this.focusNode(visible[0]);
        break;
      }
      case 'End': {
        event.preventDefault();
        const last = visible[visible.length - 1];
        if (last) this.focusNode(last);
        break;
      }
    }
  }

  // ── Click handling ──────────────────────────────────────────────────

  private handleClick(event: MouseEvent): void {
    const row = event.target instanceof Element
      ? event.target.closest<HTMLElement>('.file-tree-row')
      : null;
    if (!row) return;
    const path = row.dataset.path;
    if (!path) return;
    const node = this.findNodeByPath(path);
    if (!node) return;

    // Toggle arrow click → expand/collapse
    if (event.target instanceof Element && event.target.closest('.file-tree-toggle')) {
      if (this.isExpandable(node)) {
        if (node.state === 'expanded') {
          this.collapseNode(node);
        } else {
          void this.expandNode(node);
        }
      }
      return;
    }

    // Retry button click → re-expand
    if (event.target instanceof Element && event.target.closest('.file-tree-retry')) {
      // expandNode calls refreshRowContent (destroys this button); and the
      // button is tabIndex=-1 so focus would fall back to <body>. Move focus
      // onto the owning row first (no scrollIntoView, no scroll jump).
      this.focusNode(node);
      void this.expandNode(node);
      return;
    }

    // Row click → focus + activate
    this.focusNode(node);
    this.activateNode(node);
  }

  // ── Width persistence + drag ────────────────────────────────────────

  private get managerElement(): HTMLElement | null {
    return this.container.parentElement;
  }

  private loadWidth(): void {
    let width = DEFAULT_WIDTH;
    try {
      const stored = localStorage.getItem(WIDTH_STORAGE_KEY);
      if (stored) {
        const parsed = Number(stored);
        if (Number.isFinite(parsed) && parsed >= MIN_WIDTH && parsed <= MAX_WIDTH) {
          width = parsed;
        }
      }
    } catch { /* localStorage unavailable */ }
    this.width = width;
    this.applyWidth();
  }

  private applyWidth(): void {
    this.managerElement?.style.setProperty('--file-tree-width', `${this.width}px`);
  }

  private saveWidth(width: number): void {
    this.width = Math.max(MIN_WIDTH, Math.min(MAX_WIDTH, Math.round(width)));
    this.applyWidth();
    try { localStorage.setItem(WIDTH_STORAGE_KEY, String(this.width)); } catch { /* ignore */ }
  }

  private initResize(signal: AbortSignal): void {
    let dragging = false;
    let startX = 0;
    let startWidth = 0;

    this.resizeHandle.addEventListener('mousedown', (event: MouseEvent) => {
      dragging = true;
      startX = event.clientX;
      startWidth = this.width;
      event.preventDefault();
      document.body.style.cursor = 'col-resize';
      document.body.style.userSelect = 'none';
    }, { signal });

    document.addEventListener('mousemove', (event: MouseEvent) => {
      if (!dragging) return;
      const delta = event.clientX - startX;
      this.saveWidth(startWidth + delta);
    }, { signal });

    document.addEventListener('mouseup', () => {
      if (!dragging) return;
      dragging = false;
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    }, { signal });
  }

  // ── Collapsed sidebar ───────────────────────────────────────────────

  private loadCollapsed(): void {
    let stored: string | null = null;
    try {
      stored = localStorage.getItem(COLLAPSED_STORAGE_KEY);
    } catch { /* localStorage unavailable */ }

    if (stored === null) {
      // No saved preference: default to collapsed on narrow screens.
      this.collapsed = typeof window.matchMedia === 'function'
        && window.matchMedia('(max-width: 760px)').matches;
    } else {
      this.collapsed = stored === 'true';
    }

    if (this.collapsed) this.container.classList.add('is-collapsed');
  }

  private toggleCollapsed(): void {
    this.collapsed = !this.collapsed;
    this.container.classList.toggle('is-collapsed', this.collapsed);
    try { localStorage.setItem(COLLAPSED_STORAGE_KEY, String(this.collapsed)); } catch { /* ignore */ }
  }

  // ── i18n helpers ────────────────────────────────────────────────────

  /** Re-render all visible rows and status text after a language switch. */
  private rerenderVisible(node: TreeNode): void {
    this.refreshRowContent(node);

    // Update status rows immediately following this node
    const row = node.element;
    if (row) {
      let next = row.nextElementSibling as HTMLElement | null;
      while (next && next.classList.contains('file-tree-status')) {
        const zh = next.dataset.i18nZh;
        const en = next.dataset.i18nEn;
        if (zh && en) next.textContent = this.isChinese() ? zh : en;
        next = next.nextElementSibling as HTMLElement | null;
      }
    }

    if (node.state === 'expanded' && node.children) {
      for (const child of node.children) {
        this.rerenderVisible(child);
      }
    }
  }

  private localize(copy: LocalizedText): string {
    return this.isChinese() ? copy.zh : copy.en;
  }

  private isChinese(): boolean {
    return this.getLanguage().toLowerCase().startsWith('zh');
  }
}
