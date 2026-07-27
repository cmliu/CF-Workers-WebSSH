const DATABASE_NAME = 'workers-webssh.crypto.v1';
const DATABASE_VERSION = 1;
const STORE_NAME = 'keys';
const PASSWORD_KEY_ID = 'history-password-aes-gcm';

let passwordKeyPromise: Promise<CryptoKey | null> | null = null;

function isHistoryPasswordKey(value: unknown): value is CryptoKey {
  if (!value || typeof value !== 'object') return false;
  try {
    const key = value as CryptoKey;
    const algorithm = key.algorithm as AesKeyAlgorithm | undefined;
    return key.type === 'secret'
      && key.extractable === false
      && algorithm?.name === 'AES-GCM'
      && algorithm.length === 256
      && key.usages.includes('encrypt')
      && key.usages.includes('decrypt');
  } catch {
    return false;
  }
}

function openKeyDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE_NAME)) request.result.createObjectStore(STORE_NAME);
    };
    request.onerror = () => {
      if (settled) return;
      settled = true;
      reject(request.error ?? new Error('Unable to open password key database'));
    };
    request.onblocked = () => {
      if (settled) return;
      settled = true;
      reject(new Error('Password key database upgrade was blocked'));
    };
    request.onsuccess = () => {
      if (settled) {
        request.result.close();
        return;
      }
      settled = true;
      request.result.onversionchange = () => request.result.close();
      resolve(request.result);
    };
  });
}

interface KeyLookup {
  found: boolean;
  value: unknown;
}

function readHistoryPasswordKey(database: IDBDatabase): Promise<KeyLookup> {
  return new Promise((resolve, reject) => {
    let result: KeyLookup = { found: false, value: undefined };
    let requestError: DOMException | null = null;
    const transaction = database.transaction(STORE_NAME, 'readonly');
    const request = transaction.objectStore(STORE_NAME).openCursor(PASSWORD_KEY_ID);
    request.onsuccess = () => {
      const cursor = request.result;
      if (cursor) result = { found: true, value: cursor.value };
    };
    request.onerror = () => { requestError = request.error; };
    transaction.oncomplete = () => resolve(result);
    transaction.onerror = () => { requestError ??= transaction.error; };
    transaction.onabort = () => reject(requestError ?? transaction.error ?? new Error('Unable to read password key'));
  });
}

function addHistoryPasswordKey(database: IDBDatabase, key: CryptoKey): Promise<void> {
  return new Promise((resolve, reject) => {
    let requestError: DOMException | null = null;
    const transaction = database.transaction(STORE_NAME, 'readwrite');
    const request = transaction.objectStore(STORE_NAME).add(key, PASSWORD_KEY_ID);
    request.onerror = () => { requestError = request.error; };
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => { requestError ??= transaction.error; };
    transaction.onabort = () => reject(requestError ?? transaction.error ?? new Error('Unable to store password key'));
  });
}

function isConstraintError(error: unknown): boolean {
  try {
    return typeof error === 'object' && error !== null && 'name' in error && error.name === 'ConstraintError';
  } catch {
    return false;
  }
}

async function loadOrCreateHistoryPasswordKey(): Promise<CryptoKey | null> {
  if (!globalThis.indexedDB || !globalThis.crypto?.subtle) return null;
  let database: IDBDatabase | null = null;
  try {
    database = await openKeyDatabase();

    // Finish the read transaction before generating a key so IndexedDB cannot
    // auto-commit a transaction while Web Crypto is running.
    const stored = await readHistoryPasswordKey(database);
    if (stored.found) return isHistoryPasswordKey(stored.value) ? stored.value : null;

    const candidate = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    ) as CryptoKey;
    if (!isHistoryPasswordKey(candidate)) return null;

    try {
      await addHistoryPasswordKey(database, candidate);
      return candidate;
    } catch (error) {
      if (!isConstraintError(error)) return null;
      const winner = await readHistoryPasswordKey(database);
      return winner.found && isHistoryPasswordKey(winner.value) ? winner.value : null;
    }
  } catch {
    return null;
  } finally {
    database?.close();
  }
}

export function getHistoryPasswordKey(): Promise<CryptoKey | null> {
  passwordKeyPromise ??= loadOrCreateHistoryPasswordKey().then(
    (key) => {
      if (!key) passwordKeyPromise = null;
      return key;
    },
    () => {
      passwordKeyPromise = null;
      return null;
    },
  );
  return passwordKeyPromise;
}
